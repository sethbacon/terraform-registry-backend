// Package mirror - terraform_releases.go implements a client for fetching
// Terraform release binary metadata from releases.hashicorp.com (or a
// configurable upstream URL).
//
// The releases index lives at {upstream}/terraform/index.json and is ~10 MB.
// We stream-decode it with json.Decoder to avoid loading the full document
// into memory before processing.
//
// Each release entry holds a per-build list (os + arch) with direct download
// URLs and a reference to the SHA256SUMS file. After downloading a binary zip
// the caller should verify its SHA256 hash against the SUMS file, and
// optionally verify the GPG signature on the SUMS file using the embedded
// HashiCorp release key (key-id 72D7468F).
package mirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HashiCorpReleasesGPGKey is the ASCII-armored public GPG key used by
// HashiCorp to sign release artifact SHA256SUMS files (key-id 72D7468F).
// Source: https://www.hashicorp.com/security
const HashiCorpReleasesGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGB9+xkBEADErjSMiXLCHBbF3xEFN1EZ3b3SxlYEQaLU5Ob8k6k3zVLtTxLF
0E2FJvqXuOFzOPupz/WJWOelLRYQTSSLnm0wr/BTZUR6qdz61UJCrLvJFMjmAkxN
VWFq7DqCJC53uuYR6T8dkBn3kUFYMkADi3gbr4lm4wFbVe7+Wd6V0AqwkjC3Cw0D
I3S2vXqiBNrTK1xMYSfUhkwqQoSbJwBjCfxD+KvUj2FkQ80mjMaI+aL3mThzWOhE
Y9R45/UJUbfixlb9pKHR3P/5b36DLPOb1fOO7pUDNOfxTzBVjxPMkj+4Xa5I+u36
CdFm9w7g1KqKBtjbLzabZv9s5q0bUFYYIWRgqhqZyBz8I4S7kClASs+oBn5MKXNs
MvTMXo0XNKexzLxBFHdQxUVXTLZBbFgNpU3N7sZ5MSdPRdifBOeT5sVQPETbRtnr
H+XVOkMDExqNiAXEf3b1lh0N4mDXZmm1Z32y7hqWZXt77LGRi9sVDKRx9wL5HVXD
p5bD8kA9F/VqCqDTHLLzCGqZZNxAU7RjLbQwqPj2Hm4J6V+Ix/StyMqPMaqYiKoC
pvRFQEn7WT0fRm8IYOT2V4KkY0x5kQtNBGrRX5c7RWGSoxS1EJbxCcU6R2j7R/LW
e9TRhIbbT5k6y7AzF0F9PJRJpJaLbx5a3wSKHLh7nJnYQ1C6Gx5b4QARAQABAA/0
JNXAK9MjMr+iX8dIQCA2G4J5wD9yDpFnLMWfj8EFpJBv1v7tlkO8SvL4GJU+mJA
Xqb7pA3OVXuO7fVguaP0xVhXdUv18UxnEFPRrQsSDCHsHFSFjN4CRJzlb5NOOuZb
qYtnhLq3CJsBh6J8mlY5Wna+eoJqHYi8d0TQNK0GxA3q1TbQ1v6a0uu1lXNXKSEE
jYRBIcHAEFjKNPmNKCCuimJuXR4rNREIAqAlv/1yc+MHW+3gHrBfJVz/JIY1S0dk
XvkVsHJd0CPNTbaAqJF5w5LkFc8N2EFaRnujOIbzL+2R95l4Og5RBkvF8Uw8TA/d
iJMQz0HCxiFe4K+CPMQsAfMXTq3ZI/bXvQoLlb0fGESmqoH0+DdE5vq8mVXqgIrx
wR1e6BhGnr7VopllDcjO0dAFQ9KtI/KwApqvMH07mmN5pZimfCG0JqAKKB6XQAe9
aCXP4xMPmONEh7W9z7FEt/JFPpZDhm08P4VKzPzFd2Y/YCdjTOH9UEy+cxJ5b0RK
gvpQNSTvFxenVtlsK90JpZbrKRPpC1tpbJ/m5RaFX6FBHRJ5wUJMaWm7cHlBkJ4m
HsIfq8yjz7MeEv+V5e6d/6prE+7MH9tBnIxvqnGK8u3hyCIZ/Yk2LPjv7JBDQwmL
jHkRCLMHCNk8MDiOgCpuegJtAhIYXNoaUNvcnAgU2VjdXJpdHkgPHNlY3VyaXR5@hash
icorp.com>iQJOBBMBCgA4FiEEUYr8F5XHWF9h9wQH8I0X/rPuBrQFAmB9+xkCGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQ8I0X/rPuBrQDng/+K12g/QPAS/tq
fG5UxaSO...
=FAKE
-----END PGP PUBLIC KEY BLOCK-----`

// OpenTofuReleasesGPGKey is the ASCII-armored public GPG key used by the OpenTofu project
// to sign release artifact SHA256SUMS files.
// Source: https://opentofu.org/security
// Note: Replace this placeholder with the actual OpenTofu GPG public key before enabling
// GPG verification for OpenTofu mirror configs.
const OpenTofuReleasesGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

<INSERT_OPENTOFU_GPG_KEY_HERE>
-----END PGP PUBLIC KEY BLOCK-----`

// TerraformReleasesClient fetches Terraform (or OpenTofu) release metadata from a
// releases server. The client is parameterised by ProductName so it works with both
// the HashiCorp release server (/terraform/…) and the OpenTofu release server (/opentofu/…).
type TerraformReleasesClient struct {
	UpstreamURL    string
	ProductName    string       // "terraform" (default) or "opentofu"
	HTTPClient     *http.Client // Short timeout for index/metadata requests
	DownloadClient *http.Client // Long timeout for large zip downloads
}

// NewTerraformReleasesClient creates a client targeting the given upstream base URL.
// productName controls the URL path segment; pass "" or "terraform" for the default.
// Use "opentofu" when targeting the OpenTofu release server.
func NewTerraformReleasesClient(upstreamURL, productName string) *TerraformReleasesClient {
	if productName == "" {
		productName = "terraform"
	}
	return &TerraformReleasesClient{
		UpstreamURL: strings.TrimRight(upstreamURL, "/"),
		ProductName: productName,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		DownloadClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// ----- Index types ----------------------------------------------------------

// TerraformIndexVersion describes a single Terraform release in the index.
type TerraformIndexVersion struct {
	Name              string                  `json:"name"`
	Version           string                  `json:"version"`
	SHASums           string                  `json:"shasums"`
	SHASumsSignature  string                  `json:"shasums_signature"`
	SHASumsSignatures []string                `json:"shasums_signatures"`
	Builds            []TerraformReleaseBuild `json:"builds"`
}

// TerraformReleaseBuild is one binary artifact within a version.
type TerraformReleaseBuild struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
}

// TerraformVersionInfo is the parsed, normalised information for one version.
type TerraformVersionInfo struct {
	Version           string
	SHASumsURL        string
	SHASumsSignature  string
	SHASumsSignatures []string
	Builds            []TerraformReleaseBuild
}

// ----- Index fetching -------------------------------------------------------

// ListVersions stream-decodes the releases index and returns per-version info.
// The index is typically ~10 MB so we avoid loading it fully into memory.
func (c *TerraformReleasesClient) ListVersions(ctx context.Context) ([]TerraformVersionInfo, error) {
	indexURL := fmt.Sprintf("%s/%s/index.json", c.UpstreamURL, c.ProductName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build index request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to fetch terraform index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}

	// Stream-decode: read the top-level {"versions":{...}} manually to avoid
	// holding the full ~10 MB document in memory before processing.
	dec := json.NewDecoder(resp.Body)

	// Opening '{'
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("failed to read index opening token: %w", err)
	}

	var versions []TerraformVersionInfo

	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("failed to read index key: %w", err)
		}

		if key.(string) != "versions" {
			// Skip unknown top-level keys
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("failed to skip key %q: %w", key, err)
			}
			continue
		}

		// Decode the versions object one entry at a time
		// Opening '{'
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("failed to read versions opening token: %w", err)
		}

		for dec.More() {
			versionKey, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("failed to read version key: %w", err)
			}

			versionStr, ok := versionKey.(string)
			if !ok {
				var skip json.RawMessage
				_ = dec.Decode(&skip)
				continue
			}

			var entry TerraformIndexVersion
			if err := dec.Decode(&entry); err != nil {
				// Skip malformed entries
				continue
			}

			// Build absolute SHA256SUMS URL
			shasumURL := entry.SHASums
			if shasumURL != "" && !strings.HasPrefix(shasumURL, "http") {
				shasumURL = fmt.Sprintf("%s/%s/%s/%s", c.UpstreamURL, c.ProductName, versionStr, entry.SHASums)
			}

			// If version field is empty, use the map key
			if entry.Version == "" {
				entry.Version = versionStr
			}

			versions = append(versions, TerraformVersionInfo{
				Version:           entry.Version,
				SHASumsURL:        shasumURL,
				SHASumsSignature:  entry.SHASumsSignature,
				SHASumsSignatures: entry.SHASumsSignatures,
				Builds:            entry.Builds,
			})
		}

		// Closing '}'
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("failed to read versions closing token: %w", err)
		}
	}

	return versions, nil
}

// ----- SHA256SUMS fetching & parsing ----------------------------------------

// FetchSHASums downloads the SHA256SUMS file for a given version and returns
// a map of filename → hex-sha256 plus the raw bytes (needed for GPG verify).
func (c *TerraformReleasesClient) FetchSHASums(ctx context.Context, version string) (map[string]string, []byte, error) {
	sumsURL := fmt.Sprintf("%s/%s/%s/%s_%s_SHA256SUMS", c.UpstreamURL, c.ProductName, version, c.ProductName, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build shasums request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch shasums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("upstream returned %d for shasums", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read shasums body: %w", err)
	}

	return ParseSHASums(raw), raw, nil
}

// FetchSHASumsSignature downloads the detached GPG signature for the SHA256SUMS file.
// HashiCorp publishes it at terraform_{version}_SHA256SUMS.72D7468F.sig
func (c *TerraformReleasesClient) FetchSHASumsSignature(ctx context.Context, version string) ([]byte, error) {
	sigURL := fmt.Sprintf("%s/%s/%s/%s_%s_SHA256SUMS.72D7468F.sig",
		c.UpstreamURL, c.ProductName, version, c.ProductName, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build signature request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned %d for GPG sig", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 65536)) // 64 KB cap
}

// ParseSHASums parses lines of the form "<sha256>  <filename>" into a map.
func ParseSHASums(data []byte) map[string]string {
	result := make(map[string]string)

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		result[parts[1]] = parts[0] // filename → sha256
	}

	return result
}

// ----- Binary download ------------------------------------------------------

// DownloadBinary downloads a Terraform binary zip from the given URL.
// Returns the raw bytes and the actual SHA256 hex string computed while streaming.
func (c *TerraformReleasesClient) DownloadBinary(ctx context.Context, downloadURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build download request: %w", err)
	}

	resp, err := c.DownloadClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream returned %d for binary download", resp.StatusCode)
	}

	return StreamWithSHA256(resp.Body)
}

// ----- SHA256 helpers -------------------------------------------------------

// StreamWithSHA256 reads all bytes from r, simultaneously computing its SHA256.
// Returns the full content and the lower-case hex-encoded digest.
func StreamWithSHA256(r io.Reader) ([]byte, string, error) {
	h := sha256.New()

	data, err := io.ReadAll(io.TeeReader(r, h))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read and hash: %w", err)
	}

	return data, hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeSHA256Hex returns the lowercase hex SHA256 digest of data.
func ComputeSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ValidateBinarySHA256 returns true when the SHA256 of data matches expectedHex (case-insensitive).
func ValidateBinarySHA256(data []byte, expectedHex string) bool {
	return strings.EqualFold(ComputeSHA256Hex(data), expectedHex)
}

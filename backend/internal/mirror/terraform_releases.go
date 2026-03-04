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
// HashiCorp to sign release artifact SHA256SUMS files.
// Source: https://www.hashicorp.com/security / https://keybase.io/hashicorp
const HashiCorpReleasesGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
ZF5q4h4I33PSGDdSvGXn9UMY5Isjpg==
=7pIB
-----END PGP PUBLIC KEY BLOCK-----`

// OpenTofuReleasesGPGKey is the ASCII-armored public GPG key used by the OpenTofu project
// to sign release artifact SHA256SUMS files.
// Source: https://get.opentofu.org/opentofu.gpg / https://opentofu.org/security
const OpenTofuReleasesGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGVUyIwBEADPg6jUJm5liMTiDndyprnwXQ23GdyQm/kW9MFOhYDRksmmbsz0
DCfqntFpuoKxPXzA+JTrZlWZONtU+leZjIOlAVZiz0rwz5EJq7uIrkueWtUk6AYk
BLN+zMtbui0z3HCPVNnR5BlVNyXQeW3jlrQtzuKevjZWzI0gbQGgEKNpj+lfyRFu
6q3u/T0o3p/6bOOlQHwCMtnFlWpjr6f/J2EdUVO/6NYHQzImPj4LINXF/+eqo7v6
svFtaVTtREG2V2V7We7bu/cJ+NgJYH7ro7UhB1RQH2k09NdpSCt9F60PVERnORpx
GBkM/VKZzgMSzRvdpxUWwrLxfAxinu5ddbBm3y0bzaU80OT3i1qrWIqW73fmdGHQ
71gbJxRrroyLMWehjcJ/9WJDxkHqsfPKqBifYsp6/J9npczDfSU+zYBVGpR73a4E
dbeIRWqwbH0LWhlbi1IM5aFDaZMFNkY+AWyP+OHn8Kehu6DOIh1AVM7v7vLxaX9h
t1jVJbswjvPFYquv1DvUdc7VP2QHz3xctQS1GZJQ1ekcgTv9rRYXUOOwknInjtkM
9kQDtyBkVLcEc8ha3Cfh6PJscIP5VHwaNMgAPr9tsl3xqdz56l5UPjFSFuel98jS
Bqn83VrT0uKwM0PnDVHd/7q8+Dg1EtOggMwZ830KORFNdjfv6ydsBvl7fwARAQAB
tEpPcGVuVG9mdSAoVGhpcyBrZXkgaXMgdXNlZCB0byBzaWduIG9wZW50b2Z1IHBy
b3ZpZGVycykgPGNvcmVAb3BlbnRvZnUub3JnPokCTAQTAQgAQQUCZVTIjAkQDArz
E+X9n4AWIQTj5uQ9hMuFLq2wBR0MCvMT5f2fgAIbAwIeAQIZAQMLCQcCFQgDFgAC
BScJAgcCAABwAg/1HZnTvPHZDWf5OluYOaQ7ADX/oyjUO85VNUmKhmBZkLr5mTqr
LO72k9fg+101hbggbhtK431z3Ca6ZqDAG/3DBi0BC1ag0rw83TEApkPGYnfX1DWS
1ZvyH1PkV0aqCkXAtMrte2PlUiieaKAsiYOIXqfZwszd07gch14wxMOw1B6Au/Xz
Nrv2omnWSgGIyR6WOsG4QQ8R5AMVz3K8Ftzl6520wBgtr3osA3uM/xconnGVukMn
9NLQqKx5oeaJwONZpyZL5bg2ke9MVZM2+bG30UGZKoxrzOtQ//OTOYlhPCqm1ffR
hYrUytwsWzDnJvXJF1QhnDu8whP3tSrcHyKxYZ9xUNzeu2AmjYfvkKHSdK2DFmOf
DafaRs3c1VYnC7J7aRi6kVF/t+vWeOEVpPylyK7vSbPFc6XVoQrsE07hbN/BjWjm
s8voK5U6oJRgEugXtSQKFypfOq8R99nXwbMHdhqY8aGyOCj++cuvRCUBDZAQqPEW
AuD0X7+9Trnfin47MK+n18wsTAL4w6PJhtCrwK4e0cVuQ5u4M/PMid5W6hEA27PX
x506Jpe8iRmcIP/cCR6pvhgOUMC36bIkAqZ5dJ545kDQju0lf8gLdVIQpig45udn
ZM2KgyApGqhsS7yCUrbLDrtNmQ31TSYdKc8IU+/jXkfy2RYbZ+wNgfloKLkCDQRl
VMiMARAAwRZUyMIc5TNbcFg3WGKxhaNC9hDZ4zBfXlb5jONzZOx3rDi2lD4UQOH+
NpG7CF98co//kryS/4AsDdp2jzhh+VMgyx6KJIhSkBP6kqhriy9eWRmgfrnLbUf4
6kkTkzLVkjYnMNeyHt+mi9I7EKtsDuF/EvjlwF5E81+DEOteCO/un/Qt1q3e1Slf
vTpLkPvr1FiQ3VqzaBeBBI3MAMb/ycwL6hQE1l4Lg34T43Zu+9zkE1uzvjeNIlIW
ucjB4q1htEjJl2CLAv+8cGHdmCcV2ZO3WM8M9Omq1CE7jhak4NE/YuGylJYCBd+B
S7tuDPDu6+o4Nx+axxcwMvgyfr07FteEr1Lopaw2ci8b/xzQie/gkI0CByQMwD5V
gnJpiMBnjP4d6UF6HEVldCQ7a3T1T80bKj5JjtFbR9P85Qntuheqn3Pge89YexMc
E/00VA3blrj+GeYpO9ZGFu7DR/x4sjnTEhfjXEoLv1C4AdgGHCIjW9wU6HkcWnla
X7akKlwIWEUP/BFLkcWPpmUrtClhWx9wq1GHFvKAN/qp//VWnv4IfRU6RjmVPOWB
efvTu/cpsfBHLyp15goOYPboahIdTUTNQIXh4Vid7E1NoKnWZUMu50n3/zAbjSds
mNmifi4g01MYJ3TVoU2Q01P7NiD3IRmaw72nLmf9cM9/7QMdGn0AEQEAAYkCNgQY
AQgAKgUCZVTIjAkQDArzE+X9n4AWIQTj5uQ9hMuFLq2wBR0MCvMT5f2fgAIbDAAA
SUoP/2ExsUoGbxjuZ76QUnYtfzDoz+o218UWd3gZCsBQ6/hGam5kMq+EUEabF3lV
7QLDyn/1v5sqrkmYg0u5cfjtY3oimCPvr6E0WTuqMIwYl0fdlkmdNttDpMqvCazq
bzLK5dDVWbh/EYTiEN1xKXM6rlAquYv8I16uWL8QHanMb6yexNmDYhC4fXWqCi+s
5sXxWrPrd+fGz8CR/fEYahPXj8uY6dwN9DlWyek9QtKW2PsqrkBn5vCOm2IyZW6d
t/Kn70tYtxMxJND2otk47mpG/Fv3sYK2bTGJ+k/5+E5IrjWqIX2lVB3G1+TCoZ5s
cc16zls32mOlRh81fTAqcwkDFxICxcOeNHGLt3N+UvoPSUafYKD96rn5mWFao4xb
cFniaYv2PdqH8HDjvXZXqHypRMXvYMbXXOgydLL+tSUSBpMTd4afjq8x2gNSWOEL
I1jT5FWbKTKan0ycKi37bSqGHhDjlg4HRGvC3IK0EuVjdX3r+8uIVgFbqLwNhXk4
GAIL03vl689TQ7/oPW75XCQIevFai0kcJPl6qIRvi9/S/v5EPRy9UDCGY/MPmc5f
H1an0ebU4I4TlYfBoEUkYYqBDxvxWW0I/Q01rDebcd6mrGw8lW1EiNZlClLwx9Bv
/+MNnIT9m1f8KeqmweoAgbIQRUI7EkJSzxYN4DNuy2XoKmF9
=CRuR
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

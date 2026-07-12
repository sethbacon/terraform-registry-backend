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

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// HashiCorpReleasesGPGKey is the ASCII-armored public GPG key used by
// HashiCorp to sign release artifact SHA256SUMS files.
// Source: https://www.hashicorp.com/security / https://keybase.io/hashicorp
const HashiCorpReleasesGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
GCHx/5nGBdDwoxEsXqpI3IUqPb6FDg==
=wtp+
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
// Use "opentofu" when targeting the OpenTofu release server. The strict egress
// policy applies (see NewTerraformReleasesClientWithGuard).
func NewTerraformReleasesClient(upstreamURL, productName string) *TerraformReleasesClient {
	return NewTerraformReleasesClientWithGuard(upstreamURL, productName, nil)
}

// NewTerraformReleasesClientWithGuard is NewTerraformReleasesClient with an
// egress guard widening the SSRF deny-list (nil = strict). Index/metadata
// requests and binary downloads (index-provided URLs) are dialed through
// internal/httpsafe.
func NewTerraformReleasesClientWithGuard(upstreamURL, productName string, egress *httpsafe.Guard) *TerraformReleasesClient {
	if productName == "" {
		productName = "terraform"
	}
	return &TerraformReleasesClient{
		UpstreamURL:    strings.TrimRight(upstreamURL, "/"),
		ProductName:    productName,
		HTTPClient:     httpsafe.NewClient(30*time.Second, egress),
		DownloadClient: httpsafe.NewClient(10*time.Minute, egress),
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
	// PerFileSHAURLs maps binary filename → .sha256 sidecar download URL.
	// Populated by GitHubReleasesClient for projects (like OPA) that publish
	// individual .sha256 files instead of a combined SHA256SUMS.
	PerFileSHAURLs map[string]string
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

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
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

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
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

	resp, err := c.HTTPClient.Do(req) // #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
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
func (c *TerraformReleasesClient) DownloadBinaryStream(ctx context.Context, downloadURL string) (io.ReadCloser, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil) // #nosec G107 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	if err != nil {
		return nil, -1, fmt.Errorf("failed to build download request: %w", err)
	}

	resp, err := c.DownloadClient.Do(req)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to download binary: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, -1, fmt.Errorf("upstream returned %d for binary download: %s", resp.StatusCode, string(body))
	}

	return resp.Body, resp.ContentLength, nil
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

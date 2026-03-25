// Package mirror implements a client for fetching provider metadata and binaries
// from upstream Terraform registries (e.g., registry.terraform.io). It follows
// the HashiCorp Provider Registry Protocol: service discovery via
// /.well-known/terraform.json, then version enumeration and package download
// via the discovered endpoint URLs.
//
// Two separate HTTP clients are used — one for API calls (30-second timeout) and
// one for binary downloads (10-minute timeout). The timeout difference is
// intentional: API calls should fail quickly if the upstream is misconfigured or
// unreachable (a 30-second hang is a clear misconfiguration signal), while binary
// downloads legitimately take minutes for large provider archives on slow links.
// A single shared client with either timeout would cause unnecessary download
// failures or mask connectivity problems.
package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UpstreamRegistry represents a client for interacting with an upstream Terraform registry
type UpstreamRegistry struct {
	BaseURL        string
	HTTPClient     *http.Client // For API requests (short timeout)
	DownloadClient *http.Client // For file downloads (longer timeout)
}

// NewUpstreamRegistry creates a new upstream registry client
func NewUpstreamRegistry(baseURL string) *UpstreamRegistry {
	return &UpstreamRegistry{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		DownloadClient: &http.Client{
			Timeout: 10 * time.Minute, // Longer timeout for large provider binaries
		},
	}
}

// ServiceDiscoveryResponse represents the response from /.well-known/terraform.json
type ServiceDiscoveryResponse struct {
	ProvidersV1 string `json:"providers.v1"`
	ModulesV1   string `json:"modules.v1"`
}

// ProviderVersionsResponse represents the response from the provider versions endpoint
type ProviderVersionsResponse struct {
	Versions []ProviderVersion `json:"versions"`
}

// ProviderVersion represents a single version of a provider from upstream
type ProviderVersion struct {
	Version   string             `json:"version"`
	Protocols []string           `json:"protocols"`
	Platforms []ProviderPlatform `json:"platforms"`
}

// ProviderPlatform represents a platform-specific build of a provider
type ProviderPlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// ProviderPackageResponse represents the download information for a specific provider version
type ProviderPackageResponse struct {
	Protocols           []string        `json:"protocols"`
	OS                  string          `json:"os"`
	Arch                string          `json:"arch"`
	Filename            string          `json:"filename"`
	DownloadURL         string          `json:"download_url"`
	SHASumsURL          string          `json:"shasums_url"`
	SHASumsSignatureURL string          `json:"shasums_signature_url"`
	SHA256Sum           string          `json:"shasum"`
	SigningKeys         SigningKeysInfo `json:"signing_keys"`
}

// SigningKeysInfo contains GPG key information for verifying provider signatures
type SigningKeysInfo struct {
	GPGPublicKeys []GPGPublicKey `json:"gpg_public_keys"`
}

// GPGPublicKey represents a GPG public key
type GPGPublicKey struct {
	KeyID          string `json:"key_id"`
	ASCIIArmor     string `json:"ascii_armor"`
	TrustSignature string `json:"trust_signature"`
	Source         string `json:"source"`
	SourceURL      string `json:"source_url"`
}

// DiscoverServices performs service discovery to find the provider registry endpoints
func (u *UpstreamRegistry) DiscoverServices(ctx context.Context) (*ServiceDiscoveryResponse, error) {
	discoveryURL := fmt.Sprintf("%s/.well-known/terraform.json", u.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to perform discovery request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var discovery ServiceDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery response: %w", err)
	}

	return &discovery, nil
}

// ListProviderVersions lists all available versions of a provider from upstream
func (u *UpstreamRegistry) ListProviderVersions(ctx context.Context, namespace, providerName string) ([]ProviderVersion, error) {
	// First, discover the providers endpoint
	discovery, err := u.DiscoverServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("service discovery failed: %w", err)
	}

	// Build the provider versions URL.
	// discovery.ProvidersV1 may be either a relative path ("/v1/providers/") or an
	// absolute URL ("https://registry.terraform.io/v1/providers/"); use
	// url.ResolveReference so both cases produce a correct absolute URL.
	base, _ := url.Parse(u.BaseURL)
	provRef, _ := url.Parse(discovery.ProvidersV1)
	providersBase := base.ResolveReference(provRef)
	versionsURL := fmt.Sprintf("%s/%s/%s/versions",
		strings.TrimSuffix(providersBase.String(), "/"),
		namespace,
		providerName)

	req, err := http.NewRequestWithContext(ctx, "GET", versionsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create versions request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider versions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []ProviderVersion{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("versions request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var versionsResp ProviderVersionsResponse
	if err := json.Unmarshal(body, &versionsResp); err != nil {
		return nil, fmt.Errorf("failed to decode versions response: %w", err)
	}

	return versionsResp.Versions, nil
}

// GetProviderPackage gets the download information for a specific provider version and platform
func (u *UpstreamRegistry) GetProviderPackage(ctx context.Context, namespace, providerName, version, os, arch string) (*ProviderPackageResponse, error) {
	// First, discover the providers endpoint
	discovery, err := u.DiscoverServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("service discovery failed: %w", err)
	}

	// Build the provider package URL.
	// discovery.ProvidersV1 may be relative or absolute; use url.ResolveReference
	// to handle both cases.
	base, _ := url.Parse(u.BaseURL)
	provRef, _ := url.Parse(discovery.ProvidersV1)
	providersBase := base.ResolveReference(provRef)
	packageURL := fmt.Sprintf("%s/%s/%s/%s/download/%s/%s",
		strings.TrimSuffix(providersBase.String(), "/"),
		namespace,
		providerName,
		version,
		os,
		arch)

	req, err := http.NewRequestWithContext(ctx, "GET", packageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create package request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("package request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var packageResp ProviderPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&packageResp); err != nil {
		return nil, fmt.Errorf("failed to decode package response: %w", err)
	}

	return &packageResp, nil
}

// DownloadFile downloads a file from the given URL and returns the content
// It uses a longer timeout and implements retry logic for transient failures
func (u *UpstreamRegistry) DownloadFile(ctx context.Context, fileURL string) ([]byte, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		data, err := u.downloadFileOnce(ctx, fileURL)
		if err == nil {
			return data, nil
		}

		lastErr = err

		// Check if context was cancelled - don't retry
		if ctx.Err() != nil {
			return nil, fmt.Errorf("download cancelled: %w", ctx.Err())
		}

		// Log retry attempt
		if attempt < maxRetries {
			// Exponential backoff: 2s, 4s
			backoff := time.Duration(1<<attempt) * time.Second
			select {
			case <-time.After(backoff):
				// Continue to retry
			case <-ctx.Done():
				return nil, fmt.Errorf("download cancelled during retry wait: %w", ctx.Err())
			}
		}
	}

	return nil, fmt.Errorf("download failed after %d attempts: %w", maxRetries, lastErr)
}

// downloadFileOnce performs a single download attempt
func (u *UpstreamRegistry) downloadFileOnce(ctx context.Context, fileURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := u.DownloadClient.Do(req) // #nosec G704 -- URL is sourced from admin-controlled SCM provider or mirror configuration; non-admin users cannot influence these code paths
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read download content: %w", err)
	}

	return data, nil
}

// DownloadStream is returned by DownloadFileStream.  The caller must close Body
// when done regardless of error.
type DownloadStream struct {
	Body          io.ReadCloser
	ContentLength int64 // -1 if unknown
}

// DownloadFileStream initiates a download and returns a streaming reader so
// large binaries are not buffered in memory.  Unlike DownloadFile it makes only
// one attempt (retries on a stream would require re-downloading) and it is the
// caller's responsibility to close DownloadStream.Body.
func (u *UpstreamRegistry) DownloadFileStream(ctx context.Context, fileURL string) (*DownloadStream, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil) // #nosec G107 -- URL is admin-controlled
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := u.DownloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start download: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	return &DownloadStream{Body: resp.Body, ContentLength: resp.ContentLength}, nil
}

// ProviderDocEntry represents a single documentation entry returned by the
// upstream registry.
type ProviderDocEntry struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Slug        string  `json:"slug"`
	Category    string  `json:"category"`
	Subcategory *string `json:"subcategory"`
	Path        string  `json:"path"`
	Language    string  `json:"language"`
}

// providerDocListV2 is the JSON:API envelope returned by the v2 provider-docs
// list endpoint.
type providerDocListV2 struct {
	Data []providerDocEntryV2 `json:"data"`
	Meta struct {
		Pagination struct {
			CurrentPage int  `json:"current-page"`
			NextPage    *int `json:"next-page"`
		} `json:"pagination"`
	} `json:"meta"`
}

// providerDocEntryV2 is a single entry in the v2 provider-docs list response.
type providerDocEntryV2 struct {
	ID         string `json:"id"`
	Attributes struct {
		Category    string `json:"category"`
		Language    string `json:"language"`
		Path        string `json:"path"`
		Slug        string `json:"slug"`
		Subcategory string `json:"subcategory"`
		Title       string `json:"title"`
	} `json:"attributes"`
}

// providerDocContentV2 is the JSONAPI envelope returned by the v2 provider-docs endpoint.
type providerDocContentV2 struct {
	Data struct {
		Attributes struct {
			Content   string  `json:"content"`
			Title     string  `json:"title"`
			Category  string  `json:"category"`
			Slug      string  `json:"slug"`
			Language  string  `json:"language"`
			Truncated bool    `json:"truncated"`
			Path      *string `json:"path"`
		} `json:"attributes"`
	} `json:"data"`
}

// providerVersionListV2 is the JSON:API envelope for
// GET /v2/providers/{namespace}/{name}/versions.
type providerVersionListV2 struct {
	Data []providerVersionEntryV2 `json:"data"`
	Meta struct {
		Pagination struct {
			CurrentPage int  `json:"current-page"`
			NextPage    *int `json:"next-page"`
		} `json:"pagination"`
	} `json:"meta"`
}

// providerVersionEntryV2 is a single entry in the v2 provider-versions list.
type providerVersionEntryV2 struct {
	ID         string `json:"id"`
	Attributes struct {
		Version string `json:"version"`
	} `json:"attributes"`
}

// resolveProviderVersionID pages through the upstream v2
// /v2/providers/{namespace}/{name}/versions endpoint to find the numeric
// JSON:API ID for the given semver string. The v2 provider-docs API requires
// this numeric ID as filter[provider-version]; passing the semver string
// directly causes a 400 "provider-version filter is required" error.
func (u *UpstreamRegistry) resolveProviderVersionID(ctx context.Context, namespace, providerName, semver string) (string, error) {
	base := strings.TrimSuffix(u.BaseURL, "/")
	pageNum := 1

	for {
		reqURL := fmt.Sprintf(
			"%s/v2/providers/%s/%s/versions?page[size]=100&page[number]=%d",
			base,
			url.PathEscape(namespace),
			url.PathEscape(providerName),
			pageNum,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil) // #nosec G107 -- URL built from admin-controlled mirror configuration
		if err != nil {
			return "", fmt.Errorf("failed to create v2 provider versions request (page %d): %w", pageNum, err)
		}

		resp, err := u.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to fetch v2 provider versions (page %d): %w", pageNum, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return "", fmt.Errorf("v2 provider versions request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var page providerVersionListV2
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil {
			return "", fmt.Errorf("failed to decode v2 provider versions response (page %d): %w", pageNum, decodeErr)
		}

		for _, entry := range page.Data {
			if entry.Attributes.Version == semver {
				return entry.ID, nil
			}
		}

		if page.Meta.Pagination.NextPage == nil {
			break
		}
		pageNum++
	}

	return "", fmt.Errorf("provider version %s/%s@%s not found in upstream v2 versions API", namespace, providerName, semver)
}

// GetProviderDocIndexByVersion fetches version-specific documentation metadata
// from the upstream registry's v2 provider-docs API. It pages through all
// results (page[size]=100) and returns them as a flat slice. Only HCL-language
// entries are requested.
func (u *UpstreamRegistry) GetProviderDocIndexByVersion(ctx context.Context, namespace, providerName, version string) ([]ProviderDocEntry, error) {
	versionID, err := u.resolveProviderVersionID(ctx, namespace, providerName, version)
	if err != nil {
		return nil, fmt.Errorf("could not resolve v2 version ID for %s/%s@%s: %w", namespace, providerName, version, err)
	}

	base := strings.TrimSuffix(u.BaseURL, "/")
	var all []ProviderDocEntry
	pageNum := 1

	for {
		reqURL := fmt.Sprintf(
			"%s/v2/provider-docs?filter[provider-version]=%s&filter[language]=hcl&page[size]=100&page[number]=%d",
			base,
			url.QueryEscape(versionID),
			pageNum,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create v2 doc index request (page %d): %w", pageNum, err)
		}

		resp, err := u.HTTPClient.Do(req) // #nosec G107 -- URL built from admin-controlled mirror configuration
		if err != nil {
			return nil, fmt.Errorf("failed to fetch v2 provider doc index (page %d): %w", pageNum, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("v2 provider doc index request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var page providerDocListV2
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode v2 provider doc index response (page %d): %w", pageNum, decodeErr)
		}

		for _, entry := range page.Data {
			var subcat *string
			if entry.Attributes.Subcategory != "" {
				s := entry.Attributes.Subcategory
				subcat = &s
			}
			all = append(all, ProviderDocEntry{
				ID:          entry.ID,
				Title:       entry.Attributes.Title,
				Slug:        entry.Attributes.Slug,
				Category:    entry.Attributes.Category,
				Subcategory: subcat,
				Path:        entry.Attributes.Path,
				Language:    entry.Attributes.Language,
			})
		}

		if page.Meta.Pagination.NextPage == nil {
			break
		}
		pageNum++
	}

	return all, nil
}

// GetProviderDocContent fetches the full markdown content for a single documentation
// entry from the upstream registry's v2 provider-docs endpoint.
func (u *UpstreamRegistry) GetProviderDocContent(ctx context.Context, upstreamDocID string) (string, error) {
	docURL := fmt.Sprintf("%s/v2/provider-docs/%s",
		strings.TrimSuffix(u.BaseURL, "/"),
		upstreamDocID)

	req, err := http.NewRequestWithContext(ctx, "GET", docURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create doc content request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req) // #nosec G107 -- URL is sourced from admin-controlled mirror configuration
	if err != nil {
		return "", fmt.Errorf("failed to fetch provider doc content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("provider doc content request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var v2Resp providerDocContentV2
	if err := json.NewDecoder(resp.Body).Decode(&v2Resp); err != nil {
		return "", fmt.Errorf("failed to decode v2 provider doc response: %w", err)
	}

	return v2Resp.Data.Attributes.Content, nil
}

// ValidateRegistryURL validates that a registry URL is properly formatted
func ValidateRegistryURL(registryURL string) error {
	if registryURL == "" {
		return fmt.Errorf("registry URL cannot be empty")
	}

	parsed, err := url.Parse(registryURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("registry URL must use http or https scheme")
	}

	if parsed.Host == "" {
		return fmt.Errorf("registry URL must have a host")
	}

	return nil
}

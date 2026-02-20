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

	resp, err := u.HTTPClient.Do(req)
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

	// Build the provider versions URL
	// Format: {providers.v1}/{namespace}/{type}/versions
	// Note: discovery.ProvidersV1 typically ends with "/" so we need to handle that
	providersPath := strings.TrimSuffix(discovery.ProvidersV1, "/")
	versionsURL := fmt.Sprintf("%s%s/%s/%s/versions",
		u.BaseURL,
		providersPath,
		namespace,
		providerName)

	req, err := http.NewRequestWithContext(ctx, "GET", versionsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create versions request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req)
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

	// Read the body for debugging
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

	// Build the provider package URL
	// Format: {providers.v1}/{namespace}/{type}/{version}/download/{os}/{arch}
	// Note: discovery.ProvidersV1 typically ends with "/" so we need to handle that
	providersPath := strings.TrimSuffix(discovery.ProvidersV1, "/")
	packageURL := fmt.Sprintf("%s%s/%s/%s/%s/download/%s/%s",
		u.BaseURL,
		providersPath,
		namespace,
		providerName,
		version,
		os,
		arch)

	req, err := http.NewRequestWithContext(ctx, "GET", packageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create package request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req)
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

	resp, err := u.DownloadClient.Do(req)
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

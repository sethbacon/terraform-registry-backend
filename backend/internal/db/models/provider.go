// Package models - provider.go defines the Provider and ProviderVersion models representing
// Terraform providers in the registry and their published version metadata.
package models

import "time"

// Provider represents a Terraform provider in the registry
type Provider struct {
	ID             string
	OrganizationID string
	Namespace      string
	Type           string
	Description    *string
	Source         *string
	CreatedBy      *string // User ID who created this provider
	CreatedAt      time.Time
	UpdatedAt      time.Time
	// Joined fields (not stored in providers table)
	CreatedByName *string // User name who created this provider (joined from users table)
}

// ProviderSearchResult is returned by the search endpoint and includes aggregated
// version information (latest version, total downloads) fetched in a single query.
type ProviderSearchResult struct {
	Provider
	LatestVersion  *string `json:"latest_version,omitempty"`
	TotalDownloads int64   `json:"total_downloads"`
}

// ProviderVersion represents a specific version of a provider
type ProviderVersion struct {
	ID                  string
	ProviderID          string
	Version             string
	Protocols           []string   // JSON array of supported Terraform protocol versions (e.g. ["4.0", "5.0"])
	GPGPublicKey        string     // PEM-encoded GPG public key for signature verification
	ShasumURL           string     // URL to SHA256SUMS file
	ShasumSignatureURL  string     // URL to SHA256SUMS.sig file
	PublishedBy         *string    // User ID who published this version
	Deprecated          bool       // Whether this version is deprecated
	DeprecatedAt        *time.Time // When the version was deprecated
	DeprecationMessage  *string    // Optional message explaining deprecation
	CreatedAt           time.Time
	// Joined fields (not stored in provider_versions table)
	PublishedByName *string // User name who published this version (joined from users table)
}

// ProviderPlatform represents a platform-specific binary for a provider version
type ProviderPlatform struct {
	ID                 string
	ProviderVersionID  string
	OS                 string  // Operating system (linux, darwin, windows, etc.)
	Arch               string  // Architecture (amd64, arm64, 386, etc.)
	Filename           string  // Original filename of the provider binary
	StoragePath        string  // Path in storage backend
	StorageBackend     string  // Storage backend type (local, azure, s3)
	SizeBytes          int64   // File size in bytes
	Shasum             string  // SHA256 checksum of the binary
	DownloadCount      int64   // Number of times this platform binary has been downloaded
}

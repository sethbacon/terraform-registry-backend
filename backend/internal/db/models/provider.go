// Package models - provider.go defines the Provider and ProviderVersion models representing
// Terraform providers in the registry and their published version metadata.
package models

import "time"

// Provider represents a Terraform provider in the registry
type Provider struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Namespace      string    `json:"namespace"`
	Type           string    `json:"type"`
	Description    *string   `json:"description,omitempty"`
	Source         *string   `json:"source,omitempty"`
	CreatedBy      *string   `json:"created_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	// Joined fields (not stored in providers table)
	CreatedByName *string `json:"created_by_name,omitempty"`
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
	ID                 string
	ProviderID         string
	Version            string
	Protocols          []string   // JSON array of supported Terraform protocol versions (e.g. ["4.0", "5.0"])
	GPGPublicKey       string     // PEM-encoded GPG public key for signature verification
	ShasumURL          string     // URL to SHA256SUMS file
	ShasumSignatureURL string     // URL to SHA256SUMS.sig file
	PublishedBy        *string    // User ID who published this version
	Deprecated         bool       // Whether this version is deprecated
	DeprecatedAt       *time.Time // When the version was deprecated
	DeprecationMessage *string    // Optional message explaining deprecation
	CreatedAt          time.Time
	// Joined fields (not stored in provider_versions table)
	PublishedByName *string // User name who published this version (joined from users table)
}

// ProviderVersionShasum holds one entry from the upstream SHA256SUMS file for a
// provider version.  All entries are stored verbatim (including platforms that
// are not locally mirrored) so the Network Mirror Protocol endpoint can serve
// zh: hashes for every platform in the upstream release.
type ProviderVersionShasum struct {
	ProviderVersionID string // FK → provider_versions.id
	Filename          string // e.g. "terraform-provider-aws_6.35.1_linux_amd64.zip"
	SHA256Hex         string // lowercase hex SHA256 of the zip archive
}

// ProviderPlatform represents a platform-specific binary for a provider version
type ProviderPlatform struct {
	ID                string
	ProviderVersionID string
	OS                string  // Operating system (linux, darwin, windows, etc.)
	Arch              string  // Architecture (amd64, arm64, 386, etc.)
	Filename          string  // Original filename of the provider binary
	StoragePath       string  // Path in storage backend
	StorageBackend    string  // Storage backend type (local, azure, s3)
	SizeBytes         int64   // File size in bytes
	Shasum            string  // SHA256 checksum of the binary
	H1Hash            *string // Terraform h1: dirhash of the zip archive; nil for legacy rows
	DownloadCount     int64   // Number of times this platform binary has been downloaded
}

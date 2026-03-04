// Package models - module.go defines the Module and ModuleVersion models representing
// Terraform modules in the registry and their published version metadata.
package models

import "time"

// Module represents a Terraform module in the registry
type Module struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Namespace      string    `json:"namespace"`
	Name           string    `json:"name"`
	System         string    `json:"system"`
	Description    *string   `json:"description,omitempty"`
	Source         *string   `json:"source,omitempty"`
	CreatedBy      *string   `json:"created_by,omitempty"` // User ID who created this module
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	// Joined fields (not stored in modules table)
	CreatedByName *string `json:"created_by_name,omitempty"` // User name who created this module (joined from users table)
}

// ModuleSearchResult is returned by the search endpoint and includes aggregated
// version information (latest version, total downloads) fetched in a single query
// to avoid N+1 lookups.
type ModuleSearchResult struct {
	Module
	LatestVersion  *string `json:"latest_version,omitempty"`
	TotalDownloads int64   `json:"total_downloads"`
}

// ModuleVersion represents a specific version of a module
type ModuleVersion struct {
	ID                 string     `json:"id"`
	ModuleID           string     `json:"module_id"`
	Version            string     `json:"version"`
	StoragePath        string     `json:"storage_path"`
	StorageBackend     string     `json:"storage_backend"`
	SizeBytes          int64      `json:"size_bytes"`
	Checksum           string     `json:"checksum"`
	Readme             *string    `json:"readme,omitempty"`
	PublishedBy        *string    `json:"published_by,omitempty"`
	DownloadCount      int64      `json:"download_count"`
	Deprecated         bool       `json:"deprecated"`                    // Whether this version is deprecated
	DeprecatedAt       *time.Time `json:"deprecated_at,omitempty"`       // When the version was deprecated
	DeprecationMessage *string    `json:"deprecation_message,omitempty"` // Optional message explaining deprecation
	CreatedAt          time.Time  `json:"created_at"`
	// SCM source tracking fields (populated for webhook/sync-published versions)
	CommitSHA *string `json:"commit_sha,omitempty"`  // Git commit SHA at time of publish
	TagName   *string `json:"tag_name,omitempty"`    // Git tag name that triggered publish
	SCMRepoID *string `json:"scm_repo_id,omitempty"` // FK to module_scm_repos.id
	// Joined fields (not stored in module_versions table)
	PublishedByName *string `json:"published_by_name,omitempty"` // User name who published this version (joined from users table)
}

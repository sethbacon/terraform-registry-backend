// Package models - terraform_mirror.go defines models for the Terraform binary mirror feature.
// The mirror downloads and stores official Terraform/OpenTofu release binaries from an upstream
// source for supply-chain security and air-gapped deployments.
//
// Multiple mirror configs can coexist so that HashiCorp Terraform and OpenTofu can each
// have their own independent mirror configuration.
package models

import (
	"time"

	"github.com/google/uuid"
)

// TerraformMirrorConfig is a named configuration for a Terraform binary mirror.
// Multiple configs can coexist (e.g. one for HashiCorp Terraform, one for OpenTofu).
type TerraformMirrorConfig struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	Name              string     `json:"name" db:"name"`
	Description       *string    `json:"description,omitempty" db:"description"`
	Tool              string     `json:"tool" db:"tool"` // terraform | opentofu | custom
	Enabled           bool       `json:"enabled" db:"enabled"`
	UpstreamURL       string     `json:"upstream_url" db:"upstream_url"`
	PlatformFilter    *string    `json:"platform_filter,omitempty" db:"platform_filter"` // JSONB: []string "os/arch"
	VersionFilter     *string    `json:"version_filter,omitempty" db:"version_filter"`   // version filter expression
	GPGVerify         bool       `json:"gpg_verify" db:"gpg_verify"`
	StableOnly        bool       `json:"stable_only" db:"stable_only"` // exclude pre-release versions when true
	SyncIntervalHours int        `json:"sync_interval_hours" db:"sync_interval_hours"`
	LastSyncAt        *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastSyncStatus    *string    `json:"last_sync_status,omitempty" db:"last_sync_status"`
	LastSyncError     *string    `json:"last_sync_error,omitempty" db:"last_sync_error"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// TerraformVersion represents a single Terraform/OpenTofu release version within a mirror config.
type TerraformVersion struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	ConfigID     uuid.UUID  `json:"config_id" db:"config_id"`
	Version      string     `json:"version" db:"version"`
	IsLatest     bool       `json:"is_latest" db:"is_latest"`
	IsDeprecated bool       `json:"is_deprecated" db:"is_deprecated"`
	ReleaseDate  *time.Time `json:"release_date,omitempty" db:"release_date"`
	SyncStatus   string     `json:"sync_status" db:"sync_status"` // pending|syncing|synced|failed|partial
	SyncError    *string    `json:"sync_error,omitempty" db:"sync_error"`
	SyncedAt     *time.Time `json:"synced_at,omitempty" db:"synced_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`

	// Populated by joins — not stored in columns
	Platforms []TerraformVersionPlatform `json:"platforms,omitempty" db:"-"`
}

// TerraformVersionPlatform represents a single binary package for a version+os+arch combination.
type TerraformVersionPlatform struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	VersionID      uuid.UUID  `json:"version_id" db:"version_id"`
	OS             string     `json:"os" db:"os"`
	Arch           string     `json:"arch" db:"arch"`
	UpstreamURL    string     `json:"upstream_url" db:"upstream_url"`
	Filename       string     `json:"filename" db:"filename"`
	SHA256         string     `json:"sha256" db:"sha256"`
	StorageKey     *string    `json:"storage_key,omitempty" db:"storage_key"`
	StorageBackend *string    `json:"storage_backend,omitempty" db:"storage_backend"`
	SHA256Verified bool       `json:"sha256_verified" db:"sha256_verified"`
	GPGVerified    bool       `json:"gpg_verified" db:"gpg_verified"`
	SyncStatus     string     `json:"sync_status" db:"sync_status"` // pending|syncing|synced|failed
	SyncError      *string    `json:"sync_error,omitempty" db:"sync_error"`
	SyncedAt       *time.Time `json:"synced_at,omitempty" db:"synced_at"`
	DownloadCount  int64      `json:"download_count" db:"download_count"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// TerraformSyncHistory records each sync run (scheduled or manual) for a specific mirror config.
type TerraformSyncHistory struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	ConfigID        uuid.UUID  `json:"config_id" db:"config_id"`
	TriggeredBy     string     `json:"triggered_by" db:"triggered_by"` // scheduler|manual
	StartedAt       time.Time  `json:"started_at" db:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	Status          string     `json:"status" db:"status"` // running|success|failed|cancelled
	VersionsSynced  int        `json:"versions_synced" db:"versions_synced"`
	PlatformsSynced int        `json:"platforms_synced" db:"platforms_synced"`
	VersionsFailed  int        `json:"versions_failed" db:"versions_failed"`
	ErrorMessage    *string    `json:"error_message,omitempty" db:"error_message"`
	SyncDetails     *string    `json:"sync_details,omitempty" db:"sync_details"` // JSONB
}

// ---- Request / Response types ----

// CreateTerraformMirrorConfigRequest is the request body for POST /api/v1/admin/terraform-mirrors.
type CreateTerraformMirrorConfigRequest struct {
	Name              string   `json:"name" binding:"required,min=1,max=255"`
	Description       *string  `json:"description,omitempty"`
	Tool              string   `json:"tool" binding:"required,oneof=terraform opentofu custom"`
	UpstreamURL       string   `json:"upstream_url" binding:"required,url"`
	PlatformFilter    []string `json:"platform_filter,omitempty"`
	VersionFilter     *string  `json:"version_filter,omitempty"`
	GPGVerify         *bool    `json:"gpg_verify,omitempty"`
	StableOnly        *bool    `json:"stable_only,omitempty"`
	Enabled           *bool    `json:"enabled,omitempty"`
	SyncIntervalHours *int     `json:"sync_interval_hours,omitempty" binding:"omitempty,min=1"`
}

// UpdateTerraformMirrorConfigRequest is the request body for PUT /api/v1/admin/terraform-mirrors/:id.
type UpdateTerraformMirrorConfigRequest struct {
	Name              *string  `json:"name,omitempty" binding:"omitempty,min=1,max=255"`
	Description       *string  `json:"description,omitempty"`
	Tool              *string  `json:"tool,omitempty" binding:"omitempty,oneof=terraform opentofu custom"`
	UpstreamURL       *string  `json:"upstream_url,omitempty" binding:"omitempty,url"`
	PlatformFilter    []string `json:"platform_filter,omitempty"`
	VersionFilter     *string  `json:"version_filter,omitempty"`
	GPGVerify         *bool    `json:"gpg_verify,omitempty"`
	StableOnly        *bool    `json:"stable_only,omitempty"`
	Enabled           *bool    `json:"enabled,omitempty"`
	SyncIntervalHours *int     `json:"sync_interval_hours,omitempty" binding:"omitempty,min=1"`
}

// TerraformMirrorConfigListResponse wraps a list of mirror configs.
type TerraformMirrorConfigListResponse struct {
	Configs    []TerraformMirrorConfig `json:"configs"`
	TotalCount int                     `json:"total_count"`
}

// TerraformMirrorStatusResponse is returned by GET /api/v1/admin/terraform-mirrors/:id/status.
type TerraformMirrorStatusResponse struct {
	Config        *TerraformMirrorConfig `json:"config"`
	VersionCount  int                    `json:"version_count"`
	PlatformCount int                    `json:"platform_count"`
	PendingCount  int                    `json:"pending_count"`
	LatestVersion *string                `json:"latest_version,omitempty"`
}

// TerraformVersionListResponse wraps the list of versions with pagination info.
type TerraformVersionListResponse struct {
	Versions   []TerraformVersion `json:"versions"`
	TotalCount int                `json:"total_count"`
}

// TerraformSyncHistoryListResponse wraps sync history entries.
type TerraformSyncHistoryListResponse struct {
	History    []TerraformSyncHistory `json:"history"`
	TotalCount int                    `json:"total_count"`
}

// TerraformBinaryDownloadResponse is returned by the public download endpoint.
type TerraformBinaryDownloadResponse struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	Filename    string `json:"filename"`
	SHA256      string `json:"sha256"`
	DownloadURL string `json:"download_url"`
}

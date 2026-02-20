// Package models - mirror.go defines models for provider mirror configurations,
// including upstream registry settings, sync filters, sync state, and mirrored provider tracking.
package models

import (
	"time"

	"github.com/google/uuid"
)

// MirrorConfiguration represents a configuration for mirroring providers from an upstream registry
type MirrorConfiguration struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	Name                string     `json:"name" db:"name"`
	Description         *string    `json:"description,omitempty" db:"description"`
	UpstreamRegistryURL string     `json:"upstream_registry_url" db:"upstream_registry_url"`
	OrganizationID      *uuid.UUID `json:"organization_id,omitempty" db:"organization_id"`   // Organization for mirrored providers
	NamespaceFilter     *string    `json:"namespace_filter,omitempty" db:"namespace_filter"` // JSON array
	ProviderFilter      *string    `json:"provider_filter,omitempty" db:"provider_filter"`   // JSON array
	VersionFilter       *string    `json:"version_filter,omitempty" db:"version_filter"`     // Version filter: "3.", "latest:5", ">=3.0.0", or comma-separated
	PlatformFilter      *string    `json:"platform_filter,omitempty" db:"platform_filter"`   // JSON array of "os/arch" strings
	Enabled             bool       `json:"enabled" db:"enabled"`
	SyncIntervalHours   int        `json:"sync_interval_hours" db:"sync_interval_hours"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastSyncStatus      *string    `json:"last_sync_status,omitempty" db:"last_sync_status"` // success, failed, in_progress
	LastSyncError       *string    `json:"last_sync_error,omitempty" db:"last_sync_error"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// MirroredProvider tracks which providers were mirrored from which configuration
type MirroredProvider struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	MirrorConfigID    uuid.UUID  `json:"mirror_config_id" db:"mirror_config_id"`
	ProviderID        uuid.UUID  `json:"provider_id" db:"provider_id"`
	UpstreamNamespace string     `json:"upstream_namespace" db:"upstream_namespace"`
	UpstreamType      string     `json:"upstream_type" db:"upstream_type"`
	LastSyncedAt      time.Time  `json:"last_synced_at" db:"last_synced_at"`
	LastSyncVersion   *string    `json:"last_sync_version,omitempty" db:"last_sync_version"`
	SyncEnabled       bool       `json:"sync_enabled" db:"sync_enabled"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
}

// MirroredProviderVersion tracks individual version sync status
type MirroredProviderVersion struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	MirroredProviderID uuid.UUID `json:"mirrored_provider_id" db:"mirrored_provider_id"`
	ProviderVersionID  uuid.UUID `json:"provider_version_id" db:"provider_version_id"`
	UpstreamVersion    string    `json:"upstream_version" db:"upstream_version"`
	SyncedAt           time.Time `json:"synced_at" db:"synced_at"`
	ShasumVerified     bool      `json:"shasum_verified" db:"shasum_verified"`
	GPGVerified        bool      `json:"gpg_verified" db:"gpg_verified"`
}

// MirrorSyncHistory represents a historical record of a mirror synchronization operation
type MirrorSyncHistory struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	MirrorConfigID  uuid.UUID  `json:"mirror_config_id" db:"mirror_config_id"`
	StartedAt       time.Time  `json:"started_at" db:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	Status          string     `json:"status" db:"status"` // running, success, failed, cancelled
	ProvidersSynced int        `json:"providers_synced" db:"providers_synced"`
	ProvidersFailed int        `json:"providers_failed" db:"providers_failed"`
	ErrorMessage    *string    `json:"error_message,omitempty" db:"error_message"`
	SyncDetails     *string    `json:"sync_details,omitempty" db:"sync_details"` // JSONB
}

// CreateMirrorConfigRequest represents the request to create a new mirror configuration
type CreateMirrorConfigRequest struct {
	Name                string   `json:"name" binding:"required,min=1,max=255"`
	Description         *string  `json:"description,omitempty"`
	UpstreamRegistryURL string   `json:"upstream_registry_url" binding:"required,url"`
	OrganizationID      *string  `json:"organization_id,omitempty"`                               // Organization for mirrored providers
	NamespaceFilter     []string `json:"namespace_filter,omitempty"`                              // List of namespaces to mirror
	ProviderFilter      []string `json:"provider_filter,omitempty"`                               // List of provider names to mirror
	VersionFilter       *string  `json:"version_filter,omitempty"`                                // Version filter: "3.", "latest:5", ">=3.0.0", or comma-separated
	PlatformFilter      []string `json:"platform_filter,omitempty"`                               // List of "os/arch" strings (e.g. ["linux/amd64", "windows/amd64"])
	Enabled             *bool    `json:"enabled,omitempty"`                                       // Default: true
	SyncIntervalHours   *int     `json:"sync_interval_hours,omitempty" binding:"omitempty,min=1"` // Default: 24
}

// UpdateMirrorConfigRequest represents the request to update a mirror configuration
type UpdateMirrorConfigRequest struct {
	Name                *string  `json:"name,omitempty" binding:"omitempty,min=1,max=255"`
	Description         *string  `json:"description,omitempty"`
	UpstreamRegistryURL *string  `json:"upstream_registry_url,omitempty" binding:"omitempty,url"`
	OrganizationID      *string  `json:"organization_id,omitempty"` // Organization for mirrored providers
	NamespaceFilter     []string `json:"namespace_filter,omitempty"`
	ProviderFilter      []string `json:"provider_filter,omitempty"`
	VersionFilter       *string  `json:"version_filter,omitempty"` // Version filter: "3.", "latest:5", ">=3.0.0", or comma-separated
	PlatformFilter      []string `json:"platform_filter,omitempty"` // List of "os/arch" strings (e.g. ["linux/amd64", "windows/amd64"])
	Enabled             *bool    `json:"enabled,omitempty"`
	SyncIntervalHours   *int     `json:"sync_interval_hours,omitempty" binding:"omitempty,min=1"`
}

// TriggerSyncRequest represents the request to trigger a manual sync
type TriggerSyncRequest struct {
	Namespace    *string `json:"namespace,omitempty"`     // Optional: sync specific namespace
	ProviderName *string `json:"provider_name,omitempty"` // Optional: sync specific provider
}

// MirrorSyncStatus represents the status response for a mirror sync operation
type MirrorSyncStatus struct {
	MirrorConfig  MirrorConfiguration `json:"mirror_config"`
	CurrentSync   *MirrorSyncHistory  `json:"current_sync,omitempty"`
	RecentSyncs   []MirrorSyncHistory `json:"recent_syncs"`
	NextScheduled *time.Time          `json:"next_scheduled,omitempty"`
}

// Package models defines the StorageMigration and StorageMigrationItem types
// used for tracking artifact migrations between storage backends.
package models

import "time"

// StorageMigration tracks the overall progress of migrating artifacts from one
// storage backend to another.
type StorageMigration struct {
	ID                string     `json:"id" db:"id"`
	SourceConfigID    string     `json:"source_config_id" db:"source_config_id"`
	TargetConfigID    string     `json:"target_config_id" db:"target_config_id"`
	Status            string     `json:"status" db:"status"`
	TotalArtifacts    int        `json:"total_artifacts" db:"total_artifacts"`
	MigratedArtifacts int        `json:"migrated_artifacts" db:"migrated_artifacts"`
	FailedArtifacts   int        `json:"failed_artifacts" db:"failed_artifacts"`
	SkippedArtifacts  int        `json:"skipped_artifacts" db:"skipped_artifacts"`
	ErrorMessage      *string    `json:"error_message,omitempty" db:"error_message"`
	StartedAt         *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	CreatedBy         *string    `json:"created_by,omitempty" db:"created_by"`
}

// StorageMigrationItem tracks the migration status of a single artifact (module
// version archive or provider platform binary).
type StorageMigrationItem struct {
	ID           string     `json:"id" db:"id"`
	MigrationID  string     `json:"migration_id" db:"migration_id"`
	ArtifactType string     `json:"artifact_type" db:"artifact_type"`
	ArtifactID   string     `json:"artifact_id" db:"artifact_id"`
	SourcePath   string     `json:"source_path" db:"source_path"`
	Status       string     `json:"status" db:"status"`
	ErrorMessage *string    `json:"error_message,omitempty" db:"error_message"`
	MigratedAt   *time.Time `json:"migrated_at,omitempty" db:"migrated_at"`
}

// MigrationPlan describes what a migration between two storage configs would
// involve, without actually starting it. Returned by the plan endpoint.
type MigrationPlan struct {
	SourceConfigID string `json:"source_config_id"`
	TargetConfigID string `json:"target_config_id"`
	ModuleCount    int    `json:"module_count"`
	ProviderCount  int    `json:"provider_count"`
	TotalArtifacts int    `json:"total_artifacts"`
}

// ArtifactInfo is a lightweight projection of a module version or provider
// platform row, carrying only the fields needed to copy an artifact between
// storage backends.
type ArtifactInfo struct {
	ID          string `db:"id"`
	StoragePath string `db:"storage_path"`
}

// mirror_repository.go implements MirrorRepository, providing database queries for mirror
// configuration, mirrored provider versions, and sync history records.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// MirrorRepository handles database operations for mirror configurations
type MirrorRepository struct {
	db *sqlx.DB
}

// NewMirrorRepository creates a new mirror repository
func NewMirrorRepository(db *sqlx.DB) *MirrorRepository {
	return &MirrorRepository{db: db}
}

// Create creates a new mirror configuration
func (r *MirrorRepository) Create(ctx context.Context, config *models.MirrorConfiguration) error {
	query := `
		INSERT INTO mirror_configurations (
			id, name, description, upstream_registry_url, organization_id, namespace_filter, provider_filter,
			version_filter, platform_filter, enabled, sync_interval_hours, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := r.db.ExecContext(ctx, query,
		config.ID,
		config.Name,
		config.Description,
		config.UpstreamRegistryURL,
		config.OrganizationID,
		config.NamespaceFilter,
		config.ProviderFilter,
		config.VersionFilter,
		config.PlatformFilter,
		config.Enabled,
		config.SyncIntervalHours,
		config.CreatedAt,
		config.UpdatedAt,
		config.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create mirror configuration: %w", err)
	}

	return nil
}

// GetByID retrieves a mirror configuration by ID
func (r *MirrorRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.MirrorConfiguration, error) {
	query := `
		SELECT id, name, description, upstream_registry_url, organization_id, namespace_filter, provider_filter,
		       version_filter, platform_filter, enabled, sync_interval_hours, last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at, created_by
		FROM mirror_configurations
		WHERE id = $1
	`

	var config models.MirrorConfiguration
	err := r.db.GetContext(ctx, &config, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirror configuration: %w", err)
	}

	return &config, nil
}

// GetByName retrieves a mirror configuration by name
func (r *MirrorRepository) GetByName(ctx context.Context, name string) (*models.MirrorConfiguration, error) {
	query := `
		SELECT id, name, description, upstream_registry_url, organization_id, namespace_filter, provider_filter,
		       version_filter, platform_filter, enabled, sync_interval_hours, last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at, created_by
		FROM mirror_configurations
		WHERE name = $1
	`

	var config models.MirrorConfiguration
	err := r.db.GetContext(ctx, &config, query, name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirror configuration by name: %w", err)
	}

	return &config, nil
}

// List retrieves all mirror configurations
func (r *MirrorRepository) List(ctx context.Context, enabledOnly bool) ([]models.MirrorConfiguration, error) {
	query := `
		SELECT id, name, description, upstream_registry_url, organization_id, namespace_filter, provider_filter,
		       version_filter, platform_filter, enabled, sync_interval_hours, last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at, created_by
		FROM mirror_configurations
	`

	if enabledOnly {
		query += " WHERE enabled = true"
	}

	query += " ORDER BY name"

	var configs []models.MirrorConfiguration
	err := r.db.SelectContext(ctx, &configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list mirror configurations: %w", err)
	}

	return configs, nil
}

// Update updates a mirror configuration
func (r *MirrorRepository) Update(ctx context.Context, config *models.MirrorConfiguration) error {
	config.UpdatedAt = time.Now()

	query := `
		UPDATE mirror_configurations
		SET name = $2, description = $3, upstream_registry_url = $4, organization_id = $5,
		    namespace_filter = $6, provider_filter = $7, version_filter = $8, platform_filter = $9,
		    enabled = $10, sync_interval_hours = $11, updated_at = $12
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		config.ID,
		config.Name,
		config.Description,
		config.UpstreamRegistryURL,
		config.OrganizationID,
		config.NamespaceFilter,
		config.ProviderFilter,
		config.VersionFilter,
		config.PlatformFilter,
		config.Enabled,
		config.SyncIntervalHours,
		config.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update mirror configuration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("mirror configuration not found")
	}

	return nil
}

// Delete deletes a mirror configuration
func (r *MirrorRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM mirror_configurations WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete mirror configuration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("mirror configuration not found")
	}

	return nil
}

// UpdateSyncStatus updates the sync status of a mirror configuration
func (r *MirrorRepository) UpdateSyncStatus(ctx context.Context, id uuid.UUID, status string, syncError *string) error {
	now := time.Now()

	query := `
		UPDATE mirror_configurations
		SET last_sync_at = $2, last_sync_status = $3, last_sync_error = $4, updated_at = $5
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, now, status, syncError, now)
	if err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}

	return nil
}

// GetMirrorsNeedingSync retrieves mirror configurations that need to be synced
func (r *MirrorRepository) GetMirrorsNeedingSync(ctx context.Context) ([]models.MirrorConfiguration, error) {
	query := `
		SELECT id, name, description, upstream_registry_url, organization_id, namespace_filter, provider_filter,
		       version_filter, platform_filter, enabled, sync_interval_hours, last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at, created_by
		FROM mirror_configurations
		WHERE enabled = true
		  AND (
		      last_sync_at IS NULL
		      OR last_sync_at < NOW() - (sync_interval_hours || ' hours')::INTERVAL
		  )
		  AND (last_sync_status IS NULL OR last_sync_status != 'in_progress')
		ORDER BY last_sync_at NULLS FIRST
	`

	var configs []models.MirrorConfiguration
	err := r.db.SelectContext(ctx, &configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get mirrors needing sync: %w", err)
	}

	return configs, nil
}

// CreateSyncHistory creates a new sync history record
func (r *MirrorRepository) CreateSyncHistory(ctx context.Context, history *models.MirrorSyncHistory) error {
	query := `
		INSERT INTO mirror_sync_history (
			id, mirror_config_id, started_at, status, providers_synced, providers_failed
		) VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(ctx, query,
		history.ID,
		history.MirrorConfigID,
		history.StartedAt,
		history.Status,
		history.ProvidersSynced,
		history.ProvidersFailed,
	)

	if err != nil {
		return fmt.Errorf("failed to create sync history: %w", err)
	}

	return nil
}

// UpdateSyncHistory updates a sync history record
func (r *MirrorRepository) UpdateSyncHistory(ctx context.Context, history *models.MirrorSyncHistory) error {
	query := `
		UPDATE mirror_sync_history
		SET completed_at = $2, status = $3, providers_synced = $4, providers_failed = $5,
		    error_message = $6, sync_details = $7
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		history.ID,
		history.CompletedAt,
		history.Status,
		history.ProvidersSynced,
		history.ProvidersFailed,
		history.ErrorMessage,
		history.SyncDetails,
	)

	if err != nil {
		return fmt.Errorf("failed to update sync history: %w", err)
	}

	return nil

}

// GetSyncHistory retrieves sync history for a mirror configuration
func (r *MirrorRepository) GetSyncHistory(ctx context.Context, mirrorConfigID uuid.UUID, limit int) ([]models.MirrorSyncHistory, error) {
	query := `
		SELECT id, mirror_config_id, started_at, completed_at, status,
		       providers_synced, providers_failed, error_message, sync_details
		FROM mirror_sync_history
		WHERE mirror_config_id = $1
		ORDER BY started_at DESC
		LIMIT $2
	`

	var history []models.MirrorSyncHistory
	err := r.db.SelectContext(ctx, &history, query, mirrorConfigID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync history: %w", err)
	}

	return history, nil
}

// GetActiveSyncHistory retrieves the currently running sync for a mirror configuration
func (r *MirrorRepository) GetActiveSyncHistory(ctx context.Context, mirrorConfigID uuid.UUID) (*models.MirrorSyncHistory, error) {
	query := `
		SELECT id, mirror_config_id, started_at, completed_at, status,
		       providers_synced, providers_failed, error_message, sync_details
		FROM mirror_sync_history
		WHERE mirror_config_id = $1 AND status = 'running'
		ORDER BY started_at DESC
		LIMIT 1
	`

	var history models.MirrorSyncHistory
	err := r.db.GetContext(ctx, &history, query, mirrorConfigID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active sync history: %w", err)
	}

	return &history, nil
}


// Helper function to convert JSON string to string array
func jsonToStringArray(jsonStr *string) ([]string, error) {
	if jsonStr == nil || *jsonStr == "" {
		return nil, nil
	}

	var arr []string
	if err := json.Unmarshal([]byte(*jsonStr), &arr); err != nil {
		return nil, err
	}

	return arr, nil
}

// CreateMirroredProvider creates a tracking record for a mirrored provider
func (r *MirrorRepository) CreateMirroredProvider(ctx context.Context, mp *models.MirroredProvider) error {
	query := `
		INSERT INTO mirrored_providers (
			id, mirror_config_id, provider_id, upstream_namespace, upstream_type,
			last_synced_at, last_sync_version, sync_enabled, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		mp.ID,
		mp.MirrorConfigID,
		mp.ProviderID,
		mp.UpstreamNamespace,
		mp.UpstreamType,
		mp.LastSyncedAt,
		mp.LastSyncVersion,
		mp.SyncEnabled,
		mp.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create mirrored provider: %w", err)
	}

	return nil
}

// GetMirroredProvider retrieves a mirrored provider by mirror config and upstream info
func (r *MirrorRepository) GetMirroredProvider(ctx context.Context, mirrorConfigID uuid.UUID, upstreamNamespace, upstreamType string) (*models.MirroredProvider, error) {
	query := `
		SELECT id, mirror_config_id, provider_id, upstream_namespace, upstream_type,
		       last_synced_at, last_sync_version, sync_enabled, created_at
		FROM mirrored_providers
		WHERE mirror_config_id = $1 AND upstream_namespace = $2 AND upstream_type = $3
	`

	var mp models.MirroredProvider
	err := r.db.GetContext(ctx, &mp, query, mirrorConfigID, upstreamNamespace, upstreamType)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirrored provider: %w", err)
	}

	return &mp, nil
}

// GetMirroredProviderByProviderID retrieves a mirrored provider by the local provider ID
func (r *MirrorRepository) GetMirroredProviderByProviderID(ctx context.Context, providerID uuid.UUID) (*models.MirroredProvider, error) {
	query := `
		SELECT id, mirror_config_id, provider_id, upstream_namespace, upstream_type,
		       last_synced_at, last_sync_version, sync_enabled, created_at
		FROM mirrored_providers
		WHERE provider_id = $1
	`

	var mp models.MirroredProvider
	err := r.db.GetContext(ctx, &mp, query, providerID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirrored provider: %w", err)
	}

	return &mp, nil
}

// UpdateMirroredProvider updates a mirrored provider's sync information
func (r *MirrorRepository) UpdateMirroredProvider(ctx context.Context, mp *models.MirroredProvider) error {
	query := `
		UPDATE mirrored_providers
		SET last_synced_at = $2, last_sync_version = $3, sync_enabled = $4
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		mp.ID,
		mp.LastSyncedAt,
		mp.LastSyncVersion,
		mp.SyncEnabled,
	)

	if err != nil {
		return fmt.Errorf("failed to update mirrored provider: %w", err)
	}

	return nil
}

// ListMirroredProviders retrieves all mirrored providers for a mirror configuration
func (r *MirrorRepository) ListMirroredProviders(ctx context.Context, mirrorConfigID uuid.UUID) ([]models.MirroredProvider, error) {
	query := `
		SELECT id, mirror_config_id, provider_id, upstream_namespace, upstream_type,
		       last_synced_at, last_sync_version, sync_enabled, created_at
		FROM mirrored_providers
		WHERE mirror_config_id = $1
		ORDER BY upstream_namespace, upstream_type
	`

	var providers []models.MirroredProvider
	err := r.db.SelectContext(ctx, &providers, query, mirrorConfigID)
	if err != nil {
		return nil, fmt.Errorf("failed to list mirrored providers: %w", err)
	}

	return providers, nil
}

// CreateMirroredProviderVersion tracks a synced version
func (r *MirrorRepository) CreateMirroredProviderVersion(ctx context.Context, mpv *models.MirroredProviderVersion) error {
	query := `
		INSERT INTO mirrored_provider_versions (
			id, mirrored_provider_id, provider_version_id, upstream_version,
			synced_at, shasum_verified, gpg_verified
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (mirrored_provider_id, upstream_version) DO UPDATE
		SET provider_version_id = EXCLUDED.provider_version_id, 
		    synced_at = EXCLUDED.synced_at, 
		    shasum_verified = EXCLUDED.shasum_verified, 
		    gpg_verified = EXCLUDED.gpg_verified
	`

	_, err := r.db.ExecContext(ctx, query,
		mpv.ID,
		mpv.MirroredProviderID,
		mpv.ProviderVersionID,
		mpv.UpstreamVersion,
		mpv.SyncedAt,
		mpv.ShasumVerified,
		mpv.GPGVerified,
	)

	if err != nil {
		return fmt.Errorf("failed to create mirrored provider version: %w", err)
	}

	return nil
}

// GetMirroredProviderVersion retrieves a specific mirrored version
func (r *MirrorRepository) GetMirroredProviderVersion(ctx context.Context, mirroredProviderID uuid.UUID, version string) (*models.MirroredProviderVersion, error) {
	query := `
		SELECT id, mirrored_provider_id, provider_version_id, upstream_version,
		       synced_at, shasum_verified, gpg_verified
		FROM mirrored_provider_versions
		WHERE mirrored_provider_id = $1 AND upstream_version = $2
	`

	var mpv models.MirroredProviderVersion
	err := r.db.GetContext(ctx, &mpv, query, mirroredProviderID, version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirrored provider version: %w", err)
	}

	return &mpv, nil
}

// ListMirroredProviderVersions retrieves all synced versions for a mirrored provider
func (r *MirrorRepository) ListMirroredProviderVersions(ctx context.Context, mirroredProviderID uuid.UUID) ([]models.MirroredProviderVersion, error) {
	query := `
		SELECT id, mirrored_provider_id, provider_version_id, upstream_version,
		       synced_at, shasum_verified, gpg_verified
		FROM mirrored_provider_versions
		WHERE mirrored_provider_id = $1
		ORDER BY synced_at DESC
	`

	var versions []models.MirroredProviderVersion
	err := r.db.SelectContext(ctx, &versions, query, mirroredProviderID)
	if err != nil {
		return nil, fmt.Errorf("failed to list mirrored provider versions: %w", err)
	}

	return versions, nil
}

// GetMirroredProviderVersionByVersionID retrieves a mirrored provider version by the local version ID
func (r *MirrorRepository) GetMirroredProviderVersionByVersionID(ctx context.Context, providerVersionID uuid.UUID) (*models.MirroredProviderVersion, error) {
	query := `
		SELECT id, mirrored_provider_id, provider_version_id, upstream_version,
		       synced_at, shasum_verified, gpg_verified
		FROM mirrored_provider_versions
		WHERE provider_version_id = $1
	`

	var mpv models.MirroredProviderVersion
	err := r.db.GetContext(ctx, &mpv, query, providerVersionID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mirrored provider version by version ID: %w", err)
	}

	return &mpv, nil
}

// terraform_mirror_repository.go provides database operations for the Terraform binary mirror.
// It manages named mirror configs (multi-config design), version/platform catalog, and sync history.
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

// TerraformMirrorRepository handles database operations for the Terraform binary mirror.
type TerraformMirrorRepository struct {
	db *sqlx.DB
}

// NewTerraformMirrorRepository creates a new TerraformMirrorRepository.
func NewTerraformMirrorRepository(db *sqlx.DB) *TerraformMirrorRepository {
	return &TerraformMirrorRepository{db: db}
}

// ---- Config CRUD -----------------------------------------------------------

// Create inserts a new mirror config row and returns it with db-generated fields populated.
func (r *TerraformMirrorRepository) Create(ctx context.Context, cfg *models.TerraformMirrorConfig) error {
	if cfg.ID == uuid.Nil {
		cfg.ID = uuid.New()
	}
	now := time.Now()
	cfg.CreatedAt = now
	cfg.UpdatedAt = now

	query := `
		INSERT INTO terraform_mirror_configs (
			id, name, description, tool, enabled, upstream_url,
			platform_filter, gpg_verify, sync_interval_hours,
			created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, name, description, tool, enabled, upstream_url,
		          platform_filter, gpg_verify, sync_interval_hours,
		          last_sync_at, last_sync_status, last_sync_error,
		          created_at, updated_at
	`

	return r.db.QueryRowContext(ctx, query,
		cfg.ID,
		cfg.Name,
		cfg.Description,
		cfg.Tool,
		cfg.Enabled,
		cfg.UpstreamURL,
		cfg.PlatformFilter,
		cfg.GPGVerify,
		cfg.SyncIntervalHours,
		cfg.CreatedAt,
		cfg.UpdatedAt,
	).Scan(
		&cfg.ID,
		&cfg.Name,
		&cfg.Description,
		&cfg.Tool,
		&cfg.Enabled,
		&cfg.UpstreamURL,
		&cfg.PlatformFilter,
		&cfg.GPGVerify,
		&cfg.SyncIntervalHours,
		&cfg.LastSyncAt,
		&cfg.LastSyncStatus,
		&cfg.LastSyncError,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
	)
}

// GetByID returns a mirror config by its UUID, or nil if not found.
func (r *TerraformMirrorRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.TerraformMirrorConfig, error) {
	query := `
		SELECT id, name, description, tool, enabled, upstream_url,
		       platform_filter, gpg_verify, sync_interval_hours,
		       last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at
		FROM terraform_mirror_configs
		WHERE id = $1
	`

	var cfg models.TerraformMirrorConfig
	err := r.db.GetContext(ctx, &cfg, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform mirror config: %w", err)
	}

	return &cfg, nil
}

// GetByName returns a mirror config by its unique name, or nil if not found.
func (r *TerraformMirrorRepository) GetByName(ctx context.Context, name string) (*models.TerraformMirrorConfig, error) {
	query := `
		SELECT id, name, description, tool, enabled, upstream_url,
		       platform_filter, gpg_verify, sync_interval_hours,
		       last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at
		FROM terraform_mirror_configs
		WHERE name = $1
	`

	var cfg models.TerraformMirrorConfig
	err := r.db.GetContext(ctx, &cfg, query, name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform mirror config by name: %w", err)
	}

	return &cfg, nil
}

// ListAll returns all mirror configs ordered by name.
func (r *TerraformMirrorRepository) ListAll(ctx context.Context) ([]models.TerraformMirrorConfig, error) {
	query := `
		SELECT id, name, description, tool, enabled, upstream_url,
		       platform_filter, gpg_verify, sync_interval_hours,
		       last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at
		FROM terraform_mirror_configs
		ORDER BY name
	`

	var configs []models.TerraformMirrorConfig
	if err := r.db.SelectContext(ctx, &configs, query); err != nil {
		return nil, fmt.Errorf("failed to list terraform mirror configs: %w", err)
	}

	return configs, nil
}

// ListEnabled returns only enabled mirror configs.
func (r *TerraformMirrorRepository) ListEnabled(ctx context.Context) ([]models.TerraformMirrorConfig, error) {
	query := `
		SELECT id, name, description, tool, enabled, upstream_url,
		       platform_filter, gpg_verify, sync_interval_hours,
		       last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at
		FROM terraform_mirror_configs
		WHERE enabled = true
		ORDER BY name
	`

	var configs []models.TerraformMirrorConfig
	if err := r.db.SelectContext(ctx, &configs, query); err != nil {
		return nil, fmt.Errorf("failed to list enabled terraform mirror configs: %w", err)
	}

	return configs, nil
}

// GetConfigsNeedingSync returns enabled configs whose next sync time has been reached.
func (r *TerraformMirrorRepository) GetConfigsNeedingSync(ctx context.Context) ([]models.TerraformMirrorConfig, error) {
	query := `
		SELECT id, name, description, tool, enabled, upstream_url,
		       platform_filter, gpg_verify, sync_interval_hours,
		       last_sync_at, last_sync_status, last_sync_error,
		       created_at, updated_at
		FROM terraform_mirror_configs
		WHERE enabled = true
		  AND (
		        last_sync_at IS NULL
		        OR last_sync_at + (sync_interval_hours * INTERVAL '1 hour') <= NOW()
		      )
		ORDER BY last_sync_at ASC NULLS FIRST
	`

	var configs []models.TerraformMirrorConfig
	if err := r.db.SelectContext(ctx, &configs, query); err != nil {
		return nil, fmt.Errorf("failed to get terraform mirror configs needing sync: %w", err)
	}

	return configs, nil
}

// Update persists mutable fields of a mirror config.
func (r *TerraformMirrorRepository) Update(ctx context.Context, cfg *models.TerraformMirrorConfig) error {
	cfg.UpdatedAt = time.Now()

	query := `
		UPDATE terraform_mirror_configs
		SET name                = $2,
		    description         = $3,
		    tool                = $4,
		    enabled             = $5,
		    upstream_url        = $6,
		    platform_filter     = $7,
		    gpg_verify          = $8,
		    sync_interval_hours = $9,
		    updated_at          = $10
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		cfg.ID,
		cfg.Name,
		cfg.Description,
		cfg.Tool,
		cfg.Enabled,
		cfg.UpstreamURL,
		cfg.PlatformFilter,
		cfg.GPGVerify,
		cfg.SyncIntervalHours,
		cfg.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update terraform mirror config: %w", err)
	}

	return nil
}

// Delete removes a mirror config (and cascades to versions/platforms/history).
func (r *TerraformMirrorRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM terraform_mirror_configs WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete terraform mirror config: %w", err)
	}

	return nil
}

// UpdateSyncStatus updates the last_sync_* fields after a sync run.
func (r *TerraformMirrorRepository) UpdateSyncStatus(ctx context.Context, id uuid.UUID, status string, syncErr *string) error {
	now := time.Now()

	query := `
		UPDATE terraform_mirror_configs
		SET last_sync_at = $2, last_sync_status = $3, last_sync_error = $4, updated_at = $5
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, now, status, syncErr, now)
	if err != nil {
		return fmt.Errorf("failed to update terraform mirror config sync status: %w", err)
	}

	return nil
}

// ---- Versions --------------------------------------------------------------

// UpsertVersion inserts a version row or updates it if (config_id, version) already exists.
// Returns the resulting row (including generated id).
func (r *TerraformMirrorRepository) UpsertVersion(ctx context.Context, v *models.TerraformVersion) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	now := time.Now()
	v.CreatedAt = now
	v.UpdatedAt = now

	query := `
		INSERT INTO terraform_versions (
			id, config_id, version, is_latest, is_deprecated, release_date, sync_status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (config_id, version) DO UPDATE
		SET is_deprecated = EXCLUDED.is_deprecated,
		    release_date  = COALESCE(EXCLUDED.release_date, terraform_versions.release_date),
		    updated_at    = EXCLUDED.updated_at
		RETURNING id, config_id, version, is_latest, is_deprecated, release_date,
		          sync_status, sync_error, synced_at, created_at, updated_at
	`

	return r.db.QueryRowContext(ctx, query,
		v.ID,
		v.ConfigID,
		v.Version,
		v.IsLatest,
		v.IsDeprecated,
		v.ReleaseDate,
		v.SyncStatus,
		v.CreatedAt,
		v.UpdatedAt,
	).Scan(
		&v.ID,
		&v.ConfigID,
		&v.Version,
		&v.IsLatest,
		&v.IsDeprecated,
		&v.ReleaseDate,
		&v.SyncStatus,
		&v.SyncError,
		&v.SyncedAt,
		&v.CreatedAt,
		&v.UpdatedAt,
	)
}

// GetVersionByString looks up a version row by its semver string within a config.
func (r *TerraformMirrorRepository) GetVersionByString(ctx context.Context, configID uuid.UUID, version string) (*models.TerraformVersion, error) {
	query := `
		SELECT id, config_id, version, is_latest, is_deprecated, release_date,
		       sync_status, sync_error, synced_at, created_at, updated_at
		FROM terraform_versions
		WHERE config_id = $1 AND version = $2
	`

	var v models.TerraformVersion
	err := r.db.GetContext(ctx, &v, query, configID, version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform version: %w", err)
	}

	return &v, nil
}

// GetLatestVersion returns the version marked is_latest = true for a given config.
func (r *TerraformMirrorRepository) GetLatestVersion(ctx context.Context, configID uuid.UUID) (*models.TerraformVersion, error) {
	query := `
		SELECT id, config_id, version, is_latest, is_deprecated, release_date,
		       sync_status, sync_error, synced_at, created_at, updated_at
		FROM terraform_versions
		WHERE config_id = $1 AND is_latest = true
		LIMIT 1
	`

	var v models.TerraformVersion
	err := r.db.GetContext(ctx, &v, query, configID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest terraform version: %w", err)
	}

	return &v, nil
}

// ListVersions returns all version rows for a config ordered by created_at descending.
// When syncedOnly is true only versions with sync_status = 'synced' are returned.
func (r *TerraformMirrorRepository) ListVersions(ctx context.Context, configID uuid.UUID, syncedOnly bool) ([]models.TerraformVersion, error) {
	query := `
		SELECT id, config_id, version, is_latest, is_deprecated, release_date,
		       sync_status, sync_error, synced_at, created_at, updated_at
		FROM terraform_versions
		WHERE config_id = $1
	`

	if syncedOnly {
		query += " AND sync_status = 'synced'"
	}

	query += " ORDER BY created_at DESC"

	var versions []models.TerraformVersion
	err := r.db.SelectContext(ctx, &versions, query, configID)
	if err != nil {
		return nil, fmt.Errorf("failed to list terraform versions: %w", err)
	}

	return versions, nil
}

// UpdateVersionSyncStatus updates the sync_status, sync_error, and synced_at for a version.
func (r *TerraformMirrorRepository) UpdateVersionSyncStatus(ctx context.Context, id uuid.UUID, status string, syncErr *string) error {
	now := time.Now()
	var syncedAt *time.Time
	if status == "synced" {
		syncedAt = &now
	}

	query := `
		UPDATE terraform_versions
		SET sync_status = $2, sync_error = $3, synced_at = $4, updated_at = $5
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, status, syncErr, syncedAt, now)
	if err != nil {
		return fmt.Errorf("failed to update terraform version sync status: %w", err)
	}

	return nil
}

// SetLatestVersion marks a single version as is_latest and clears all others within the same config.
// This runs inside a transaction to avoid races.
func (r *TerraformMirrorRepository) SetLatestVersion(ctx context.Context, configID, versionID uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Clear all is_latest within this config
	if _, err := tx.ExecContext(ctx,
		`UPDATE terraform_versions SET is_latest = false WHERE config_id = $1 AND is_latest = true`,
		configID,
	); err != nil {
		return fmt.Errorf("failed to clear is_latest: %w", err)
	}

	// Set the target
	if _, err := tx.ExecContext(ctx,
		`UPDATE terraform_versions SET is_latest = true WHERE id = $1`,
		versionID,
	); err != nil {
		return fmt.Errorf("failed to set is_latest: %w", err)
	}

	return tx.Commit()
}

// DeleteVersion deletes a version and its platforms (cascade).
func (r *TerraformMirrorRepository) DeleteVersion(ctx context.Context, versionID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM terraform_versions WHERE id = $1`, versionID)
	if err != nil {
		return fmt.Errorf("failed to delete terraform version: %w", err)
	}

	return nil
}

// ---- Platforms -------------------------------------------------------------

// UpsertPlatform inserts or updates a platform row.
func (r *TerraformMirrorRepository) UpsertPlatform(ctx context.Context, p *models.TerraformVersionPlatform) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	query := `
		INSERT INTO terraform_version_platforms (
			id, version_id, os, arch, upstream_url, filename, sha256,
			storage_key, storage_backend, sha256_verified, gpg_verified,
			sync_status, sync_error, synced_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (version_id, os, arch) DO UPDATE
		SET upstream_url     = EXCLUDED.upstream_url,
		    filename         = EXCLUDED.filename,
		    sha256           = EXCLUDED.sha256,
		    updated_at       = EXCLUDED.updated_at
		RETURNING id
	`

	return r.db.QueryRowContext(ctx, query,
		p.ID,
		p.VersionID,
		p.OS,
		p.Arch,
		p.UpstreamURL,
		p.Filename,
		p.SHA256,
		p.StorageKey,
		p.StorageBackend,
		p.SHA256Verified,
		p.GPGVerified,
		p.SyncStatus,
		p.SyncError,
		p.SyncedAt,
		p.CreatedAt,
		p.UpdatedAt,
	).Scan(&p.ID)
}

// GetPlatform retrieves a single platform by version_id + os + arch.
func (r *TerraformMirrorRepository) GetPlatform(ctx context.Context, versionID uuid.UUID, os, arch string) (*models.TerraformVersionPlatform, error) {
	query := `
		SELECT id, version_id, os, arch, upstream_url, filename, sha256,
		       storage_key, storage_backend, sha256_verified, gpg_verified,
		       sync_status, sync_error, synced_at, created_at, updated_at
		FROM terraform_version_platforms
		WHERE version_id = $1 AND os = $2 AND arch = $3
	`

	var p models.TerraformVersionPlatform
	err := r.db.GetContext(ctx, &p, query, versionID, os, arch)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform platform: %w", err)
	}

	return &p, nil
}

// ListPlatformsForVersion retrieves all platform rows for a given version.
func (r *TerraformMirrorRepository) ListPlatformsForVersion(ctx context.Context, versionID uuid.UUID) ([]models.TerraformVersionPlatform, error) {
	query := `
		SELECT id, version_id, os, arch, upstream_url, filename, sha256,
		       storage_key, storage_backend, sha256_verified, gpg_verified,
		       sync_status, sync_error, synced_at, created_at, updated_at
		FROM terraform_version_platforms
		WHERE version_id = $1
		ORDER BY os, arch
	`

	var platforms []models.TerraformVersionPlatform
	err := r.db.SelectContext(ctx, &platforms, query, versionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list terraform platforms: %w", err)
	}

	return platforms, nil
}

// ListPendingPlatforms returns all platform rows for a config that have not yet been synced.
func (r *TerraformMirrorRepository) ListPendingPlatforms(ctx context.Context, configID uuid.UUID) ([]models.TerraformVersionPlatform, error) {
	query := `
		SELECT p.id, p.version_id, p.os, p.arch, p.upstream_url, p.filename, p.sha256,
		       p.storage_key, p.storage_backend, p.sha256_verified, p.gpg_verified,
		       p.sync_status, p.sync_error, p.synced_at, p.created_at, p.updated_at
		FROM terraform_version_platforms p
		JOIN terraform_versions v ON v.id = p.version_id
		WHERE v.config_id = $1
		  AND p.sync_status IN ('pending', 'failed')
		ORDER BY p.created_at
	`

	var platforms []models.TerraformVersionPlatform
	err := r.db.SelectContext(ctx, &platforms, query, configID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending terraform platforms: %w", err)
	}

	return platforms, nil
}

// UpdatePlatformSyncStatus marks a platform as synced (or failed) and records storage info.
func (r *TerraformMirrorRepository) UpdatePlatformSyncStatus(
	ctx context.Context,
	id uuid.UUID,
	status string,
	storageKey, storageBackend *string,
	sha256Verified, gpgVerified bool,
	syncErr *string,
) error {
	now := time.Now()
	var syncedAt *time.Time
	if status == "synced" {
		syncedAt = &now
	}

	query := `
		UPDATE terraform_version_platforms
		SET sync_status     = $2,
		    storage_key     = COALESCE($3, storage_key),
		    storage_backend = COALESCE($4, storage_backend),
		    sha256_verified  = $5,
		    gpg_verified    = $6,
		    sync_error      = $7,
		    synced_at       = $8,
		    updated_at      = $9
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		id, status, storageKey, storageBackend,
		sha256Verified, gpgVerified, syncErr, syncedAt, now,
	)
	if err != nil {
		return fmt.Errorf("failed to update terraform platform sync status: %w", err)
	}

	return nil
}

// CountVersionStats returns total, synced, and pending platform counts for a config.
func (r *TerraformMirrorRepository) CountVersionStats(ctx context.Context, configID uuid.UUID) (total, synced, pending int, err error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE p.sync_status = 'synced') AS synced,
			COUNT(*) FILTER (WHERE p.sync_status IN ('pending','failed')) AS pending
		FROM terraform_version_platforms p
		JOIN terraform_versions v ON v.id = p.version_id
		WHERE v.config_id = $1
	`, configID)

	if scanErr := row.Scan(&total, &synced, &pending); scanErr != nil {
		return 0, 0, 0, fmt.Errorf("failed to count terraform platform stats: %w", scanErr)
	}

	return total, synced, pending, nil
}

// ---- Sync History ----------------------------------------------------------

// CreateSyncHistory inserts a new sync history record.
func (r *TerraformMirrorRepository) CreateSyncHistory(ctx context.Context, h *models.TerraformSyncHistory) error {
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}

	query := `
		INSERT INTO terraform_sync_history (
			id, config_id, triggered_by, started_at, status,
			versions_synced, platforms_synced, versions_failed
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(ctx, query,
		h.ID,
		h.ConfigID,
		h.TriggeredBy,
		h.StartedAt,
		h.Status,
		h.VersionsSynced,
		h.PlatformsSynced,
		h.VersionsFailed,
	)
	if err != nil {
		return fmt.Errorf("failed to create terraform sync history: %w", err)
	}

	return nil
}

// CompleteSyncHistory marks a sync history row as complete.
func (r *TerraformMirrorRepository) CompleteSyncHistory(
	ctx context.Context,
	id uuid.UUID,
	status string,
	versionsSynced, platformsSynced, versionsFailed int,
	errMsg *string,
	details *string,
) error {
	now := time.Now()

	query := `
		UPDATE terraform_sync_history
		SET status           = $2,
		    completed_at     = $3,
		    versions_synced  = $4,
		    platforms_synced = $5,
		    versions_failed  = $6,
		    error_message    = $7,
		    sync_details     = $8
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		id, status, now,
		versionsSynced, platformsSynced, versionsFailed,
		errMsg, details,
	)
	if err != nil {
		return fmt.Errorf("failed to complete terraform sync history: %w", err)
	}

	return nil
}

// ListSyncHistory returns the most recent sync history rows for a config.
func (r *TerraformMirrorRepository) ListSyncHistory(ctx context.Context, configID uuid.UUID, limit int) ([]models.TerraformSyncHistory, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, config_id, triggered_by, started_at, completed_at, status,
		       versions_synced, platforms_synced, versions_failed, error_message, sync_details
		FROM terraform_sync_history
		WHERE config_id = $1
		ORDER BY started_at DESC
		LIMIT $2
	`

	var history []models.TerraformSyncHistory
	err := r.db.SelectContext(ctx, &history, query, configID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list terraform sync history: %w", err)
	}

	return history, nil
}

// ---- Platform filter helpers -----------------------------------------------

// ParsePlatformFilter decodes the JSONB platform_filter column into a []string.
func ParsePlatformFilter(raw *string) ([]string, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}

	var platforms []string
	if err := json.Unmarshal([]byte(*raw), &platforms); err != nil {
		return nil, fmt.Errorf("invalid platform_filter JSON: %w", err)
	}

	return platforms, nil
}

// EncodePlatformFilter encodes []string into the JSONB column value (or nil for "all").
func EncodePlatformFilter(platforms []string) (*string, error) {
	if len(platforms) == 0 {
		return nil, nil
	}

	b, err := json.Marshal(platforms)
	if err != nil {
		return nil, fmt.Errorf("failed to encode platform_filter: %w", err)
	}

	s := string(b)
	return &s, nil
}

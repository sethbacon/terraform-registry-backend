// storage_migration_repository.go implements StorageMigrationRepository, providing
// database queries for creating, tracking, and updating storage migration jobs and
// their individual artifact items.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// StorageMigrationRepository handles database operations for storage migrations
type StorageMigrationRepository struct {
	db *sqlx.DB
}

// NewStorageMigrationRepository creates a new storage migration repository
// coverage:skip:requires-database
func NewStorageMigrationRepository(db *sqlx.DB) *StorageMigrationRepository {
	return &StorageMigrationRepository{db: db}
}

// CreateMigration inserts a new storage migration record
// coverage:skip:requires-database
func (r *StorageMigrationRepository) CreateMigration(ctx context.Context, m *models.StorageMigration) error {
	query := `
		INSERT INTO storage_migrations (
			id, source_config_id, target_config_id, status,
			total_artifacts, migrated_artifacts, failed_artifacts, skipped_artifacts,
			error_message, started_at, completed_at, created_at, created_by
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12, $13
		)`
	_, err := r.db.ExecContext(ctx, query,
		m.ID, m.SourceConfigID, m.TargetConfigID, m.Status,
		m.TotalArtifacts, m.MigratedArtifacts, m.FailedArtifacts, m.SkippedArtifacts,
		m.ErrorMessage, m.StartedAt, m.CompletedAt, m.CreatedAt, m.CreatedBy,
	)
	return err
}

// GetMigration retrieves a storage migration by ID
// coverage:skip:requires-database
func (r *StorageMigrationRepository) GetMigration(ctx context.Context, id string) (*models.StorageMigration, error) {
	var m models.StorageMigration
	query := `SELECT * FROM storage_migrations WHERE id = $1`
	err := r.db.GetContext(ctx, &m, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListMigrations returns a paginated list of migrations and the total count
// coverage:skip:requires-database
func (r *StorageMigrationRepository) ListMigrations(ctx context.Context, limit, offset int) ([]*models.StorageMigration, int, error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM storage_migrations`); err != nil {
		return nil, 0, err
	}

	var migrations []*models.StorageMigration
	query := `SELECT * FROM storage_migrations ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	if err := r.db.SelectContext(ctx, &migrations, query, limit, offset); err != nil {
		return nil, 0, err
	}
	return migrations, total, nil
}

// UpdateMigrationStatus sets the status and optional error message on a migration
// coverage:skip:requires-database
func (r *StorageMigrationRepository) UpdateMigrationStatus(ctx context.Context, id, status string, errorMsg *string) error {
	query := `UPDATE storage_migrations SET status = $2, error_message = $3 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, status, errorMsg)
	return err
}

// UpdateMigrationProgress updates the artifact counters on a migration
// coverage:skip:requires-database
func (r *StorageMigrationRepository) UpdateMigrationProgress(ctx context.Context, id string, migrated, failed, skipped int) error {
	query := `UPDATE storage_migrations SET migrated_artifacts = $2, failed_artifacts = $3, skipped_artifacts = $4 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, migrated, failed, skipped)
	return err
}

// SetMigrationStarted marks a migration as running with the current timestamp
// coverage:skip:requires-database
func (r *StorageMigrationRepository) SetMigrationStarted(ctx context.Context, id string) error {
	query := `UPDATE storage_migrations SET status = 'running', started_at = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, time.Now())
	return err
}

// SetMigrationCompleted marks a migration as completed with the current timestamp
// coverage:skip:requires-database
func (r *StorageMigrationRepository) SetMigrationCompleted(ctx context.Context, id string) error {
	query := `UPDATE storage_migrations SET status = 'completed', completed_at = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, time.Now())
	return err
}

// CreateMigrationItems batch-inserts migration items
// coverage:skip:requires-database
func (r *StorageMigrationRepository) CreateMigrationItems(ctx context.Context, items []*models.StorageMigrationItem) error {
	if len(items) == 0 {
		return nil
	}

	// Build a multi-row INSERT for efficiency
	const cols = 6 // id, migration_id, artifact_type, artifact_id, source_path, status
	valueStrings := make([]string, 0, len(items))
	valueArgs := make([]interface{}, 0, len(items)*cols)
	for i, item := range items {
		base := i * cols
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
		))
		valueArgs = append(valueArgs,
			item.ID, item.MigrationID, item.ArtifactType,
			item.ArtifactID, item.SourcePath, item.Status,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO storage_migration_items (id, migration_id, artifact_type, artifact_id, source_path, status)
		VALUES %s`, strings.Join(valueStrings, ", "))

	_, err := r.db.ExecContext(ctx, query, valueArgs...)
	return err
}

// GetPendingItems retrieves up to limit pending items for a migration
// coverage:skip:requires-database
func (r *StorageMigrationRepository) GetPendingItems(ctx context.Context, migrationID string, limit int) ([]*models.StorageMigrationItem, error) {
	var items []*models.StorageMigrationItem
	query := `
		SELECT * FROM storage_migration_items
		WHERE migration_id = $1 AND status = 'pending'
		ORDER BY id
		LIMIT $2`
	if err := r.db.SelectContext(ctx, &items, query, migrationID, limit); err != nil {
		return nil, err
	}
	return items, nil
}

// UpdateItemStatus sets the status and optional error message on a single item
// coverage:skip:requires-database
func (r *StorageMigrationRepository) UpdateItemStatus(ctx context.Context, id, status string, errorMsg *string) error {
	query := `UPDATE storage_migration_items SET status = $2, error_message = $3, migrated_at = $4 WHERE id = $1`
	var migratedAt *time.Time
	if status == "migrated" {
		now := time.Now()
		migratedAt = &now
	}
	_, err := r.db.ExecContext(ctx, query, id, status, errorMsg, migratedAt)
	return err
}

// GetModuleArtifacts returns module version artifacts stored in the given backend
// coverage:skip:requires-database
func (r *StorageMigrationRepository) GetModuleArtifacts(ctx context.Context, storageBackend string) ([]models.ArtifactInfo, error) {
	var artifacts []models.ArtifactInfo
	query := `SELECT id, storage_path FROM module_versions WHERE storage_backend = $1`
	if err := r.db.SelectContext(ctx, &artifacts, query, storageBackend); err != nil {
		return nil, err
	}
	return artifacts, nil
}

// GetProviderArtifacts returns provider platform artifacts stored in the given backend
// coverage:skip:requires-database
func (r *StorageMigrationRepository) GetProviderArtifacts(ctx context.Context, storageBackend string) ([]models.ArtifactInfo, error) {
	var artifacts []models.ArtifactInfo
	query := `SELECT id, storage_path FROM provider_platforms WHERE storage_backend = $1`
	if err := r.db.SelectContext(ctx, &artifacts, query, storageBackend); err != nil {
		return nil, err
	}
	return artifacts, nil
}

// UpdateModuleVersionBackend changes the storage_backend column for a module version
// coverage:skip:requires-database
func (r *StorageMigrationRepository) UpdateModuleVersionBackend(ctx context.Context, id, backend string) error {
	query := `UPDATE module_versions SET storage_backend = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, backend)
	return err
}

// UpdateProviderPlatformBackend changes the storage_backend column for a provider platform
// coverage:skip:requires-database
func (r *StorageMigrationRepository) UpdateProviderPlatformBackend(ctx context.Context, id, backend string) error {
	query := `UPDATE provider_platforms SET storage_backend = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, backend)
	return err
}

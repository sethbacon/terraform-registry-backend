// storage_config_repository.go implements StorageConfigRepository, providing database queries
// for reading and updating the active storage backend configuration.
package repositories

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// StorageConfigRepository handles database operations for storage configuration
type StorageConfigRepository struct {
	db *sqlx.DB
}

// NewStorageConfigRepository creates a new storage configuration repository
func NewStorageConfigRepository(db *sqlx.DB) *StorageConfigRepository {
	return &StorageConfigRepository{db: db}
}

// System Settings Operations

// GetSystemSettings retrieves the singleton system settings record
func (r *StorageConfigRepository) GetSystemSettings(ctx context.Context) (*models.SystemSettings, error) {
	var settings models.SystemSettings
	query := `SELECT * FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &settings, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &settings, err
}

// IsStorageConfigured checks if storage has been configured
func (r *StorageConfigRepository) IsStorageConfigured(ctx context.Context) (bool, error) {
	var configured bool
	query := `SELECT storage_configured FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configured, query)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return configured, err
}

// SetStorageConfigured marks storage as configured
func (r *StorageConfigRepository) SetStorageConfigured(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE system_settings SET
			storage_configured = true,
			storage_configured_at = $1,
			storage_configured_by = $2,
			updated_at = $1
		WHERE id = 1`

	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	return err
}

// Storage Configuration Operations

// CreateStorageConfig creates a new storage configuration
func (r *StorageConfigRepository) CreateStorageConfig(ctx context.Context, config *models.StorageConfig) error {
	query := `
		INSERT INTO storage_config (
			id, backend_type, is_active,
			local_base_path, local_serve_directly,
			azure_account_name, azure_account_key_encrypted, azure_container_name, azure_cdn_url,
			s3_endpoint, s3_region, s3_bucket, s3_auth_method,
			s3_access_key_id_encrypted, s3_secret_access_key_encrypted,
			s3_role_arn, s3_role_session_name, s3_external_id, s3_web_identity_token_file,
			gcs_bucket, gcs_project_id, gcs_auth_method, gcs_credentials_file,
			gcs_credentials_json_encrypted, gcs_endpoint,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			$14, $15,
			$16, $17, $18, $19,
			$20, $21, $22, $23,
			$24, $25,
			$26, $27, $28, $29
		)`

	_, err := r.db.ExecContext(ctx, query,
		config.ID, config.BackendType, config.IsActive,
		config.LocalBasePath, config.LocalServeDirectly,
		config.AzureAccountName, config.AzureAccountKeyEncrypted, config.AzureContainerName, config.AzureCDNURL,
		config.S3Endpoint, config.S3Region, config.S3Bucket, config.S3AuthMethod,
		config.S3AccessKeyIDEncrypted, config.S3SecretAccessKeyEncrypted,
		config.S3RoleARN, config.S3RoleSessionName, config.S3ExternalID, config.S3WebIdentityTokenFile,
		config.GCSBucket, config.GCSProjectID, config.GCSAuthMethod, config.GCSCredentialsFile,
		config.GCSCredentialsJSONEncrypted, config.GCSEndpoint,
		config.CreatedAt, config.UpdatedAt, config.CreatedBy, config.UpdatedBy,
	)
	return err
}

// GetStorageConfig retrieves a storage configuration by ID
func (r *StorageConfigRepository) GetStorageConfig(ctx context.Context, id uuid.UUID) (*models.StorageConfig, error) {
	var config models.StorageConfig
	query := `SELECT * FROM storage_config WHERE id = $1`
	err := r.db.GetContext(ctx, &config, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &config, err
}

// GetActiveStorageConfig retrieves the currently active storage configuration
func (r *StorageConfigRepository) GetActiveStorageConfig(ctx context.Context) (*models.StorageConfig, error) {
	var config models.StorageConfig
	query := `SELECT * FROM storage_config WHERE is_active = true LIMIT 1`
	err := r.db.GetContext(ctx, &config, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &config, err
}

// ListStorageConfigs lists all storage configurations
func (r *StorageConfigRepository) ListStorageConfigs(ctx context.Context) ([]*models.StorageConfig, error) {
	var configs []*models.StorageConfig
	query := `SELECT * FROM storage_config ORDER BY created_at DESC`
	err := r.db.SelectContext(ctx, &configs, query)
	return configs, err
}

// UpdateStorageConfig updates a storage configuration
func (r *StorageConfigRepository) UpdateStorageConfig(ctx context.Context, config *models.StorageConfig) error {
	query := `
		UPDATE storage_config SET
			backend_type = $2, is_active = $3,
			local_base_path = $4, local_serve_directly = $5,
			azure_account_name = $6, azure_account_key_encrypted = $7,
			azure_container_name = $8, azure_cdn_url = $9,
			s3_endpoint = $10, s3_region = $11, s3_bucket = $12, s3_auth_method = $13,
			s3_access_key_id_encrypted = $14, s3_secret_access_key_encrypted = $15,
			s3_role_arn = $16, s3_role_session_name = $17, s3_external_id = $18,
			s3_web_identity_token_file = $19,
			gcs_bucket = $20, gcs_project_id = $21, gcs_auth_method = $22,
			gcs_credentials_file = $23, gcs_credentials_json_encrypted = $24, gcs_endpoint = $25,
			updated_at = $26, updated_by = $27
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		config.ID,
		config.BackendType, config.IsActive,
		config.LocalBasePath, config.LocalServeDirectly,
		config.AzureAccountName, config.AzureAccountKeyEncrypted,
		config.AzureContainerName, config.AzureCDNURL,
		config.S3Endpoint, config.S3Region, config.S3Bucket, config.S3AuthMethod,
		config.S3AccessKeyIDEncrypted, config.S3SecretAccessKeyEncrypted,
		config.S3RoleARN, config.S3RoleSessionName, config.S3ExternalID,
		config.S3WebIdentityTokenFile,
		config.GCSBucket, config.GCSProjectID, config.GCSAuthMethod,
		config.GCSCredentialsFile, config.GCSCredentialsJSONEncrypted, config.GCSEndpoint,
		time.Now(), config.UpdatedBy,
	)
	return err
}

// DeleteStorageConfig deletes a storage configuration
func (r *StorageConfigRepository) DeleteStorageConfig(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM storage_config WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// DeactivateAllStorageConfigs sets is_active=false for all configurations
func (r *StorageConfigRepository) DeactivateAllStorageConfigs(ctx context.Context) error {
	query := `UPDATE storage_config SET is_active = false, updated_at = $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// ActivateStorageConfig activates a specific configuration (deactivates others first)
func (r *StorageConfigRepository) ActivateStorageConfig(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Deactivate all configs
	_, err = tx.ExecContext(ctx, `UPDATE storage_config SET is_active = false, updated_at = $1`, time.Now())
	if err != nil {
		return err
	}

	// Activate the specified config
	_, err = tx.ExecContext(ctx,
		`UPDATE storage_config SET is_active = true, updated_at = $1, updated_by = $2 WHERE id = $3`,
		time.Now(), userID, id,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// oidc_config_repository.go implements OIDCConfigRepository, providing database queries
// for reading, creating, and managing OIDC provider configurations stored in the database.
// Follows the same pattern as StorageConfigRepository for consistency.
package repositories

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// OIDCConfigRepository handles database operations for OIDC configuration
type OIDCConfigRepository struct {
	db *sqlx.DB
}

// NewOIDCConfigRepository creates a new OIDC configuration repository
func NewOIDCConfigRepository(db *sqlx.DB) *OIDCConfigRepository {
	return &OIDCConfigRepository{db: db}
}

// === System Settings Extensions for Setup Wizard ===

// IsSetupCompleted checks if the initial setup has been completed
func (r *OIDCConfigRepository) IsSetupCompleted(ctx context.Context) (bool, error) {
	var completed bool
	query := `SELECT setup_completed FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &completed, query)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return completed, err
}

// SetSetupCompleted marks initial setup as completed and clears the setup token
func (r *OIDCConfigRepository) SetSetupCompleted(ctx context.Context) error {
	query := `
		UPDATE system_settings SET
			setup_completed = true,
			setup_token_hash = NULL,
			updated_at = $1
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// GetSetupTokenHash retrieves the bcrypt hash of the setup token
func (r *OIDCConfigRepository) GetSetupTokenHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	query := `SELECT setup_token_hash FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &hash, query)
	if err != nil {
		return "", err
	}
	if !hash.Valid {
		return "", nil
	}
	return hash.String, nil
}

// SetSetupTokenHash stores the bcrypt hash of the setup token
func (r *OIDCConfigRepository) SetSetupTokenHash(ctx context.Context, hash string) error {
	query := `
		UPDATE system_settings SET
			setup_token_hash = $1,
			updated_at = $2
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, hash, time.Now())
	return err
}

// IsOIDCConfigured checks if OIDC has been configured
func (r *OIDCConfigRepository) IsOIDCConfigured(ctx context.Context) (bool, error) {
	var configured bool
	query := `SELECT oidc_configured FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configured, query)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return configured, err
}

// SetOIDCConfigured marks OIDC as configured
func (r *OIDCConfigRepository) SetOIDCConfigured(ctx context.Context) error {
	query := `
		UPDATE system_settings SET
			oidc_configured = true,
			updated_at = $1
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// SetPendingAdminEmail stores the email of the initial admin user
func (r *OIDCConfigRepository) SetPendingAdminEmail(ctx context.Context, email string) error {
	query := `
		UPDATE system_settings SET
			pending_admin_email = $1,
			updated_at = $2
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, email, time.Now())
	return err
}

// GetPendingAdminEmail retrieves the pending admin email
func (r *OIDCConfigRepository) GetPendingAdminEmail(ctx context.Context) (string, error) {
	var email sql.NullString
	query := `SELECT pending_admin_email FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &email, query)
	if err != nil {
		return "", err
	}
	if !email.Valid {
		return "", nil
	}
	return email.String, nil
}

// ClearPendingAdminEmail clears the pending admin email after the admin logs in
func (r *OIDCConfigRepository) ClearPendingAdminEmail(ctx context.Context) error {
	query := `
		UPDATE system_settings SET
			pending_admin_email = NULL,
			updated_at = $1
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// GetEnhancedSetupStatus returns the full setup status for the wizard
func (r *OIDCConfigRepository) GetEnhancedSetupStatus(ctx context.Context) (*models.SetupStatus, error) {
	var settings models.SystemSettings
	query := `SELECT * FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &settings, query)
	if err == sql.ErrNoRows {
		// Fresh database with no settings row yet
		return &models.SetupStatus{
			SetupCompleted:    false,
			StorageConfigured: false,
			OIDCConfigured:    false,
			AdminConfigured:   false,
			SetupRequired:     true,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	status := &models.SetupStatus{
		SetupCompleted:    settings.SetupCompleted,
		StorageConfigured: settings.StorageConfigured,
		OIDCConfigured:    settings.OIDCConfigured,
		AdminConfigured:   settings.PendingAdminEmail.Valid && settings.PendingAdminEmail.String != "",
		SetupRequired:     !settings.SetupCompleted,
		AdminEmail:        settings.PendingAdminEmail,
	}

	if settings.StorageConfiguredAt.Valid {
		t := settings.StorageConfiguredAt.Time
		status.StorageConfiguredAt = &t
	}

	return status, nil
}

// === OIDC Configuration CRUD ===

// CreateOIDCConfig creates a new OIDC configuration
func (r *OIDCConfigRepository) CreateOIDCConfig(ctx context.Context, config *models.OIDCConfig) error {
	query := `
		INSERT INTO oidc_config (
			id, name, provider_type, issuer_url, client_id, client_secret_encrypted,
			redirect_url, scopes, is_active, extra_config,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14
		)`

	_, err := r.db.ExecContext(ctx, query,
		config.ID, config.Name, config.ProviderType, config.IssuerURL, config.ClientID,
		config.ClientSecretEncrypted,
		config.RedirectURL, config.Scopes, config.IsActive, config.ExtraConfig,
		config.CreatedAt, config.UpdatedAt, config.CreatedBy, config.UpdatedBy,
	)
	return err
}

// GetActiveOIDCConfig retrieves the currently active OIDC configuration
func (r *OIDCConfigRepository) GetActiveOIDCConfig(ctx context.Context) (*models.OIDCConfig, error) {
	var config models.OIDCConfig
	query := `SELECT * FROM oidc_config WHERE is_active = true LIMIT 1`
	err := r.db.GetContext(ctx, &config, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &config, err
}

// GetOIDCConfig retrieves an OIDC configuration by ID
func (r *OIDCConfigRepository) GetOIDCConfig(ctx context.Context, id uuid.UUID) (*models.OIDCConfig, error) {
	var config models.OIDCConfig
	query := `SELECT * FROM oidc_config WHERE id = $1`
	err := r.db.GetContext(ctx, &config, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &config, err
}

// ListOIDCConfigs lists all OIDC configurations
func (r *OIDCConfigRepository) ListOIDCConfigs(ctx context.Context) ([]*models.OIDCConfig, error) {
	var configs []*models.OIDCConfig
	query := `SELECT * FROM oidc_config ORDER BY created_at DESC`
	err := r.db.SelectContext(ctx, &configs, query)
	return configs, err
}

// DeleteOIDCConfig deletes an OIDC configuration
func (r *OIDCConfigRepository) DeleteOIDCConfig(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM oidc_config WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// DeactivateAllOIDCConfigs sets is_active=false for all configurations
func (r *OIDCConfigRepository) DeactivateAllOIDCConfigs(ctx context.Context) error {
	query := `UPDATE oidc_config SET is_active = false, updated_at = $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// ActivateOIDCConfig activates a specific configuration (deactivates others first)
func (r *OIDCConfigRepository) ActivateOIDCConfig(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // nolint:errcheck

	// Deactivate all configs
	_, err = tx.ExecContext(ctx, `UPDATE oidc_config SET is_active = false, updated_at = $1`, time.Now())
	if err != nil {
		return err
	}

	// Activate the specified config
	_, err = tx.ExecContext(ctx,
		`UPDATE oidc_config SET is_active = true, updated_at = $1 WHERE id = $2`,
		time.Now(), id,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

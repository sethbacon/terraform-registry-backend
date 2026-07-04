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

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// OIDCConfigRepository handles OIDC configuration plus the registry's setup-wizard
// state. Setup-wizard methods run on the registry's domain connection
// (system_settings); OIDC-config CRUD is delegated to the shared identity store
// so it follows the identity schema.
type OIDCConfigRepository struct {
	db   *sqlx.DB
	oidc *identitystore.OIDCConfigRepository
}

// NewOIDCConfigRepository creates a new OIDC configuration repository whose
// OIDC-config CRUD uses the same connection as the setup-wizard methods. Use
// NewOIDCConfigRepositoryWithIdentity to route OIDC-config CRUD at the dedicated
// identity pool (identity-schema cutover).
func NewOIDCConfigRepository(db *sqlx.DB) *OIDCConfigRepository {
	return NewOIDCConfigRepositoryWithIdentity(db, db)
}

// NewOIDCConfigRepositoryWithIdentity creates a new OIDC configuration
// repository. db is the registry's domain connection (system_settings);
// identityDB backs OIDC-config CRUD (the shared identity store).
func NewOIDCConfigRepositoryWithIdentity(db, identityDB *sqlx.DB) *OIDCConfigRepository {
	return &OIDCConfigRepository{
		db:   db,
		oidc: identitystore.NewOIDCConfigRepository(identityDB),
	}
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
			SetupCompleted:      false,
			StorageConfigured:   false,
			OIDCConfigured:      false,
			LDAPConfigured:      false,
			AdminConfigured:     false,
			ScanningConfigured:  false,
			AuthMethod:          "oidc",
			SetupRequired:       true,
			PendingFeatureSetup: false,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	adminConfigured := settings.PendingAdminEmail.Valid && settings.PendingAdminEmail.String != ""

	// Auth is configured if either OIDC or LDAP is configured
	authConfigured := settings.OIDCConfigured || settings.LDAPConfigured

	// Detect features that were added after initial setup completed but haven't
	// been configured yet (e.g. scanning added in a newer release).
	pendingFeatureSetup := settings.SetupCompleted && !settings.ScanningConfigured

	status := &models.SetupStatus{
		SetupCompleted:      settings.SetupCompleted,
		StorageConfigured:   settings.StorageConfigured,
		OIDCConfigured:      settings.OIDCConfigured,
		LDAPConfigured:      settings.LDAPConfigured,
		AdminConfigured:     adminConfigured,
		ScanningConfigured:  settings.ScanningConfigured,
		AuthMethod:          settings.AuthMethod,
		SetupRequired:       !settings.SetupCompleted || pendingFeatureSetup,
		PendingFeatureSetup: pendingFeatureSetup,
		AdminEmail:          settings.PendingAdminEmail,
	}
	// Suppress the unused variable warning — authConfigured is used by the
	// setup_required calculation below in the full-setup path.
	_ = authConfigured

	if settings.StorageConfiguredAt.Valid {
		t := settings.StorageConfiguredAt.Time
		status.StorageConfiguredAt = &t
	}

	return status, nil
}

// HasPendingFeatureSetup returns true when initial setup is completed but one
// or more features added in later releases have not been configured yet.
//
// To add a new feature check (e.g. for E4.3 policy engine or E4.4 module testing),
// extend the boolean expression:
//
//	setup_completed AND (NOT scanning_configured OR NOT policy_configured OR NOT testing_configured)
func (r *OIDCConfigRepository) HasPendingFeatureSetup(ctx context.Context) (bool, error) {
	var pending bool
	query := `SELECT setup_completed AND (NOT scanning_configured) FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &pending, query)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return pending, err
}

// GetScanningConfigured checks if scanning has been configured via the setup wizard
func (r *OIDCConfigRepository) GetScanningConfigured(ctx context.Context) (bool, error) {
	var configured bool
	query := `SELECT scanning_configured FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configured, query)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return configured, err
}

// SetScanningConfig stores the scanning configuration JSON and marks scanning as configured
func (r *OIDCConfigRepository) SetScanningConfig(ctx context.Context, configJSON []byte) error {
	query := `
		UPDATE system_settings SET
			scanning_configured = true,
			scanning_configured_at = NOW(),
			scanning_config = $1,
			updated_at = $2
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, configJSON, time.Now())
	return err
}

// GetScanningConfig retrieves the scanning configuration JSON from system settings
func (r *OIDCConfigRepository) GetScanningConfig(ctx context.Context) ([]byte, error) {
	var configJSON []byte
	query := `SELECT scanning_config FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configJSON, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return configJSON, nil
}

// SetNotificationsConfig stores the notifications configuration JSON (SMTP password
// MUST be encrypted by the caller before it reaches here) and marks notifications configured.
func (r *OIDCConfigRepository) SetNotificationsConfig(ctx context.Context, configJSON []byte) error {
	query := `
		UPDATE system_settings SET
			notifications_configured = true,
			notifications_configured_at = NOW(),
			notifications_config = $1,
			updated_at = $2
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, configJSON, time.Now())
	return err
}

// GetNotificationsConfig retrieves the notifications configuration JSON (may be nil).
func (r *OIDCConfigRepository) GetNotificationsConfig(ctx context.Context) ([]byte, error) {
	var configJSON []byte
	query := `SELECT notifications_config FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configJSON, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return configJSON, nil
}

// SetLDAPConfig stores the LDAP configuration JSON and marks LDAP as configured.
// It also sets auth_method to 'ldap'.
func (r *OIDCConfigRepository) SetLDAPConfig(ctx context.Context, configJSON []byte) error {
	query := `
		UPDATE system_settings SET
			ldap_configured = true,
			ldap_configured_at = NOW(),
			ldap_config = $1,
			auth_method = 'ldap',
			updated_at = $2
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, configJSON, time.Now())
	return err
}

// GetLDAPConfig retrieves the LDAP configuration JSON from system settings.
func (r *OIDCConfigRepository) GetLDAPConfig(ctx context.Context) ([]byte, error) {
	var configJSON []byte
	query := `SELECT ldap_config FROM system_settings WHERE id = 1`
	err := r.db.GetContext(ctx, &configJSON, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return configJSON, nil
}

// SetAuthMethod updates the auth_method column.
func (r *OIDCConfigRepository) SetAuthMethod(ctx context.Context, method string) error {
	query := `UPDATE system_settings SET auth_method = $1, updated_at = $2 WHERE id = 1`
	_, err := r.db.ExecContext(ctx, query, method, time.Now())
	return err
}

// === OIDC Configuration CRUD (delegated to the shared identity store) ===

// CreateOIDCConfig creates a new OIDC configuration.
func (r *OIDCConfigRepository) CreateOIDCConfig(ctx context.Context, config *models.OIDCConfig) error {
	return r.oidc.CreateOIDCConfig(ctx, config)
}

// GetActiveOIDCConfig retrieves the currently active OIDC configuration.
func (r *OIDCConfigRepository) GetActiveOIDCConfig(ctx context.Context) (*models.OIDCConfig, error) {
	return r.oidc.GetActiveOIDCConfig(ctx)
}

// GetOIDCConfig retrieves an OIDC configuration by ID.
func (r *OIDCConfigRepository) GetOIDCConfig(ctx context.Context, id uuid.UUID) (*models.OIDCConfig, error) {
	return r.oidc.GetOIDCConfig(ctx, id)
}

// ListOIDCConfigs lists all OIDC configurations.
func (r *OIDCConfigRepository) ListOIDCConfigs(ctx context.Context) ([]*models.OIDCConfig, error) {
	return r.oidc.ListOIDCConfigs(ctx)
}

// DeleteOIDCConfig deletes an OIDC configuration.
func (r *OIDCConfigRepository) DeleteOIDCConfig(ctx context.Context, id uuid.UUID) error {
	return r.oidc.DeleteOIDCConfig(ctx, id)
}

// UpdateOIDCConfigExtraConfig updates only the extra_config column (used for group mapping settings).
func (r *OIDCConfigRepository) UpdateOIDCConfigExtraConfig(ctx context.Context, id uuid.UUID, extraConfig []byte) error {
	return r.oidc.UpdateOIDCConfigExtraConfig(ctx, id, extraConfig)
}

// DeactivateAllOIDCConfigs sets is_active=false for all configurations.
func (r *OIDCConfigRepository) DeactivateAllOIDCConfigs(ctx context.Context) error {
	return r.oidc.DeactivateAllOIDCConfigs(ctx)
}

// ActivateOIDCConfig activates a specific configuration (deactivates others first).
func (r *OIDCConfigRepository) ActivateOIDCConfig(ctx context.Context, id uuid.UUID) error {
	return r.oidc.ActivateOIDCConfig(ctx, id)
}

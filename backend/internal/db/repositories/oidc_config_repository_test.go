package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var errOIDCDB = errors.New("oidc db error")

func newOIDCConfigRepo(t *testing.T) (*OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

// ---------------------------------------------------------------------------
// IsSetupCompleted
// ---------------------------------------------------------------------------

func TestIsSetupCompleted_True(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))

	completed, err := repo.IsSetupCompleted(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !completed {
		t.Error("expected completed = true")
	}
}

func TestIsSetupCompleted_False(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))

	completed, err := repo.IsSetupCompleted(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if completed {
		t.Error("expected completed = false")
	}
}

func TestIsSetupCompleted_NoRows(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnError(sql.ErrNoRows)

	completed, err := repo.IsSetupCompleted(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if completed {
		t.Error("expected completed = false for no rows")
	}
}

func TestIsSetupCompleted_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnError(errOIDCDB)

	_, err := repo.IsSetupCompleted(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// SetSetupCompleted
// ---------------------------------------------------------------------------

func TestSetSetupCompleted_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.SetSetupCompleted(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetSetupCompleted_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errOIDCDB)

	err := repo.SetSetupCompleted(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetSetupTokenHash
// ---------------------------------------------------------------------------

func TestGetSetupTokenHash_Valid(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow("$2a$12$somehash"))

	hash, err := repo.GetSetupTokenHash(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != "$2a$12$somehash" {
		t.Errorf("hash = %q, want $2a$12$somehash", hash)
	}
}

func TestGetSetupTokenHash_Null(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(nil))

	hash, err := repo.GetSetupTokenHash(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != "" {
		t.Errorf("hash = %q, want empty", hash)
	}
}

func TestGetSetupTokenHash_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnError(errOIDCDB)

	_, err := repo.GetSetupTokenHash(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// SetSetupTokenHash
// ---------------------------------------------------------------------------

func TestSetSetupTokenHash_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.SetSetupTokenHash(context.Background(), "$2a$12$hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IsOIDCConfigured
// ---------------------------------------------------------------------------

func TestIsOIDCConfigured_True(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT oidc_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"oidc_configured"}).AddRow(true))

	configured, err := repo.IsOIDCConfigured(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured {
		t.Error("expected configured = true")
	}
}

func TestIsOIDCConfigured_NoRows(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT oidc_configured FROM system_settings").
		WillReturnError(sql.ErrNoRows)

	configured, err := repo.IsOIDCConfigured(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configured {
		t.Error("expected configured = false for no rows")
	}
}

// ---------------------------------------------------------------------------
// SetOIDCConfigured
// ---------------------------------------------------------------------------

func TestSetOIDCConfigured_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.SetOIDCConfigured(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetPendingAdminEmail / GetPendingAdminEmail / ClearPendingAdminEmail
// ---------------------------------------------------------------------------

func TestSetPendingAdminEmail_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.SetPendingAdminEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPendingAdminEmail_Valid(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT pending_admin_email FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"pending_admin_email"}).AddRow("admin@test.com"))

	email, err := repo.GetPendingAdminEmail(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "admin@test.com" {
		t.Errorf("email = %q, want admin@test.com", email)
	}
}

func TestGetPendingAdminEmail_Null(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT pending_admin_email FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"pending_admin_email"}).AddRow(nil))

	email, err := repo.GetPendingAdminEmail(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "" {
		t.Errorf("email = %q, want empty", email)
	}
}

func TestGetPendingAdminEmail_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT pending_admin_email FROM system_settings").
		WillReturnError(errOIDCDB)

	_, err := repo.GetPendingAdminEmail(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestClearPendingAdminEmail_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.ClearPendingAdminEmail(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetEnhancedSetupStatus
// ---------------------------------------------------------------------------

func TestGetEnhancedSetupStatus_NoRows(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnError(sql.ErrNoRows)

	status, err := repo.GetEnhancedSetupStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.SetupCompleted {
		t.Error("expected SetupCompleted = false")
	}
	if !status.SetupRequired {
		t.Error("expected SetupRequired = true")
	}
}

func TestGetEnhancedSetupStatus_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnError(errOIDCDB)

	_, err := repo.GetEnhancedSetupStatus(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestGetEnhancedSetupStatus_Configured(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)

	settingsCols := []string{
		"id", "storage_configured", "storage_configured_at", "storage_configured_by",
		"setup_completed", "setup_token_hash", "oidc_configured", "pending_admin_email",
		"created_at", "updated_at",
	}
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(sqlmock.NewRows(settingsCols).AddRow(
			1, true, now, nil,
			true, nil, true, "admin@example.com",
			now, now,
		))

	status, err := repo.GetEnhancedSetupStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.SetupCompleted {
		t.Error("expected SetupCompleted = true")
	}
	if !status.StorageConfigured {
		t.Error("expected StorageConfigured = true")
	}
	if !status.OIDCConfigured {
		t.Error("expected OIDCConfigured = true")
	}
	if !status.AdminConfigured {
		t.Error("expected AdminConfigured = true")
	}
	if status.SetupRequired {
		t.Error("expected SetupRequired = false")
	}
	if status.StorageConfiguredAt == nil {
		t.Error("expected StorageConfiguredAt to be set")
	}
}

// ---------------------------------------------------------------------------
// CreateOIDCConfig
// ---------------------------------------------------------------------------

func TestCreateOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	cfg := &models.OIDCConfig{
		ID:           uuid.New(),
		Name:         "test",
		ProviderType: "generic_oidc",
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "client-id",
		RedirectURL:  "https://app.example.com/callback",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := repo.CreateOIDCConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnError(errOIDCDB)

	cfg := &models.OIDCConfig{ID: uuid.New()}
	err := repo.CreateOIDCConfig(context.Background(), cfg)
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetActiveOIDCConfig
// ---------------------------------------------------------------------------

var oidcConfigCols = []string{
	"id", "name", "provider_type", "issuer_url", "client_id",
	"client_secret_encrypted", "redirect_url", "scopes", "is_active",
	"extra_config", "created_at", "updated_at", "created_by", "updated_by",
}

func TestGetActiveOIDCConfig_Found(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "default", "generic_oidc", "https://issuer.example.com", "client-id",
			"encrypted-secret", "https://app/callback", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	cfg, err := repo.GetActiveOIDCConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if cfg.ID != id {
		t.Errorf("ID = %v, want %v", cfg.ID, id)
	}
}

func TestGetActiveOIDCConfig_NotFound(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
		WillReturnError(sql.ErrNoRows)

	cfg, err := repo.GetActiveOIDCConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

func TestGetActiveOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
		WillReturnError(errOIDCDB)

	_, err := repo.GetActiveOIDCConfig(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOIDCConfig
// ---------------------------------------------------------------------------

func TestGetOIDCConfig_Found(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE id").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "test", "generic_oidc", "https://issuer.example.com", "client",
			"enc", "https://app/callback", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	cfg, err := repo.GetOIDCConfig(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config")
	}
}

func TestGetOIDCConfig_NotFound(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE id").
		WillReturnError(sql.ErrNoRows)

	cfg, err := repo.GetOIDCConfig(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

// ---------------------------------------------------------------------------
// ListOIDCConfigs
// ---------------------------------------------------------------------------

func TestListOIDCConfigs_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config ORDER BY").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "default", "generic_oidc", "https://a.com", "c",
			"e", "https://r.com", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	configs, err := repo.ListOIDCConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("len = %d, want 1", len(configs))
	}
}

func TestListOIDCConfigs_Empty(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config ORDER BY").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols))

	configs, err := repo.ListOIDCConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("len = %d, want 0", len(configs))
	}
}

// ---------------------------------------------------------------------------
// DeleteOIDCConfig
// ---------------------------------------------------------------------------

func TestDeleteOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("DELETE FROM oidc_config WHERE id").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.DeleteOIDCConfig(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("DELETE FROM oidc_config WHERE id").
		WillReturnError(errOIDCDB)

	err := repo.DeleteOIDCConfig(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// DeactivateAllOIDCConfigs
// ---------------------------------------------------------------------------

func TestDeactivateAllOIDCConfigs_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 2))

	err := repo.DeactivateAllOIDCConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ActivateOIDCConfig — transactional
// ---------------------------------------------------------------------------

func TestActivateOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE oidc_config SET is_active = true").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := repo.ActivateOIDCConfig(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestActivateOIDCConfig_BeginError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin().WillReturnError(errOIDCDB)

	err := repo.ActivateOIDCConfig(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error from Begin")
	}
}

func TestActivateOIDCConfig_DeactivateError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	err := repo.ActivateOIDCConfig(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error from deactivation")
	}
}

func TestActivateOIDCConfig_ActivateError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE oidc_config SET is_active = true").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	err := repo.ActivateOIDCConfig(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error from activation")
	}
}

// ---------------------------------------------------------------------------
// UpdateOIDCConfigExtraConfig
// ---------------------------------------------------------------------------

func TestUpdateOIDCConfigExtraConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)

	mock.ExpectExec("UPDATE oidc_config SET extra_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	extraConfig := []byte(`{"group_claim":"groups"}`)
	if err := repo.UpdateOIDCConfigExtraConfig(context.Background(), uuid.New(), extraConfig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateOIDCConfigExtraConfig_DBError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)

	mock.ExpectExec("UPDATE oidc_config SET extra_config").
		WillReturnError(errOIDCDB)

	if err := repo.UpdateOIDCConfigExtraConfig(context.Background(), uuid.New(), []byte(`{}`)); err == nil {
		t.Error("expected error, got nil")
	}
}

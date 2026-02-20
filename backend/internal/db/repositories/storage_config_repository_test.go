package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newStorageConfigRepo(t *testing.T) (*StorageConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStorageConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

// minimal columns sufficient for sqlx struct scan
var systemSettingsCols = []string{
	"id", "storage_configured", "storage_configured_at", "storage_configured_by",
	"created_at", "updated_at",
}

var storageConfigMinCols = []string{
	"id", "backend_type", "is_active", "created_at", "updated_at",
}

func sampleSystemSettingsRow() *sqlmock.Rows {
	return sqlmock.NewRows(systemSettingsCols).
		AddRow(1, false, nil, nil, time.Now(), time.Now())
}

func sampleStorageConfigRow() *sqlmock.Rows {
	return sqlmock.NewRows(storageConfigMinCols).
		AddRow(uuid.New(), "local", true, time.Now(), time.Now())
}

// ---------------------------------------------------------------------------
// GetSystemSettings
// ---------------------------------------------------------------------------

func TestGetSystemSettings_Found(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(sampleSystemSettingsRow())

	settings, err := repo.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settings == nil {
		t.Fatal("expected settings, got nil")
	}
}

func TestGetSystemSettings_NotFound(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(sqlmock.NewRows(systemSettingsCols))

	settings, err := repo.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settings != nil {
		t.Errorf("expected nil, got %v", settings)
	}
}

func TestGetSystemSettings_Error(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnError(errDB)

	_, err := repo.GetSystemSettings(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// IsStorageConfigured
// ---------------------------------------------------------------------------

func TestIsStorageConfigured_True(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))

	configured, err := repo.IsStorageConfigured(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured {
		t.Error("expected true, got false")
	}
}

func TestIsStorageConfigured_NotFound(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))

	configured, err := repo.IsStorageConfigured(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configured {
		t.Error("expected false for not found")
	}
}

func TestIsStorageConfigured_Error(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnError(errDB)

	_, err := repo.IsStorageConfigured(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// SetStorageConfigured
// ---------------------------------------------------------------------------

func TestSetStorageConfigured_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.SetStorageConfigured(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetStorageConfigured_Error(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("UPDATE system_settings").
		WillReturnError(errDB)

	if err := repo.SetStorageConfigured(context.Background(), uuid.New()); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// CreateStorageConfig
// ---------------------------------------------------------------------------

func TestCreateStorageConfig_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	cfg := &models.StorageConfig{
		ID:          uuid.New(),
		BackendType: "local",
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := repo.CreateStorageConfig(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateStorageConfig_Error(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnError(errDB)

	cfg := &models.StorageConfig{ID: uuid.New(), BackendType: "s3"}
	if err := repo.CreateStorageConfig(context.Background(), cfg); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetStorageConfig
// ---------------------------------------------------------------------------

func TestGetStorageConfig_Found(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*WHERE id").
		WillReturnRows(sampleStorageConfigRow())

	cfg, err := repo.GetStorageConfig(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
}

func TestGetStorageConfig_NotFound(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*WHERE id").
		WillReturnRows(sqlmock.NewRows(storageConfigMinCols))

	cfg, err := repo.GetStorageConfig(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

func TestGetStorageConfig_Error(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetStorageConfig(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetActiveStorageConfig
// ---------------------------------------------------------------------------

func TestGetActiveStorageConfig_Found(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*WHERE is_active").
		WillReturnRows(sampleStorageConfigRow())

	cfg, err := repo.GetActiveStorageConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
}

func TestGetActiveStorageConfig_NotFound(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*WHERE is_active").
		WillReturnRows(sqlmock.NewRows(storageConfigMinCols))

	cfg, err := repo.GetActiveStorageConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

// ---------------------------------------------------------------------------
// ListStorageConfigs
// ---------------------------------------------------------------------------

func TestListStorageConfigs_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config").
		WillReturnRows(sampleStorageConfigRow())

	configs, err := repo.ListStorageConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("len = %d, want 1", len(configs))
	}
}

func TestListStorageConfigs_Empty(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM storage_config").
		WillReturnRows(sqlmock.NewRows(storageConfigMinCols))

	configs, err := repo.ListStorageConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("len = %d, want 0", len(configs))
	}
}

// ---------------------------------------------------------------------------
// UpdateStorageConfig
// ---------------------------------------------------------------------------

func TestUpdateStorageConfig_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	cfg := &models.StorageConfig{ID: uuid.New(), BackendType: "azure", IsActive: false}
	if err := repo.UpdateStorageConfig(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteStorageConfig
// ---------------------------------------------------------------------------

func TestDeleteStorageConfig_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("DELETE FROM storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteStorageConfig(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeactivateAllStorageConfigs
// ---------------------------------------------------------------------------

func TestDeactivateAllStorageConfigs_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(1, 2))

	if err := repo.DeactivateAllStorageConfigs(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ActivateStorageConfig
// ---------------------------------------------------------------------------

func TestActivateStorageConfig_Success(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectBegin()
	// deactivate all
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(1, 3))
	// activate one
	mock.ExpectExec("UPDATE storage_config SET is_active = true").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := repo.ActivateStorageConfig(context.Background(), uuid.New(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestActivateStorageConfig_BeginError(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectBegin().WillReturnError(errDB)

	if err := repo.ActivateStorageConfig(context.Background(), uuid.New(), uuid.New()); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestActivateStorageConfig_DeactivateError(t *testing.T) {
	repo, mock := newStorageConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnError(errDB)
	mock.ExpectRollback()

	if err := repo.ActivateStorageConfig(context.Background(), uuid.New(), uuid.New()); err == nil {
		t.Error("expected error, got nil")
	}
}

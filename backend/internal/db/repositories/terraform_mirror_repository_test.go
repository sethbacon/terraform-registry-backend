package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// tfMirrorConfigCols lists the SELECT columns for TerraformMirrorConfig queries.
var tfMirrorConfigCols = []string{
	"id", "name", "description", "tool", "enabled", "upstream_url",
	"platform_filter", "version_filter", "gpg_verify", "stable_only", "sync_interval_hours",
	"last_sync_at", "last_sync_status", "last_sync_error",
	"created_at", "updated_at",
}

func newTerraformMirrorRepo(t *testing.T) (*TerraformMirrorRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func newTfMirrorConfigRow(mock sqlmock.Sqlmock, cfg *models.TerraformMirrorConfig) *sqlmock.Rows {
	rows := mock.NewRows(tfMirrorConfigCols)
	rows.AddRow(
		cfg.ID,
		cfg.Name,
		cfg.Description,
		cfg.Tool,
		cfg.Enabled,
		cfg.UpstreamURL,
		cfg.PlatformFilter,
		cfg.VersionFilter,
		cfg.GPGVerify,
		cfg.StableOnly,
		cfg.SyncIntervalHours,
		cfg.LastSyncAt,
		cfg.LastSyncStatus,
		cfg.LastSyncError,
		cfg.CreatedAt,
		cfg.UpdatedAt,
	)
	return rows
}

func testMirrorConfig() *models.TerraformMirrorConfig {
	now := time.Now().UTC().Truncate(time.Second)
	return &models.TerraformMirrorConfig{
		ID:                uuid.New(),
		Name:              "test-mirror",
		Tool:              "terraform",
		Enabled:           true,
		UpstreamURL:       "https://releases.hashicorp.com",
		GPGVerify:         true,
		StableOnly:        true,
		SyncIntervalHours: 24,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// --- Constructor ---

func TestNewTerraformMirrorRepository_NotNil(t *testing.T) {
	repo, _ := newTerraformMirrorRepo(t)
	if repo == nil {
		t.Fatal("expected non-nil repository")
	}
}

// --- ParsePlatformFilter (pure logic, no DB) ---

func TestParsePlatformFilter_Nil(t *testing.T) {
	platforms, err := ParsePlatformFilter(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if platforms != nil {
		t.Fatalf("expected nil, got %v", platforms)
	}
}

func TestParsePlatformFilter_EmptyString(t *testing.T) {
	s := ""
	platforms, err := ParsePlatformFilter(&s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if platforms != nil {
		t.Fatalf("expected nil, got %v", platforms)
	}
}

func TestParsePlatformFilter_Valid(t *testing.T) {
	s := `["linux_amd64","darwin_arm64"]`
	platforms, err := ParsePlatformFilter(&s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 2 {
		t.Fatalf("expected 2 platforms, got %d", len(platforms))
	}
	if platforms[0] != "linux_amd64" || platforms[1] != "darwin_arm64" {
		t.Fatalf("unexpected values: %v", platforms)
	}
}

func TestParsePlatformFilter_InvalidJSON(t *testing.T) {
	s := `not-json`
	_, err := ParsePlatformFilter(&s)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParsePlatformFilter_SingleItem(t *testing.T) {
	s := `["windows_amd64"]`
	platforms, err := ParsePlatformFilter(&s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 1 || platforms[0] != "windows_amd64" {
		t.Fatalf("unexpected value: %v", platforms)
	}
}

// --- EncodePlatformFilter (pure logic, no DB) ---

func TestEncodePlatformFilter_Nil(t *testing.T) {
	result, err := EncodePlatformFilter(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestEncodePlatformFilter_Empty(t *testing.T) {
	result, err := EncodePlatformFilter([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil for empty slice, got %v", result)
	}
}

func TestEncodePlatformFilter_Valid(t *testing.T) {
	platforms := []string{"linux_amd64", "darwin_arm64"}
	result, err := EncodePlatformFilter(platforms)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	expected := `["linux_amd64","darwin_arm64"]`
	if *result != expected {
		t.Fatalf("expected %q, got %q", expected, *result)
	}
}

func TestEncodePlatformFilter_RoundTrip(t *testing.T) {
	original := []string{"linux_amd64", "darwin_arm64", "windows_amd64"}
	encoded, err := EncodePlatformFilter(original)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	decoded, err := ParsePlatformFilter(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("index %d: got %q, want %q", i, decoded[i], original[i])
		}
	}
}

// --- GetByID ---

func TestTerraformMirrorGetByID_NotFound(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs(id).
		WillReturnRows(mock.NewRows(tfMirrorConfigCols))

	cfg, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config for not-found")
	}
}

func TestTerraformMirrorGetByID_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	expected := testMirrorConfig()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs(expected.ID).
		WillReturnRows(newTfMirrorConfigRow(mock, expected))

	cfg, err := repo.GetByID(context.Background(), expected.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || cfg.ID != expected.ID {
		t.Fatalf("unexpected config: %v", cfg)
	}
}

func TestTerraformMirrorGetByID_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs(id).
		WillReturnError(fmt.Errorf("connection error"))

	_, err := repo.GetByID(context.Background(), id)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- GetByName ---

func TestTerraformMirrorGetByName_NotFound(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs("nonexistent").
		WillReturnRows(mock.NewRows(tfMirrorConfigCols))

	cfg, err := repo.GetByName(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config for not-found")
	}
}

func TestTerraformMirrorGetByName_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	expected := testMirrorConfig()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs(expected.Name).
		WillReturnRows(newTfMirrorConfigRow(mock, expected))

	cfg, err := repo.GetByName(context.Background(), expected.Name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || cfg.Name != expected.Name {
		t.Fatalf("unexpected config: %v", cfg)
	}
}

func TestTerraformMirrorGetByName_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WithArgs("test").
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.GetByName(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- ListAll ---

func TestTerraformMirrorListAll_Empty(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnRows(mock.NewRows(tfMirrorConfigCols))

	cfgs, err := repo.ListAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 0 {
		t.Fatalf("expected empty slice, got %d", len(cfgs))
	}
}

func TestTerraformMirrorListAll_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	c1 := testMirrorConfig()
	c2 := testMirrorConfig()
	c2.Name = "second-mirror"

	rows := mock.NewRows(tfMirrorConfigCols)
	for _, c := range []*models.TerraformMirrorConfig{c1, c2} {
		rows.AddRow(
			c.ID, c.Name, c.Description, c.Tool, c.Enabled, c.UpstreamURL,
			c.PlatformFilter, c.VersionFilter, c.GPGVerify, c.StableOnly, c.SyncIntervalHours,
			c.LastSyncAt, c.LastSyncStatus, c.LastSyncError, c.CreatedAt, c.UpdatedAt,
		)
	}

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnRows(rows)

	cfgs, err := repo.ListAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(cfgs))
	}
}

func TestTerraformMirrorListAll_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.ListAll(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- ListEnabled ---

func TestTerraformMirrorListEnabled_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	c := testMirrorConfig()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnRows(newTfMirrorConfigRow(mock, c))

	cfgs, err := repo.ListEnabled(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(cfgs))
	}
}

func TestTerraformMirrorListEnabled_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.ListEnabled(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- GetConfigsNeedingSync ---

func TestTerraformMirrorGetConfigsNeedingSync_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	c := testMirrorConfig()

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnRows(newTfMirrorConfigRow(mock, c))

	cfgs, err := repo.GetConfigsNeedingSync(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(cfgs))
	}
}

func TestTerraformMirrorGetConfigsNeedingSync_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs`).
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.GetConfigsNeedingSync(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Delete ---

func TestTerraformMirrorDelete_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`DELETE FROM terraform_mirror_configs`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Delete(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerraformMirrorDelete_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`DELETE FROM terraform_mirror_configs`).
		WithArgs(id).
		WillReturnError(fmt.Errorf("db error"))

	err := repo.Delete(context.Background(), id)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Update ---

func TestTerraformMirrorUpdate_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	cfg := testMirrorConfig()

	mock.ExpectExec(`UPDATE terraform_mirror_configs`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Update(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerraformMirrorUpdate_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	cfg := testMirrorConfig()

	mock.ExpectExec(`UPDATE terraform_mirror_configs`).
		WillReturnError(fmt.Errorf("db error"))

	err := repo.Update(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- UpdateSyncStatus ---

func TestTerraformMirrorUpdateSyncStatus_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()
	status := "synced"

	mock.ExpectExec(`UPDATE terraform_mirror_configs`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.UpdateSyncStatus(context.Background(), id, status, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerraformMirrorUpdateSyncStatus_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`UPDATE terraform_mirror_configs`).
		WillReturnError(fmt.Errorf("db error"))

	err := repo.UpdateSyncStatus(context.Background(), id, "failed", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Version columns helper ---

var tfVersionCols = []string{
	"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
}

func newTFVersionRow(mock sqlmock.Sqlmock, v *models.TerraformVersion) *sqlmock.Rows {
	return mock.NewRows(tfVersionCols).AddRow(
		v.ID, v.ConfigID, v.Version, v.IsLatest, v.IsDeprecated, v.ReleaseDate,
		v.SyncStatus, v.SyncError, v.SyncedAt, v.CreatedAt, v.UpdatedAt,
	)
}

func testTFVersion(configID uuid.UUID) *models.TerraformVersion {
	now := time.Now().UTC().Truncate(time.Second)
	return &models.TerraformVersion{
		ID:         uuid.New(),
		ConfigID:   configID,
		Version:    "1.9.0",
		SyncStatus: "synced",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// --- GetVersionByString ---

func TestGetVersionByString_NotFound(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID, "1.9.0").
		WillReturnRows(mock.NewRows(tfVersionCols))

	v, err := repo.GetVersionByString(context.Background(), configID, "1.9.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != nil {
		t.Fatal("expected nil")
	}
}

func TestGetVersionByString_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID, "1.9.0").
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.GetVersionByString(context.Background(), configID, "1.9.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- GetLatestVersion ---

func TestGetLatestVersion_NotFound(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID).
		WillReturnRows(mock.NewRows(tfVersionCols))

	v, err := repo.GetLatestVersion(context.Background(), configID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != nil {
		t.Fatal("expected nil")
	}
}

func TestGetLatestVersion_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID).
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.GetLatestVersion(context.Background(), configID)
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- ListVersions ---

func TestTFMirrorListVersions_Empty(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID).
		WillReturnRows(mock.NewRows(tfVersionCols))

	versions, err := repo.ListVersions(context.Background(), configID, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected empty, got %d", len(versions))
	}
}

func TestTFMirrorListVersions_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID := uuid.New()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions`).
		WithArgs(configID).
		WillReturnError(fmt.Errorf("db error"))

	_, err := repo.ListVersions(context.Background(), configID, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- UpdateVersionSyncStatus ---

func TestUpdateVersionSyncStatus_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`UPDATE terraform_versions`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateVersionSyncStatus(context.Background(), id, "synced", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateVersionSyncStatus_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`UPDATE terraform_versions`).
		WillReturnError(fmt.Errorf("db error"))

	if err := repo.UpdateVersionSyncStatus(context.Background(), id, "failed", nil); err == nil {
		t.Fatal("expected error")
	}
}

// --- DeleteVersion ---

func TestTerraformMirrorDeleteVersion_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`DELETE FROM terraform_versions`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteVersion(context.Background(), id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerraformMirrorDeleteVersion_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	id := uuid.New()

	mock.ExpectExec(`DELETE FROM terraform_versions`).
		WithArgs(id).
		WillReturnError(fmt.Errorf("db error"))

	if err := repo.DeleteVersion(context.Background(), id); err == nil {
		t.Fatal("expected error")
	}
}

// --- SetLatestVersion ---

func TestSetLatestVersion_Success(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID, versionID := uuid.New(), uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE terraform_versions SET is_latest = false`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE terraform_versions SET is_latest = true`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := repo.SetLatestVersion(context.Background(), configID, versionID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetLatestVersion_DBError(t *testing.T) {
	repo, mock := newTerraformMirrorRepo(t)
	configID, versionID := uuid.New(), uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE terraform_versions SET is_latest = false`).
		WillReturnError(fmt.Errorf("db error"))
	mock.ExpectRollback()

	if err := repo.SetLatestVersion(context.Background(), configID, versionID); err == nil {
		t.Fatal("expected error")
	}
}

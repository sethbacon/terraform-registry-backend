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

func newMirrorRepo(t *testing.T) (*MirrorRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewMirrorRepository(sqlx.NewDb(db, "sqlmock")), mock
}

// Minimal column sets for struct scanning
var mirrorConfigCols = []string{
	"id", "name", "upstream_registry_url", "enabled", "sync_interval_hours",
	"created_at", "updated_at",
}

var mirroredProviderCols = []string{
	"id", "mirror_config_id", "provider_id", "upstream_namespace", "upstream_type",
	"last_synced_at", "sync_enabled", "created_at",
}

var mirroredVersionCols = []string{
	"id", "mirrored_provider_id", "provider_version_id", "upstream_version",
	"synced_at", "shasum_verified", "gpg_verified",
}

var syncHistoryCols = []string{
	"id", "mirror_config_id", "started_at", "status",
	"providers_synced", "providers_failed",
}

func sampleMirrorConfigRow() *sqlmock.Rows {
	id := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	return sqlmock.NewRows(mirrorConfigCols).
		AddRow(id, "my-mirror", "https://registry.terraform.io", true, 24, time.Now(), time.Now())
}

func sampleMirroredProviderRow() *sqlmock.Rows {
	id := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	mirrorID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	providerID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	return sqlmock.NewRows(mirroredProviderCols).
		AddRow(id, mirrorID, providerID, "hashicorp", "aws", time.Now(), true, time.Now())
}

func sampleMirroredVersionRow() *sqlmock.Rows {
	id := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	mpID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	pvID := uuid.MustParse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
	return sqlmock.NewRows(mirroredVersionCols).
		AddRow(id, mpID, pvID, "4.0.0", time.Now(), true, false)
}

func sampleSyncHistoryRow() *sqlmock.Rows {
	id := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	mirrorID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	return sqlmock.NewRows(syncHistoryCols).
		AddRow(id, mirrorID, time.Now(), "success", 5, 0)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestMirrorCreate_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	cfg := &models.MirrorConfiguration{
		ID:                  uuid.New(),
		Name:                "test-mirror",
		UpstreamRegistryURL: "https://registry.terraform.io",
		Enabled:             true,
		SyncIntervalHours:   24,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	if err := repo.Create(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMirrorCreate_Error(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnError(errDB)

	cfg := &models.MirrorConfiguration{ID: uuid.New(), Name: "x"}
	if err := repo.Create(context.Background(), cfg); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------------

func TestMirrorGetByID_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	id := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations.*WHERE id").
		WillReturnRows(sampleMirrorConfigRow())

	cfg, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
}

func TestMirrorGetByID_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols))

	cfg, err := repo.GetByID(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

// ---------------------------------------------------------------------------
// GetByName
// ---------------------------------------------------------------------------

func TestMirrorGetByName_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations.*WHERE name").
		WillReturnRows(sampleMirrorConfigRow())

	cfg, err := repo.GetByName(context.Background(), "my-mirror")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
}

func TestMirrorGetByName_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations.*WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols))

	cfg, err := repo.GetByName(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestMirrorList_All(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(sampleMirrorConfigRow())

	configs, err := repo.List(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("len = %d, want 1", len(configs))
	}
}

func TestMirrorList_EnabledOnly(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols))

	configs, err := repo.List(context.Background(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("len = %d, want 0", len(configs))
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestMirrorUpdate_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("UPDATE mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	cfg := &models.MirrorConfiguration{
		ID:                  uuid.New(),
		Name:                "updated",
		UpstreamRegistryURL: "https://registry.terraform.io",
		Enabled:             true,
		SyncIntervalHours:   12,
	}
	if err := repo.Update(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMirrorUpdate_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("UPDATE mirror_configurations").
		WillReturnResult(sqlmock.NewResult(0, 0))

	cfg := &models.MirrorConfiguration{
		ID:                  uuid.New(),
		UpstreamRegistryURL: "https://registry.terraform.io",
	}
	if err := repo.Update(context.Background(), cfg); err == nil {
		t.Error("expected error for not found")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestMirrorDelete_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("DELETE FROM mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMirrorDelete_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("DELETE FROM mirror_configurations").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.Delete(context.Background(), uuid.New()); err == nil {
		t.Error("expected error for not found")
	}
}

// ---------------------------------------------------------------------------
// UpdateSyncStatus
// ---------------------------------------------------------------------------

func TestMirrorUpdateSyncStatus_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("UPDATE mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateSyncStatus(context.Background(), uuid.New(), "success", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetMirrorsNeedingSync
// ---------------------------------------------------------------------------

func TestGetMirrorsNeedingSync_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations.*WHERE enabled = true").
		WillReturnRows(sampleMirrorConfigRow())

	configs, err := repo.GetMirrorsNeedingSync(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("len = %d, want 1", len(configs))
	}
}

// ---------------------------------------------------------------------------
// CreateSyncHistory
// ---------------------------------------------------------------------------

func TestCreateSyncHistory_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("INSERT INTO mirror_sync_history").
		WillReturnResult(sqlmock.NewResult(1, 1))

	hist := &models.MirrorSyncHistory{
		ID:             uuid.New(),
		MirrorConfigID: uuid.New(),
		StartedAt:      time.Now(),
		Status:         "running",
	}
	if err := repo.CreateSyncHistory(context.Background(), hist); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateSyncHistory
// ---------------------------------------------------------------------------

func TestUpdateSyncHistory_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("UPDATE mirror_sync_history").
		WillReturnResult(sqlmock.NewResult(1, 1))

	hist := &models.MirrorSyncHistory{
		ID:              uuid.New(),
		Status:          "success",
		ProvidersSynced: 5,
	}
	if err := repo.UpdateSyncHistory(context.Background(), hist); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetSyncHistory
// ---------------------------------------------------------------------------

func TestGetSyncHistory_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mirrorID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	mock.ExpectQuery("SELECT id.*FROM mirror_sync_history.*WHERE mirror_config_id").
		WillReturnRows(sampleSyncHistoryRow())

	hist, err := repo.GetSyncHistory(context.Background(), mirrorID, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hist) != 1 {
		t.Errorf("len = %d, want 1", len(hist))
	}
}

// ---------------------------------------------------------------------------
// GetActiveSyncHistory
// ---------------------------------------------------------------------------

func TestGetActiveSyncHistory_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_sync_history.*WHERE mirror_config_id.*AND status").
		WillReturnRows(sampleSyncHistoryRow())

	hist, err := repo.GetActiveSyncHistory(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hist == nil {
		t.Fatal("expected history, got nil")
	}
}

func TestGetActiveSyncHistory_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_sync_history.*WHERE mirror_config_id.*AND status").
		WillReturnRows(sqlmock.NewRows(syncHistoryCols))

	hist, err := repo.GetActiveSyncHistory(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hist != nil {
		t.Errorf("expected nil, got %v", hist)
	}
}

// ---------------------------------------------------------------------------
// CreateMirroredProvider
// ---------------------------------------------------------------------------

func TestCreateMirroredProvider_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("INSERT INTO mirrored_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mp := &models.MirroredProvider{
		ID:                uuid.New(),
		MirrorConfigID:    uuid.New(),
		ProviderID:        uuid.New(),
		UpstreamNamespace: "hashicorp",
		UpstreamType:      "aws",
		LastSyncedAt:      time.Now(),
		SyncEnabled:       true,
		CreatedAt:         time.Now(),
	}
	if err := repo.CreateMirroredProvider(context.Background(), mp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetMirroredProvider
// ---------------------------------------------------------------------------

func TestGetMirroredProvider_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mirrorID := uuid.New()
	mock.ExpectQuery("SELECT id.*FROM mirrored_providers.*WHERE mirror_config_id").
		WillReturnRows(sampleMirroredProviderRow())

	mp, err := repo.GetMirroredProvider(context.Background(), mirrorID, "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mp == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestGetMirroredProvider_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_providers.*WHERE mirror_config_id").
		WillReturnRows(sqlmock.NewRows(mirroredProviderCols))

	mp, err := repo.GetMirroredProvider(context.Background(), uuid.New(), "ns", "type")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mp != nil {
		t.Errorf("expected nil, got %v", mp)
	}
}

// ---------------------------------------------------------------------------
// GetMirroredProviderByProviderID
// ---------------------------------------------------------------------------

func TestGetMirroredProviderByProviderID_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_providers.*WHERE provider_id").
		WillReturnRows(sampleMirroredProviderRow())

	mp, err := repo.GetMirroredProviderByProviderID(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mp == nil {
		t.Fatal("expected provider, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateMirroredProvider
// ---------------------------------------------------------------------------

func TestUpdateMirroredProvider_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("UPDATE mirrored_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mp := &models.MirroredProvider{ID: uuid.New(), SyncEnabled: true, LastSyncedAt: time.Now()}
	if err := repo.UpdateMirroredProvider(context.Background(), mp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListMirroredProviders
// ---------------------------------------------------------------------------

func TestListMirroredProviders_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_providers.*WHERE mirror_config_id").
		WillReturnRows(sampleMirroredProviderRow())

	providers, err := repo.ListMirroredProviders(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 1 {
		t.Errorf("len = %d, want 1", len(providers))
	}
}

// ---------------------------------------------------------------------------
// CreateMirroredProviderVersion
// ---------------------------------------------------------------------------

func TestCreateMirroredProviderVersion_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectExec("INSERT INTO mirrored_provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mpv := &models.MirroredProviderVersion{
		ID:                 uuid.New(),
		MirroredProviderID: uuid.New(),
		ProviderVersionID:  uuid.New(),
		UpstreamVersion:    "4.0.0",
		SyncedAt:           time.Now(),
		ShasumVerified:     true,
		GPGVerified:        false,
	}
	if err := repo.CreateMirroredProviderVersion(context.Background(), mpv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetMirroredProviderVersion
// ---------------------------------------------------------------------------

func TestGetMirroredProviderVersion_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_provider_versions.*WHERE mirrored_provider_id").
		WillReturnRows(sampleMirroredVersionRow())

	mpv, err := repo.GetMirroredProviderVersion(context.Background(), uuid.New(), "4.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mpv == nil {
		t.Fatal("expected version, got nil")
	}
}

func TestGetMirroredProviderVersion_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_provider_versions.*WHERE mirrored_provider_id").
		WillReturnRows(sqlmock.NewRows(mirroredVersionCols))

	mpv, err := repo.GetMirroredProviderVersion(context.Background(), uuid.New(), "99.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mpv != nil {
		t.Errorf("expected nil, got %v", mpv)
	}
}

// ---------------------------------------------------------------------------
// ListMirroredProviderVersions
// ---------------------------------------------------------------------------

func TestListMirroredProviderVersions_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_provider_versions.*WHERE mirrored_provider_id").
		WillReturnRows(sampleMirroredVersionRow())

	versions, err := repo.ListMirroredProviderVersions(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("len = %d, want 1", len(versions))
	}
}

// ---------------------------------------------------------------------------
// GetMirroredProviderVersionByVersionID
// ---------------------------------------------------------------------------

func TestGetMirroredProviderVersionByVersionID_Found(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_provider_versions.*WHERE provider_version_id").
		WillReturnRows(sampleMirroredVersionRow())

	mpv, err := repo.GetMirroredProviderVersionByVersionID(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mpv == nil {
		t.Fatal("expected version, got nil")
	}
}

func TestGetMirroredProviderVersionByVersionID_NotFound(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirrored_provider_versions.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(mirroredVersionCols))

	mpv, err := repo.GetMirroredProviderVersionByVersionID(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mpv != nil {
		t.Errorf("expected nil, got %v", mpv)
	}
}

// ---------------------------------------------------------------------------
// jsonToStringArray pure function tests
// ---------------------------------------------------------------------------

func TestJsonToStringArray_Nil(t *testing.T) {
	result, err := jsonToStringArray(nil)
	if err != nil || result != nil {
		t.Errorf("jsonToStringArray(nil) = %v, %v; want nil, nil", result, err)
	}
}

func TestJsonToStringArray_Empty(t *testing.T) {
	empty := ""
	result, err := jsonToStringArray(&empty)
	if err != nil || result != nil {
		t.Errorf("jsonToStringArray(\"\") = %v, %v; want nil, nil", result, err)
	}
}

func TestJsonToStringArray_ValidJSON(t *testing.T) {
	json := `["foo","bar","baz"]`
	result, err := jsonToStringArray(&json)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 || result[0] != "foo" || result[1] != "bar" || result[2] != "baz" {
		t.Errorf("jsonToStringArray = %v, want [foo bar baz]", result)
	}
}

func TestJsonToStringArray_InvalidJSON(t *testing.T) {
	bad := "not-json"
	_, err := jsonToStringArray(&bad)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

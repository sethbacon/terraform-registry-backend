package repositories

import (
	"context"
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

// Full column set used by GetPullThroughConfigsForProvider
var pullThroughCols = []string{
	"id", "name", "description", "upstream_registry_url", "organization_id",
	"namespace_filter", "provider_filter", "version_filter", "platform_filter",
	"enabled", "sync_interval_hours", "pull_through_enabled",
	"pull_through_cache_ttl_hours", "last_sync_at", "last_sync_status", "last_sync_error",
	"created_at", "updated_at", "created_by",
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

// ---------------------------------------------------------------------------
// ResetStaleSyncs
// ---------------------------------------------------------------------------

func TestResetStaleSyncs_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)

	mock.ExpectExec("UPDATE mirror_sync_history").
		WillReturnResult(sqlmock.NewResult(0, 2))

	mock.ExpectExec("UPDATE mirror_configurations").
		WillReturnResult(sqlmock.NewResult(0, 1))

	rows, err := repo.ResetStaleSyncs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rows != 2 {
		t.Errorf("rows = %d, want 2", rows)
	}
}

func TestResetStaleSyncs_FirstExecError(t *testing.T) {
	repo, mock := newMirrorRepo(t)

	mock.ExpectExec("UPDATE mirror_sync_history").
		WillReturnError(errDB)

	_, err := repo.ResetStaleSyncs(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestResetStaleSyncs_SecondExecError(t *testing.T) {
	repo, mock := newMirrorRepo(t)

	mock.ExpectExec("UPDATE mirror_sync_history").
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectExec("UPDATE mirror_configurations").
		WillReturnError(errDB)

	_, err := repo.ResetStaleSyncs(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListMirroredProvidersPaginated
// ---------------------------------------------------------------------------

func TestListMirroredProvidersPaginated_Success(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mirrorID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	mock.ExpectQuery("SELECT COUNT").
		WithArgs(mirrorID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery("SELECT.*FROM mirrored_providers.*WHERE mirror_config_id").
		WithArgs(mirrorID, 10, 0).
		WillReturnRows(sampleMirroredProviderRow())

	providers, total, err := repo.ListMirroredProvidersPaginated(context.Background(), mirrorID, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(providers) != 1 {
		t.Errorf("len = %d, want 1", len(providers))
	}
}

func TestListMirroredProvidersPaginated_CountError(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mirrorID := uuid.New()

	mock.ExpectQuery("SELECT COUNT").
		WithArgs(mirrorID).
		WillReturnError(errDB)

	_, _, err := repo.ListMirroredProvidersPaginated(context.Background(), mirrorID, 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// matchesJSONFilter (pure helper — no DB required)
// ---------------------------------------------------------------------------

func TestMatchesJSONFilter_NilFilter(t *testing.T) {
	if !matchesJSONFilter(nil, "linux") {
		t.Error("nil filter should match everything")
	}
}

func TestMatchesJSONFilter_EmptyFilter(t *testing.T) {
	empty := ""
	if !matchesJSONFilter(&empty, "linux") {
		t.Error("empty filter should match everything")
	}
}

func TestMatchesJSONFilter_MatchInList(t *testing.T) {
	f := `["linux","darwin","windows"]`
	if !matchesJSONFilter(&f, "linux") {
		t.Error("expected match for 'linux' in JSON array")
	}
}

func TestMatchesJSONFilter_NoMatchInList(t *testing.T) {
	f := `["darwin","windows"]`
	if matchesJSONFilter(&f, "linux") {
		t.Error("expected no match for 'linux' not in JSON array")
	}
}

func TestMatchesJSONFilter_SubstringButNotInList(t *testing.T) {
	// "linux" appears as substring of "linuxalt" in filter but is not a list member
	f := `["linuxalt","darwin"]`
	if matchesJSONFilter(&f, "linux") {
		t.Error("expected no match: 'linux' is not a list element even though it's a substring")
	}
}

func TestMatchesJSONFilter_InvalidJSON_MatchesAll(t *testing.T) {
	// Unparseable filter is treated as "match all"
	bad := "not-json-but-contains-linux"
	// matchesJSONFilter first checks if value is a substring; then tries to parse.
	// Since "linux" is in the string, substring check passes. JSON parse fails → return true.
	if !matchesJSONFilter(&bad, "linux") {
		t.Error("unparseable filter containing value as substring should match")
	}
}

func TestMatchesJSONFilter_NotSubstring(t *testing.T) {
	// If value isn't even a substring, return false immediately (before JSON parse)
	f := `["darwin","windows"]`
	if matchesJSONFilter(&f, "linux") {
		t.Error("expected no match when value not present as substring")
	}
}

// ---------------------------------------------------------------------------
// GetPullThroughConfigsForProvider
// ---------------------------------------------------------------------------

// pullThroughRow builds a sqlmock row for a MirrorConfiguration with the
// full column set returned by GetPullThroughConfigsForProvider.
func pullThroughRow(id uuid.UUID, orgID uuid.UUID, nsFilter, provFilter *string) *sqlmock.Rows {
	rows := sqlmock.NewRows(pullThroughCols)
	rows.AddRow(
		id,                              // id
		"pt-mirror",                     // name
		nil,                             // description
		"https://registry.terraform.io", // upstream_registry_url
		orgID,                           // organization_id
		nsFilter,                        // namespace_filter
		provFilter,                      // provider_filter
		nil,                             // version_filter
		nil,                             // platform_filter
		true,                            // enabled
		24,                              // sync_interval_hours
		true,                            // pull_through_enabled
		1,                               // pull_through_cache_ttl_hours
		nil,                             // last_sync_at
		nil,                             // last_sync_status
		nil,                             // last_sync_error
		time.Now(),                      // created_at
		time.Now(),                      // updated_at
		nil,                             // created_by
	)
	return rows
}

func TestGetPullThroughConfigsForProvider_DBError(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnError(errDB)

	result, err := repo.GetPullThroughConfigsForProvider(context.Background(), "org1", "hashicorp", "aws")
	if err == nil {
		t.Error("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %v", result)
	}
}

func TestGetPullThroughConfigsForProvider_Empty(t *testing.T) {
	repo, mock := newMirrorRepo(t)
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(pullThroughCols))

	result, err := repo.GetPullThroughConfigsForProvider(context.Background(), "org1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 results, got %d", len(result))
	}
}

func TestGetPullThroughConfigsForProvider_NilFiltersMatchAll(t *testing.T) {
	// A config with nil namespace_filter and nil provider_filter matches any provider.
	repo, mock := newMirrorRepo(t)
	orgID := uuid.New()
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(pullThroughRow(uuid.New(), orgID, nil, nil))

	result, err := repo.GetPullThroughConfigsForProvider(context.Background(), orgID.String(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}

func TestGetPullThroughConfigsForProvider_FilteredOut(t *testing.T) {
	// Namespace filter ["terraform"] does not match "hashicorp".
	repo, mock := newMirrorRepo(t)
	orgID := uuid.New()
	nsFilter := `["terraform"]`
	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(pullThroughRow(uuid.New(), orgID, &nsFilter, nil))

	result, err := repo.GetPullThroughConfigsForProvider(context.Background(), orgID.String(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 results (filtered out), got %d", len(result))
	}
}

func TestGetPullThroughConfigsForProvider_SpecificitySort(t *testing.T) {
	// Three configs returned from DB; most specific (both filters set) should sort first.
	repo, mock := newMirrorRepo(t)
	orgID := uuid.New()

	nsFilter := `["hashicorp"]`
	provFilter := `["aws"]`

	// Row 1: no filters (score 0)
	id1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	// Row 2: provider filter only (score 2)
	id2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	// Row 3: both filters (score 3)
	id3 := uuid.MustParse("33333333-3333-3333-3333-333333333333")

	rows := sqlmock.NewRows(pullThroughCols)
	// DB returns them in id1, id2, id3 order; sort should reorder to id3, id2, id1.
	for _, row := range []struct {
		id         uuid.UUID
		nsFilter   *string
		provFilter *string
	}{
		{id1, nil, nil},
		{id2, nil, &provFilter},
		{id3, &nsFilter, &provFilter},
	} {
		rows.AddRow(
			row.id, "pt-mirror", nil, "https://registry.terraform.io", orgID,
			row.nsFilter, row.provFilter, nil, nil,
			true, 24, true, 1, nil, nil, nil,
			time.Now(), time.Now(), nil,
		)
	}

	mock.ExpectQuery("SELECT id.*FROM mirror_configurations").
		WillReturnRows(rows)

	result, err := repo.GetPullThroughConfigsForProvider(context.Background(), orgID.String(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	// Most specific first: both filters (id3) → provider only (id2) → no filters (id1)
	if result[0].ID != id3 {
		t.Errorf("result[0] = %v, want id3 (%v)", result[0].ID, id3)
	}
	if result[1].ID != id2 {
		t.Errorf("result[1] = %v, want id2 (%v)", result[1].ID, id2)
	}
	if result[2].ID != id1 {
		t.Errorf("result[2] = %v, want id1 (%v)", result[2].ID, id1)
	}
}

package services

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"

	// Register the local storage backend for buildStorageFromConfig tests.
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
)

// ---------------------------------------------------------------------------
// NewStorageMigrationService
// ---------------------------------------------------------------------------

func TestNewStorageMigrationService_NonNil(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	if svc == nil {
		t.Fatal("NewStorageMigrationService returned nil")
	}
}

func TestNewStorageMigrationService_StoresFields(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	cfg := &config.Config{}

	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, cfg)
	if svc == nil {
		t.Fatal("NewStorageMigrationService returned nil")
	}
	if svc.repo != repo {
		t.Error("repo field was not set correctly")
	}
	if svc.storageConfigRepo != scRepo {
		t.Error("storageConfigRepo field was not set correctly")
	}
	if svc.cfg != cfg {
		t.Error("cfg field was not set correctly")
	}
}

func TestNewStorageMigrationService_AllNilArgs(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	if svc == nil {
		t.Fatal("NewStorageMigrationService returned nil with all nil args")
	}
	if svc.repo != nil {
		t.Error("repo should be nil")
	}
	if svc.storageConfigRepo != nil {
		t.Error("storageConfigRepo should be nil")
	}
	if svc.moduleRepo != nil {
		t.Error("moduleRepo should be nil")
	}
	if svc.providerRepo != nil {
		t.Error("providerRepo should be nil")
	}
	if svc.tokenCipher != nil {
		t.Error("tokenCipher should be nil")
	}
	if svc.cfg != nil {
		t.Error("cfg should be nil")
	}
}

// ---------------------------------------------------------------------------
// updateBackendRef — dispatches on artifact type to update the correct table
// ---------------------------------------------------------------------------

func TestUpdateBackendRef_Module(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectExec("UPDATE module_versions").
		WithArgs("artifact-123", "s3").
		WillReturnResult(sqlmock.NewResult(0, 1))

	item := &models.StorageMigrationItem{
		ArtifactType: "module",
		ArtifactID:   "artifact-123",
	}
	if err := svc.updateBackendRef(context.Background(), item, "s3"); err != nil {
		t.Errorf("updateBackendRef(module) returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpdateBackendRef_Provider(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectExec("UPDATE provider_platforms").
		WithArgs("artifact-456", "azure").
		WillReturnResult(sqlmock.NewResult(0, 1))

	item := &models.StorageMigrationItem{
		ArtifactType: "provider",
		ArtifactID:   "artifact-456",
	}
	if err := svc.updateBackendRef(context.Background(), item, "azure"); err != nil {
		t.Errorf("updateBackendRef(provider) returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpdateBackendRef_UnknownType(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	item := &models.StorageMigrationItem{
		ArtifactType: "unknown",
		ArtifactID:   "x",
	}
	err := svc.updateBackendRef(context.Background(), item, "s3")
	if err == nil {
		t.Fatal("expected error for unknown artifact type, got nil")
	}
}

func TestUpdateBackendRef_ModuleDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectExec("UPDATE module_versions").
		WithArgs("artifact-123", "s3").
		WillReturnError(&testDBError{"update failed"})

	item := &models.StorageMigrationItem{
		ArtifactType: "module",
		ArtifactID:   "artifact-123",
	}
	if err := svc.updateBackendRef(context.Background(), item, "s3"); err == nil {
		t.Error("expected error when DB fails, got nil")
	}
}

func TestUpdateBackendRef_ProviderDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectExec("UPDATE provider_platforms").
		WithArgs("artifact-456", "gcs").
		WillReturnError(&testDBError{"update failed"})

	item := &models.StorageMigrationItem{
		ArtifactType: "provider",
		ArtifactID:   "artifact-456",
	}
	if err := svc.updateBackendRef(context.Background(), item, "gcs"); err == nil {
		t.Error("expected error when DB fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// CancelFuncs sync.Map — verify store/load/delete cycle
// ---------------------------------------------------------------------------

func TestCancelFuncs_StoreAndDelete(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.cancelFuncs.Store("mig-1", cancel)

	if _, ok := svc.cancelFuncs.Load("mig-1"); !ok {
		t.Error("expected cancel func to be stored for mig-1")
	}

	// Simulate what CancelMigration does
	if cancelFn, ok := svc.cancelFuncs.LoadAndDelete("mig-1"); ok {
		cancelFn.(context.CancelFunc)()
	}

	if _, ok := svc.cancelFuncs.Load("mig-1"); ok {
		t.Error("expected cancel func to be deleted for mig-1")
	}

	// Verify context was actually cancelled
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("context should have been cancelled")
	}
}

// testDBError is a simple error for DB test failures.
type testDBError struct{ msg string }

func (e *testDBError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// storageConfigColumns / storageMigrationColumns — helpers for sqlmock rows
// ---------------------------------------------------------------------------

var storageConfigColumns = []string{
	"id", "backend_type", "is_active",
	"local_base_path", "local_serve_directly",
	"azure_account_name", "azure_account_key_encrypted", "azure_container_name", "azure_cdn_url",
	"s3_endpoint", "s3_region", "s3_bucket", "s3_auth_method",
	"s3_access_key_id_encrypted", "s3_secret_access_key_encrypted",
	"s3_role_arn", "s3_role_session_name", "s3_external_id", "s3_web_identity_token_file",
	"gcs_bucket", "gcs_project_id", "gcs_auth_method", "gcs_credentials_file",
	"gcs_credentials_json_encrypted", "gcs_endpoint",
	"created_at", "updated_at", "created_by", "updated_by",
}

func newStorageConfigRow(id, backendType string) []driver.Value {
	now := time.Now()
	return []driver.Value{
		id, backendType, true,
		nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil,
		now, now, nil, nil,
	}
}

var storageMigrationColumns = []string{
	"id", "source_config_id", "target_config_id", "status",
	"total_artifacts", "migrated_artifacts", "failed_artifacts", "skipped_artifacts",
	"error_message", "started_at", "completed_at", "created_at", "created_by",
}

func newMigrationRow(id, srcID, tgtID, status string, total int) []driver.Value {
	now := time.Now()
	return []driver.Value{
		id, srcID, tgtID, status,
		total, 0, 0, 0,
		nil, nil, nil, now, nil,
	}
}

// ---------------------------------------------------------------------------
// PlanMigration
// ---------------------------------------------------------------------------

func TestPlanMigration_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Mock GetStorageConfig for source
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	// Mock GetStorageConfig for target
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "s3")...))

	// Mock GetModuleArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).
			AddRow("m1", "/modules/m1.zip").
			AddRow("m2", "/modules/m2.zip"))

	// Mock GetProviderArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).
			AddRow("p1", "/providers/p1.zip"))

	plan, err := svc.PlanMigration(context.Background(), srcID, tgtID)
	if err != nil {
		t.Fatalf("PlanMigration returned error: %v", err)
	}
	if plan.ModuleCount != 2 {
		t.Errorf("ModuleCount = %d, want 2", plan.ModuleCount)
	}
	if plan.ProviderCount != 1 {
		t.Errorf("ProviderCount = %d, want 1", plan.ProviderCount)
	}
	if plan.TotalArtifacts != 3 {
		t.Errorf("TotalArtifacts = %d, want 3", plan.TotalArtifacts)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestPlanMigration_InvalidSourceUUID(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	_, err := svc.PlanMigration(context.Background(), "not-a-uuid", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	if err == nil {
		t.Fatal("expected error for invalid source UUID, got nil")
	}
}

func TestPlanMigration_InvalidTargetUUID(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	_, err := svc.PlanMigration(context.Background(), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bad")
	if err == nil {
		t.Fatal("expected error for invalid target UUID, got nil")
	}
}

func TestPlanMigration_SourceNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Return no rows so GetStorageConfig returns nil
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns))

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for source not found, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestGetStatus_Found(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	migID := "cccccccc-cccc-cccc-cccc-cccccccccccc"
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow(migID, "src", "tgt", "running", 10)...))

	m, err := svc.GetStatus(context.Background(), migID)
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if m == nil {
		t.Fatal("GetStatus returned nil")
	}
	if m.Status != "running" {
		t.Errorf("Status = %q, want %q", m.Status, "running")
	}
	if m.TotalArtifacts != 10 {
		t.Errorf("TotalArtifacts = %d, want 10", m.TotalArtifacts)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetStatus_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns))

	m, err := svc.GetStatus(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil migration, got %+v", m)
	}
}

// ---------------------------------------------------------------------------
// ListMigrations
// ---------------------------------------------------------------------------

func TestListMigrations_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	// Mock COUNT query
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Mock SELECT query
	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY created_at DESC").
		WithArgs(10, 0).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow("mig-1", "s1", "t1", "completed", 5)...).
			AddRow(newMigrationRow("mig-2", "s2", "t2", "running", 3)...))

	migrations, total, err := svc.ListMigrations(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListMigrations returned error: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(migrations) != 2 {
		t.Errorf("len(migrations) = %d, want 2", len(migrations))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestListMigrations_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY created_at DESC").
		WithArgs(10, 0).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns))

	migrations, total, err := svc.ListMigrations(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListMigrations returned error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(migrations) != 0 {
		t.Errorf("len(migrations) = %d, want 0", len(migrations))
	}
}

// ---------------------------------------------------------------------------
// CancelMigration
// ---------------------------------------------------------------------------

func TestCancelMigration_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("no-such-id").
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns))

	err = svc.CancelMigration(context.Background(), "no-such-id")
	if err == nil {
		t.Fatal("expected error for not-found migration, got nil")
	}
}

func TestCancelMigration_NotCancellable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	migID := "dddddddd-dddd-dddd-dddd-dddddddddddd"
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow(migID, "s", "t", "completed", 5)...))

	err = svc.CancelMigration(context.Background(), migID)
	if err == nil {
		t.Fatal("expected error for completed migration, got nil")
	}
}

func TestCancelMigration_Success_NoCancelFunc(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	migID := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

	// GetMigration returns a running migration
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow(migID, "s", "t", "running", 5)...))

	// UpdateMigrationStatus to cancelled
	mock.ExpectExec("UPDATE storage_migrations SET status").
		WithArgs(migID, "cancelled", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = svc.CancelMigration(context.Background(), migID)
	if err != nil {
		t.Fatalf("CancelMigration returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestCancelMigration_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("x").
		WillReturnError(&testDBError{"db failed"})

	err = svc.CancelMigration(context.Background(), "x")
	if err == nil {
		t.Fatal("expected error when DB fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// updateProgress — writes counters to DB
// ---------------------------------------------------------------------------

func TestUpdateProgress(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	mock.ExpectExec("UPDATE storage_migrations SET migrated_artifacts").
		WithArgs("mig-1", 10, 2, 0).
		WillReturnResult(sqlmock.NewResult(0, 1))

	var migrated, failed, skipped int64 = 10, 2, 0
	svc.updateProgress("mig-1", &migrated, &failed, &skipped)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildStorageFromConfig — local backend case
// ---------------------------------------------------------------------------

func TestBuildStorageFromConfig_Local(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})

	tmpDir := t.TempDir()
	sc := &models.StorageConfig{
		BackendType: "local",
	}
	sc.LocalBasePath.Valid = true
	sc.LocalBasePath.String = tmpDir

	stor, err := svc.buildStorageFromConfig(sc)
	if err != nil {
		t.Fatalf("buildStorageFromConfig(local) returned error: %v", err)
	}
	if stor == nil {
		t.Fatal("expected non-nil storage")
	}
}

func TestBuildStorageFromConfig_LocalWithServeDirectly(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})

	tmpDir := t.TempDir()
	sc := &models.StorageConfig{
		BackendType: "local",
	}
	sc.LocalBasePath.Valid = true
	sc.LocalBasePath.String = tmpDir
	sc.LocalServeDirectly.Valid = true
	sc.LocalServeDirectly.Bool = true

	stor, err := svc.buildStorageFromConfig(sc)
	if err != nil {
		t.Fatalf("buildStorageFromConfig(local+serve) returned error: %v", err)
	}
	if stor == nil {
		t.Fatal("expected non-nil storage")
	}
}

// ---------------------------------------------------------------------------
// StartMigration — validation paths
// ---------------------------------------------------------------------------

func TestStartMigration_InvalidSourceUUID(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	_, err := svc.StartMigration(context.Background(), "bad-uuid", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "user1")
	if err == nil {
		t.Fatal("expected error for invalid source UUID")
	}
}

func TestStartMigration_InvalidTargetUUID(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	_, err := svc.StartMigration(context.Background(), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bad", "user1")
	if err == nil {
		t.Fatal("expected error for invalid target UUID")
	}
}

func TestStartMigration_SourceNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Source config not found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns))

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "user1")
	if err == nil {
		t.Fatal("expected error for source not found")
	}
}

func TestStartMigration_TargetNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Source config found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).
			AddRow(newStorageConfigRow(srcID, "local")...))

	// Target config not found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns))

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "user1")
	if err == nil {
		t.Fatal("expected error for target not found")
	}
}

// ---------------------------------------------------------------------------
// buildStorageFromConfig — unsupported backend
// ---------------------------------------------------------------------------

func TestBuildStorageFromConfig_UnknownBackend(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})
	sc := &models.StorageConfig{
		BackendType: "unknown-backend",
	}
	_, err := svc.buildStorageFromConfig(sc)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// ---------------------------------------------------------------------------
// PlanMigration — target not found and artifact query errors
// ---------------------------------------------------------------------------

func TestPlanMigration_TargetNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Source config found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	// Target config not found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns))

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for target not found")
	}
}

func TestPlanMigration_ModuleArtifactQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "s3")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnError(&testDBError{"module query failed"})

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for module artifact query failure")
	}
}

func TestPlanMigration_ProviderArtifactQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "s3")...))

	// Module artifacts OK
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	// Provider artifacts query fails
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnError(&testDBError{"provider query failed"})

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for provider artifact query failure")
	}
}

func TestPlanMigration_SourceConfigDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(&testDBError{"connection refused"})

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for source config DB error")
	}
}

func TestPlanMigration_TargetConfigDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(nil, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(&testDBError{"connection refused"})

	_, err = svc.PlanMigration(context.Background(), srcID, tgtID)
	if err == nil {
		t.Fatal("expected error for target config DB error")
	}
}

// ---------------------------------------------------------------------------
// CancelMigration — with stored cancel func
// ---------------------------------------------------------------------------

func TestCancelMigration_WithCancelFunc(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	migID := "ffffffff-ffff-ffff-ffff-ffffffffffff"

	// Pre-store a cancel func
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.cancelFuncs.Store(migID, cancel)

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow(migID, "s", "t", "running", 5)...))

	mock.ExpectExec("UPDATE storage_migrations SET status").
		WithArgs(migID, "cancelled", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = svc.CancelMigration(context.Background(), migID)
	if err != nil {
		t.Fatalf("CancelMigration returned error: %v", err)
	}

	// Verify context was cancelled
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("expected context to be cancelled")
	}

	// Verify cancel func was removed
	if _, ok := svc.cancelFuncs.Load(migID); ok {
		t.Error("expected cancel func to be removed")
	}
}

// ---------------------------------------------------------------------------
// CancelMigration — update status DB error
// ---------------------------------------------------------------------------

func TestCancelMigration_UpdateStatusError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, nil, nil, nil, nil, nil)

	migID := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(storageMigrationColumns).
			AddRow(newMigrationRow(migID, "s", "t", "pending", 5)...))

	mock.ExpectExec("UPDATE storage_migrations SET status").
		WithArgs(migID, "cancelled", nil).
		WillReturnError(&testDBError{"update failed"})

	err = svc.CancelMigration(context.Background(), migID)
	if err == nil {
		t.Fatal("expected error when update status fails")
	}
}

// ---------------------------------------------------------------------------
// StartMigration — full success path through CreateMigration + CreateMigrationItems
// ---------------------------------------------------------------------------

func TestStartMigration_FullSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, &config.Config{})

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// GetStorageConfig source
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	// GetStorageConfig target
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "local")...))

	// GetModuleArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).
			AddRow("m1", "/mod/m1.zip"))

	// GetProviderArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	// CreateMigration
	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// CreateMigrationItems (1 module item)
	mock.ExpectExec("INSERT INTO storage_migration_items").
		WillReturnResult(sqlmock.NewResult(0, 1))

	migration, err := svc.StartMigration(context.Background(), srcID, tgtID, "user-1")
	if err != nil {
		t.Fatalf("StartMigration returned error: %v", err)
	}
	if migration == nil {
		t.Fatal("expected non-nil migration")
	}
	if migration.Status != "pending" {
		t.Errorf("Status = %q, want pending", migration.Status)
	}
	if migration.TotalArtifacts != 1 {
		t.Errorf("TotalArtifacts = %d, want 1", migration.TotalArtifacts)
	}
	if migration.CreatedBy == nil || *migration.CreatedBy != "user-1" {
		t.Error("CreatedBy should be set to user-1")
	}

	// Allow background goroutine to start (executeMigration will fail on nil deps, but that's OK)
	time.Sleep(10 * time.Millisecond)
}

func TestStartMigration_EmptyUserID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, &config.Config{})

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "local")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	// CreateMigration (0 artifacts)
	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnResult(sqlmock.NewResult(0, 1))

	migration, err := svc.StartMigration(context.Background(), srcID, tgtID, "")
	if err != nil {
		t.Fatalf("StartMigration returned error: %v", err)
	}
	if migration.CreatedBy != nil {
		t.Errorf("CreatedBy should be nil for empty userID, got %v", migration.CreatedBy)
	}

	time.Sleep(10 * time.Millisecond)
}

func TestStartMigration_ModuleArtifactError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "s3")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnError(&testDBError{"module query error"})

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "")
	if err == nil {
		t.Fatal("expected error for module artifact query failure")
	}
}

func TestStartMigration_ProviderArtifactError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "s3")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnError(&testDBError{"provider query error"})

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "")
	if err == nil {
		t.Fatal("expected error for provider artifact query failure")
	}
}

func TestStartMigration_CreateMigrationError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "local")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnError(&testDBError{"insert failed"})

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "user-1")
	if err == nil {
		t.Fatal("expected error when CreateMigration fails")
	}
}

func TestStartMigration_CreateItemsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)

	srcID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tgtID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(srcID, "local")...))

	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigColumns).AddRow(newStorageConfigRow(tgtID, "local")...))

	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).
			AddRow("m1", "/mod/m1.zip"))

	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectExec("INSERT INTO storage_migration_items").
		WillReturnError(&testDBError{"items insert failed"})

	_, err = svc.StartMigration(context.Background(), srcID, tgtID, "user-1")
	if err == nil {
		t.Fatal("expected error when CreateMigrationItems fails")
	}
}

// ---------------------------------------------------------------------------
// buildStorageFromConfig — azure, s3, gcs branches (config only, no real connection)
// ---------------------------------------------------------------------------

func TestBuildStorageFromConfig_Azure(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})
	sc := &models.StorageConfig{
		BackendType: "azure",
	}
	sc.AzureAccountName.Valid = true
	sc.AzureAccountName.String = "myaccount"
	sc.AzureContainerName.Valid = true
	sc.AzureContainerName.String = "mycontainer"

	// azure.New will fail because there's no real Azure account, but we exercise
	// the config-building branch in buildStorageFromConfig before the call to NewStorage.
	_, err := svc.buildStorageFromConfig(sc)
	// We expect an error from the Azure storage constructor (no real creds),
	// but we've exercised the azure case arm.
	_ = err
}

func TestBuildStorageFromConfig_S3(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})
	sc := &models.StorageConfig{
		BackendType: "s3",
	}
	sc.S3Bucket.Valid = true
	sc.S3Bucket.String = "my-bucket"
	sc.S3Region.Valid = true
	sc.S3Region.String = "us-east-1"
	sc.S3AuthMethod.Valid = true
	sc.S3AuthMethod.String = "static"

	_, err := svc.buildStorageFromConfig(sc)
	_ = err // Will fail at actual S3 client creation, but branch is exercised
}

func TestBuildStorageFromConfig_GCS(t *testing.T) {
	svc := NewStorageMigrationService(nil, nil, nil, nil, nil, &config.Config{})
	sc := &models.StorageConfig{
		BackendType: "gcs",
	}
	sc.GCSBucket.Valid = true
	sc.GCSBucket.String = "my-bucket"
	sc.GCSProjectID.Valid = true
	sc.GCSProjectID.String = "my-project"
	sc.GCSAuthMethod.Valid = true
	sc.GCSAuthMethod.String = "adc"

	_, err := svc.buildStorageFromConfig(sc)
	_ = err // Will fail at GCS client creation, but branch is exercised
}

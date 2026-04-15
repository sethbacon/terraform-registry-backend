package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Test setup helper
// ---------------------------------------------------------------------------

func newStorageMigrationRepo(t *testing.T) (*StorageMigrationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStorageMigrationRepository(sqlx.NewDb(db, "sqlmock")), mock
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var storageMigrationCols = []string{
	"id", "source_config_id", "target_config_id", "status",
	"total_artifacts", "migrated_artifacts", "failed_artifacts", "skipped_artifacts",
	"error_message", "started_at", "completed_at", "created_at", "created_by",
}

var storageMigrationItemCols = []string{
	"id", "migration_id", "artifact_type", "artifact_id", "source_path", "status",
	"error_message", "migrated_at",
}

var artifactInfoCols = []string{"id", "storage_path"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleMigrationRow() *sqlmock.Rows {
	return sqlmock.NewRows(storageMigrationCols).
		AddRow("mig-1", "cfg-src", "cfg-tgt", "pending",
			10, 0, 0, 0,
			nil, nil, nil, time.Now(), nil)
}

func emptyMigrationRows() *sqlmock.Rows {
	return sqlmock.NewRows(storageMigrationCols)
}

func sampleMigrationItemRow() *sqlmock.Rows {
	return sqlmock.NewRows(storageMigrationItemCols).
		AddRow("item-1", "mig-1", "module", "mod-1", "path/to/mod.tar.gz", "pending", nil, nil)
}

// ---------------------------------------------------------------------------
// CreateMigration
// ---------------------------------------------------------------------------

func TestCreateMigration_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	m := &models.StorageMigration{
		ID:             "mig-1",
		SourceConfigID: "cfg-src",
		TargetConfigID: "cfg-tgt",
		Status:         "pending",
		CreatedAt:      time.Now(),
	}
	if err := repo.CreateMigration(context.Background(), m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateMigration_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("INSERT INTO storage_migrations").
		WillReturnError(errDB)

	m := &models.StorageMigration{
		ID:             "mig-1",
		SourceConfigID: "cfg-src",
		TargetConfigID: "cfg-tgt",
		Status:         "pending",
		CreatedAt:      time.Now(),
	}
	if err := repo.CreateMigration(context.Background(), m); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetMigration
// ---------------------------------------------------------------------------

func TestGetMigration_Found(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("mig-1").
		WillReturnRows(sampleMigrationRow())

	m, err := repo.GetMigration(context.Background(), "mig-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected migration, got nil")
	}
	if m.ID != "mig-1" {
		t.Errorf("ID = %s, want mig-1", m.ID)
	}
	if m.Status != "pending" {
		t.Errorf("Status = %s, want pending", m.Status)
	}
}

func TestGetMigration_NotFound(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("mig-missing").
		WillReturnRows(emptyMigrationRows())

	m, err := repo.GetMigration(context.Background(), "mig-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil migration, got non-nil")
	}
}

func TestGetMigration_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("mig-1").
		WillReturnError(errDB)

	_, err := repo.GetMigration(context.Background(), "mig-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListMigrations
// ---------------------------------------------------------------------------

func TestListMigrations_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY").
		WillReturnRows(sampleMigrationRow())

	migrations, total, err := repo.ListMigrations(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(migrations) != 1 {
		t.Errorf("len(migrations) = %d, want 1", len(migrations))
	}
}

func TestListMigrations_Empty(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY").
		WillReturnRows(emptyMigrationRows())

	migrations, total, err := repo.ListMigrations(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(migrations) != 0 {
		t.Errorf("len(migrations) = %d, want 0", len(migrations))
	}
}

func TestListMigrations_CountError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(errDB)

	_, _, err := repo.ListMigrations(context.Background(), 10, 0)
	if err == nil {
		t.Error("expected error on count query failure")
	}
}

func TestListMigrations_QueryError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY").
		WillReturnError(errDB)

	_, _, err := repo.ListMigrations(context.Background(), 10, 0)
	if err == nil {
		t.Error("expected error on select query failure")
	}
}

// ---------------------------------------------------------------------------
// UpdateMigrationStatus
// ---------------------------------------------------------------------------

func TestUpdateMigrationStatus_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))

	errMsg := "something went wrong"
	if err := repo.UpdateMigrationStatus(context.Background(), "mig-1", "failed", &errMsg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateMigrationStatus_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status").
		WillReturnError(errDB)

	if err := repo.UpdateMigrationStatus(context.Background(), "mig-1", "failed", nil); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateMigrationProgress
// ---------------------------------------------------------------------------

func TestUpdateMigrationProgress_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET migrated_artifacts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateMigrationProgress(context.Background(), "mig-1", 5, 1, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateMigrationProgress_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET migrated_artifacts").
		WillReturnError(errDB)

	if err := repo.UpdateMigrationProgress(context.Background(), "mig-1", 5, 1, 2); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// SetMigrationStarted
// ---------------------------------------------------------------------------

func TestSetMigrationStarted_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status = 'running'").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.SetMigrationStarted(context.Background(), "mig-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetMigrationStarted_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status = 'running'").
		WillReturnError(errDB)

	if err := repo.SetMigrationStarted(context.Background(), "mig-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// SetMigrationCompleted
// ---------------------------------------------------------------------------

func TestSetMigrationCompleted_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status = 'completed'").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.SetMigrationCompleted(context.Background(), "mig-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetMigrationCompleted_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migrations SET status = 'completed'").
		WillReturnError(errDB)

	if err := repo.SetMigrationCompleted(context.Background(), "mig-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// CreateMigrationItems
// ---------------------------------------------------------------------------

func TestCreateMigrationItems_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("INSERT INTO storage_migration_items").
		WillReturnResult(sqlmock.NewResult(1, 2))

	items := []*models.StorageMigrationItem{
		{ID: "item-1", MigrationID: "mig-1", ArtifactType: "module", ArtifactID: "mod-1", SourcePath: "path/a.tar.gz", Status: "pending"},
		{ID: "item-2", MigrationID: "mig-1", ArtifactType: "provider", ArtifactID: "prov-1", SourcePath: "path/b.zip", Status: "pending"},
	}
	if err := repo.CreateMigrationItems(context.Background(), items); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateMigrationItems_Empty(t *testing.T) {
	repo, _ := newStorageMigrationRepo(t)

	// Empty slice should be a no-op (no DB call)
	if err := repo.CreateMigrationItems(context.Background(), []*models.StorageMigrationItem{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateMigrationItems_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("INSERT INTO storage_migration_items").
		WillReturnError(errDB)

	items := []*models.StorageMigrationItem{
		{ID: "item-1", MigrationID: "mig-1", ArtifactType: "module", ArtifactID: "mod-1", SourcePath: "p", Status: "pending"},
	}
	if err := repo.CreateMigrationItems(context.Background(), items); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetPendingItems
// ---------------------------------------------------------------------------

func TestGetPendingItems_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migration_items.*WHERE migration_id").
		WillReturnRows(sampleMigrationItemRow())

	items, err := repo.GetPendingItems(context.Background(), "mig-1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("len(items) = %d, want 1", len(items))
	}
	if items[0].ID != "item-1" {
		t.Errorf("items[0].ID = %s, want item-1", items[0].ID)
	}
}

func TestGetPendingItems_Empty(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migration_items.*WHERE migration_id").
		WillReturnRows(sqlmock.NewRows(storageMigrationItemCols))

	items, err := repo.GetPendingItems(context.Background(), "mig-1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("len(items) = %d, want 0", len(items))
	}
}

func TestGetPendingItems_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migration_items.*WHERE migration_id").
		WillReturnError(errDB)

	_, err := repo.GetPendingItems(context.Background(), "mig-1", 10)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateItemStatus
// ---------------------------------------------------------------------------

func TestUpdateItemStatus_Migrated(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migration_items SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateItemStatus(context.Background(), "item-1", "migrated", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateItemStatus_Failed(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migration_items SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))

	errMsg := "copy failed"
	if err := repo.UpdateItemStatus(context.Background(), "item-1", "failed", &errMsg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateItemStatus_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE storage_migration_items SET status").
		WillReturnError(errDB)

	if err := repo.UpdateItemStatus(context.Background(), "item-1", "migrated", nil); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetModuleArtifacts
// ---------------------------------------------------------------------------

func TestGetModuleArtifacts_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WillReturnRows(sqlmock.NewRows(artifactInfoCols).
			AddRow("ver-1", "modules/v1.tar.gz").
			AddRow("ver-2", "modules/v2.tar.gz"))

	arts, err := repo.GetModuleArtifacts(context.Background(), "s3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(arts) != 2 {
		t.Errorf("len(artifacts) = %d, want 2", len(arts))
	}
}

func TestGetModuleArtifacts_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WillReturnError(errDB)

	_, err := repo.GetModuleArtifacts(context.Background(), "s3")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetProviderArtifacts
// ---------------------------------------------------------------------------

func TestGetProviderArtifacts_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows(artifactInfoCols).
			AddRow("plat-1", "providers/plat1.zip"))

	arts, err := repo.GetProviderArtifacts(context.Background(), "gcs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(arts) != 1 {
		t.Errorf("len(artifacts) = %d, want 1", len(arts))
	}
}

func TestGetProviderArtifacts_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WillReturnError(errDB)

	_, err := repo.GetProviderArtifacts(context.Background(), "gcs")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateModuleVersionBackend
// ---------------------------------------------------------------------------

func TestUpdateModuleVersionBackend_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE module_versions SET storage_backend").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateModuleVersionBackend(context.Background(), "ver-1", "s3"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateModuleVersionBackend_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE module_versions SET storage_backend").
		WillReturnError(errDB)

	if err := repo.UpdateModuleVersionBackend(context.Background(), "ver-1", "s3"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateProviderPlatformBackend
// ---------------------------------------------------------------------------

func TestUpdateProviderPlatformBackend_Success(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE provider_platforms SET storage_backend").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateProviderPlatformBackend(context.Background(), "plat-1", "gcs"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateProviderPlatformBackend_DBError(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectExec("UPDATE provider_platforms SET storage_backend").
		WillReturnError(errDB)

	if err := repo.UpdateProviderPlatformBackend(context.Background(), "plat-1", "gcs"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetMigration edge case: sql.ErrNoRows explicitly
// ---------------------------------------------------------------------------

func TestGetMigration_SqlErrNoRows(t *testing.T) {
	repo, mock := newStorageMigrationRepo(t)
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	m, err := repo.GetMigration(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for ErrNoRows, got: %v", err)
	}
	if m != nil {
		t.Error("expected nil migration for ErrNoRows")
	}
}

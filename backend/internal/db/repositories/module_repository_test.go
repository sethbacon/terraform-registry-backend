package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var moduleCols = []string{
	"id", "organization_id", "namespace", "name", "system",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
}

var modVersionListCols = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "published_by_name", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

var modVersionGetCols = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

var modCreateCols = []string{"id", "created_at", "updated_at"}
var modVersionCreateCols = []string{"id", "created_at"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleModuleRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleCols).
		AddRow("mod-1", "org-1", "hashicorp", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil)
}

func emptyModuleRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleCols)
}

func sampleModVersionRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionGetCols).
		AddRow("ver-1", "mod-1", "1.0.0", "path/file.tar.gz", "default",
			int64(1024), "checksum", nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func sampleModVersionListRowsData() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionListCols).
		AddRow("ver-1", "mod-1", "1.0.0", "path/file.tar.gz", "default",
			int64(1024), "checksum", nil, nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func emptyModVersionRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionGetCols)
}

func emptyModVersionListRows() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionListCols)
}

func newModuleRepo(t *testing.T) (*ModuleRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewModuleRepository(db), mock
}

// ---------------------------------------------------------------------------
// GetModule
// ---------------------------------------------------------------------------

func TestGetModule_Found(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WillReturnRows(sampleModuleRow())

	m, err := repo.GetModule(context.Background(), "org-1", "hashicorp", "vpc", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected module, got nil")
	}
	if m.ID != "mod-1" {
		t.Errorf("ID = %s, want mod-1", m.ID)
	}
}

func TestGetModule_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WillReturnRows(emptyModuleRow())

	m, err := repo.GetModule(context.Background(), "org-1", "hashicorp", "vpc", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil module, got non-nil")
	}
}

func TestGetModule_DBError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WillReturnError(errDB)

	_, err := repo.GetModule(context.Background(), "org-1", "hashicorp", "vpc", "aws")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// CreateModule
// ---------------------------------------------------------------------------

func TestCreateModule_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("INSERT INTO modules").
		WillReturnRows(sqlmock.NewRows(modCreateCols).AddRow("mod-new", time.Now(), time.Now()))

	m := &models.Module{Namespace: "hashicorp", Name: "vpc", System: "aws"}
	if err := repo.CreateModule(context.Background(), m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ID != "mod-new" {
		t.Errorf("ID = %s, want mod-new", m.ID)
	}
}

func TestCreateModule_DBError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("INSERT INTO modules").
		WillReturnError(errDB)

	m := &models.Module{Namespace: "hashicorp", Name: "vpc", System: "aws"}
	if err := repo.CreateModule(context.Background(), m); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetVersion
// ---------------------------------------------------------------------------

func TestGetVersion_Found(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionRow())

	v, err := repo.GetVersion(context.Background(), "mod-1", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected version, got nil")
	}
	if v.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", v.Version)
	}
}

func TestGetVersion_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(emptyModVersionRow())

	v, err := repo.GetVersion(context.Background(), "mod-1", "9.9.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != nil {
		t.Error("expected nil version, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// ListVersions
// ---------------------------------------------------------------------------

func TestListVersions_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE mv.module_id").
		WillReturnRows(sampleModVersionListRowsData())

	versions, err := repo.ListVersions(context.Background(), "mod-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("len(versions) = %d, want 1", len(versions))
	}
}

func TestListVersions_Empty(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE mv.module_id").
		WillReturnRows(emptyModVersionListRows())

	versions, err := repo.ListVersions(context.Background(), "mod-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("len(versions) = %d, want 0", len(versions))
	}
}

func TestListVersions_DBError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE mv.module_id").
		WillReturnError(errDB)

	_, err := repo.ListVersions(context.Background(), "mod-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// CreateVersion
// ---------------------------------------------------------------------------

func TestCreateVersion_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("INSERT INTO module_versions").
		WillReturnRows(sqlmock.NewRows(modVersionCreateCols).AddRow("ver-new", time.Now()))

	v := &models.ModuleVersion{ModuleID: "mod-1", Version: "2.0.0", StoragePath: "path/v2.tar.gz"}
	if err := repo.CreateVersion(context.Background(), v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "ver-new" {
		t.Errorf("ID = %s, want ver-new", v.ID)
	}
}

// ---------------------------------------------------------------------------
// DeleteModule
// ---------------------------------------------------------------------------

func TestDeleteModule_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("DELETE FROM modules").
		WithArgs("mod-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteModule(context.Background(), "mod-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteModule_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("DELETE FROM modules").
		WithArgs("mod-missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteModule(context.Background(), "mod-missing"); err == nil {
		t.Error("expected error for not found, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion
// ---------------------------------------------------------------------------

func TestDeleteModuleVersion_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("DELETE FROM module_versions").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteVersion(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteModuleVersion_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("DELETE FROM module_versions").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteVersion(context.Background(), "ver-missing"); err == nil {
		t.Error("expected error for not found, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion
// ---------------------------------------------------------------------------

func TestDeprecateVersion_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE module_versions.*SET deprecated").
		WillReturnResult(sqlmock.NewResult(1, 1))

	msg := "outdated"
	if err := repo.DeprecateVersion(context.Background(), "ver-1", &msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeprecateVersion_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE module_versions.*SET deprecated").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeprecateVersion(context.Background(), "ver-missing", nil); err == nil {
		t.Error("expected error for not found, got nil")
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion
// ---------------------------------------------------------------------------

func TestUndeprecateVersion_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE module_versions.*SET deprecated = false").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UndeprecateVersion(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IncrementDownloadCount
// ---------------------------------------------------------------------------

func TestIncrementDownloadCount_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE module_versions.*SET download_count").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.IncrementDownloadCount(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateModule
// ---------------------------------------------------------------------------

func TestUpdateModule_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("UPDATE modules.*SET description").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	m := &models.Module{ID: "mod-1", Namespace: "hashicorp", Name: "vpc", System: "aws"}
	if err := repo.UpdateModule(context.Background(), m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// moduleSearchCols matches the SELECT column order in SearchModules (created_by_name is at pos 8)
var moduleSearchCols = []string{
	"id", "organization_id", "namespace", "name", "system",
	"description", "source", "created_by", "created_by_name", "created_at", "updated_at",
}

func sampleModuleSearchRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleSearchCols).
		AddRow("mod-1", "org-1", "hashicorp", "vpc", "aws", nil, nil, nil, nil, time.Now(), time.Now())
}

// ---------------------------------------------------------------------------
// SearchModules
// ---------------------------------------------------------------------------

func TestSearchModules_CountError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(errDB)

	_, _, err := repo.SearchModules(context.Background(), "", "vpc", "", "", 10, 0)
	if err == nil {
		t.Error("expected error on count query failure")
	}
}

func TestSearchModules_QueryError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	_, _, err := repo.SearchModules(context.Background(), "", "vpc", "", "", 10, 0)
	if err == nil {
		t.Error("expected error on search query failure")
	}
}

func TestSearchModules_Empty(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sqlmock.NewRows(moduleSearchCols))

	modules, total, err := repo.SearchModules(context.Background(), "", "", "", "", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(modules) != 0 {
		t.Errorf("len(modules) = %d, want 0", len(modules))
	}
}

func TestSearchModules_WithOrgAndFilters(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleSearchRow())

	modules, total, err := repo.SearchModules(context.Background(), "org-1", "vpc", "hashicorp", "aws", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(modules) != 1 {
		t.Errorf("len(modules) = %d, want 1", len(modules))
	}
}

// ---------------------------------------------------------------------------
// moduleCompareSemver — pure function, no DB interaction needed
// ---------------------------------------------------------------------------

func TestModuleCompareSemver_MajorGreater(t *testing.T) {
	if got := moduleCompareSemver("2.0.0", "1.9.9"); got != 1 {
		t.Errorf("got %d, want 1 (2.0.0 > 1.9.9)", got)
	}
}

func TestModuleCompareSemver_MajorLess(t *testing.T) {
	if got := moduleCompareSemver("1.0.0", "2.0.0"); got != -1 {
		t.Errorf("got %d, want -1 (1.0.0 < 2.0.0)", got)
	}
}

func TestModuleCompareSemver_MinorGreater(t *testing.T) {
	if got := moduleCompareSemver("1.2.0", "1.1.0"); got != 1 {
		t.Errorf("got %d, want 1 (1.2.0 > 1.1.0)", got)
	}
}

func TestModuleCompareSemver_MinorLess(t *testing.T) {
	if got := moduleCompareSemver("1.0.0", "1.1.0"); got != -1 {
		t.Errorf("got %d, want -1 (1.0.0 < 1.1.0)", got)
	}
}

func TestModuleCompareSemver_PatchGreater(t *testing.T) {
	if got := moduleCompareSemver("1.0.2", "1.0.1"); got != 1 {
		t.Errorf("got %d, want 1 (1.0.2 > 1.0.1)", got)
	}
}

func TestModuleCompareSemver_PatchLess(t *testing.T) {
	if got := moduleCompareSemver("1.0.0", "1.0.1"); got != -1 {
		t.Errorf("got %d, want -1 (1.0.0 < 1.0.1)", got)
	}
}

func TestModuleCompareSemver_Equal(t *testing.T) {
	if got := moduleCompareSemver("1.2.3", "1.2.3"); got != 0 {
		t.Errorf("got %d, want 0 (equal)", got)
	}
}

func TestModuleCompareSemver_PreReleaseStripped(t *testing.T) {
	// Pre-release suffix is stripped: 1.2.3-alpha == 1.2.3-beta
	if got := moduleCompareSemver("1.2.3-alpha", "1.2.3-beta"); got != 0 {
		t.Errorf("got %d, want 0 (pre-release stripped, numeric portions equal)", got)
	}
}

// ---------------------------------------------------------------------------
// moduleParseSemverParts — pure function, no DB interaction needed
// ---------------------------------------------------------------------------

func TestModuleParseSemverParts_Standard(t *testing.T) {
	got := moduleParseSemverParts("1.2.3")
	want := [3]int{1, 2, 3}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestModuleParseSemverParts_VPrefix(t *testing.T) {
	got := moduleParseSemverParts("v2.5.10")
	want := [3]int{2, 5, 10}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestModuleParseSemverParts_PreRelease(t *testing.T) {
	got := moduleParseSemverParts("1.3.0-rc.1")
	want := [3]int{1, 3, 0}
	if got != want {
		t.Errorf("pre-release suffix should be stripped: got %v, want %v", got, want)
	}
}

func TestModuleParseSemverParts_MajorOnly(t *testing.T) {
	got := moduleParseSemverParts("5")
	want := [3]int{5, 0, 0}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestModuleParseSemverParts_InvalidNonNumeric(t *testing.T) {
	// Non-numeric parts parse as 0
	got := moduleParseSemverParts("x.y.z")
	want := [3]int{0, 0, 0}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestModuleParseSemverParts_Zero(t *testing.T) {
	got := moduleParseSemverParts("0.0.0")
	want := [3]int{0, 0, 0}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

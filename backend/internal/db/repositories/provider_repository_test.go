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

var providerCols = []string{
	"id", "organization_id", "namespace", "type",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
}

var provVersionGetCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "deprecated", "deprecated_at", "deprecation_message", "created_at",
}

var provVersionListCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "published_by_name", "deprecated", "deprecated_at", "deprecation_message", "created_at",
}

var platformCols = []string{
	"id", "provider_version_id", "os", "arch",
	"filename", "storage_path", "storage_backend", "size_bytes", "shasum", "h1_hash", "download_count",
}

var provCreateCols = []string{"id", "created_at", "updated_at"}
var provVersionCreateCols = []string{"id", "created_at"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleProviderRow() *sqlmock.Rows {
	protocols := []byte(`["6.0"]`)
	_ = protocols // used below
	return sqlmock.NewRows(providerCols).
		AddRow("prov-1", nil, "hashicorp", "aws", nil, nil, nil, time.Now(), time.Now(), nil)
}

func emptyProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerCols)
}

func sampleProvVersionRow() *sqlmock.Rows {
	protocols := []byte(`["6.0"]`)
	return sqlmock.NewRows(provVersionGetCols).
		AddRow("ver-1", "prov-1", "5.0.0", protocols, "", "", "", nil, false, nil, nil, time.Now())
}

func emptyProvVersionRow() *sqlmock.Rows {
	return sqlmock.NewRows(provVersionGetCols)
}

func sampleProvVersionListRows() *sqlmock.Rows {
	protocols := []byte(`["6.0"]`)
	return sqlmock.NewRows(provVersionListCols).
		AddRow("ver-1", "prov-1", "5.0.0", protocols, "", "", "", nil, nil, false, nil, nil, time.Now())
}

func samplePlatformRow() *sqlmock.Rows {
	return sqlmock.NewRows(platformCols).
		AddRow("plat-1", "ver-1", "linux", "amd64", "file.zip", "path/to/file.zip", "default", int64(1024), "abc", nil, int64(0))
}

func emptyPlatformRows() *sqlmock.Rows {
	return sqlmock.NewRows(platformCols)
}

func newProviderRepo(t *testing.T) (*ProviderRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewProviderRepository(db), mock
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

func TestCreateProvider_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(provCreateCols).AddRow("prov-new", time.Now(), time.Now()))

	p := &models.Provider{Namespace: "hashicorp", Type: "aws"}
	if err := repo.CreateProvider(context.Background(), p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID != "prov-new" {
		t.Errorf("ID = %s, want prov-new", p.ID)
	}
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

func TestGetProvider_Found(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").
		WillReturnRows(sampleProviderRow())

	p, err := repo.GetProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
	if p.ID != "prov-1" {
		t.Errorf("ID = %s, want prov-1", p.ID)
	}
}

func TestGetProvider_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").
		WillReturnRows(emptyProviderRow())

	p, err := repo.GetProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestGetProvider_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").
		WillReturnError(errDB)

	_, err := repo.GetProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetProvider_QueryIncludesDeterministicOrdering(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("ORDER BY CASE WHEN p.organization_id = \\$1 THEN 0 ELSE 1 END").
		WillReturnRows(sampleProviderRow())

	_, err := repo.GetProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetProvider_ScansOrganizationIDWhenPresent(t *testing.T) {
	repo, mock := newProviderRepo(t)
	rows := sqlmock.NewRows(providerCols).
		AddRow("prov-2", "org-1", "hashicorp", "aws", nil, nil, nil, time.Now(), time.Now(), nil)
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").
		WillReturnRows(rows)

	p, err := repo.GetProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
	if p.OrganizationID != "org-1" {
		t.Errorf("OrganizationID = %q, want org-1", p.OrganizationID)
	}
}

// ---------------------------------------------------------------------------
// GetVersion
// ---------------------------------------------------------------------------

func TestGetProviderVersion_Found(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleProvVersionRow())

	v, err := repo.GetVersion(context.Background(), "prov-1", "5.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected version, got nil")
	}
	if v.Version != "5.0.0" {
		t.Errorf("Version = %s, want 5.0.0", v.Version)
	}
}

func TestGetProviderVersion_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(emptyProvVersionRow())

	v, err := repo.GetVersion(context.Background(), "prov-1", "9.9.9")
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

func TestListProviderVersions_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").
		WillReturnRows(sampleProvVersionListRows())

	versions, err := repo.ListVersions(context.Background(), "prov-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("len(versions) = %d, want 1", len(versions))
	}
}

func TestListProviderVersions_Empty(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").
		WillReturnRows(sqlmock.NewRows(provVersionListCols))

	versions, err := repo.ListVersions(context.Background(), "prov-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("len(versions) = %d, want 0", len(versions))
	}
}

// ---------------------------------------------------------------------------
// ListPlatforms
// ---------------------------------------------------------------------------

func TestListPlatforms_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	platforms, err := repo.ListPlatforms(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 1 {
		t.Errorf("len(platforms) = %d, want 1", len(platforms))
	}
}

func TestListPlatforms_Empty(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(emptyPlatformRows())

	platforms, err := repo.ListPlatforms(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 0 {
		t.Errorf("len(platforms) = %d, want 0", len(platforms))
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

func TestDeleteProvider_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM providers").
		WithArgs("prov-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteProvider(context.Background(), "prov-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteProvider_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM providers").
		WillReturnError(errDB)

	if err := repo.DeleteProvider(context.Background(), "prov-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion
// ---------------------------------------------------------------------------

func TestDeleteProviderVersion_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_versions").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteVersion(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion / UndeprecateVersion
// ---------------------------------------------------------------------------

func TestDeprecateProviderVersion_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = true").
		WillReturnResult(sqlmock.NewResult(1, 1))

	msg := "old version"
	if err := repo.DeprecateVersion(context.Background(), "ver-1", &msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUndeprecateProviderVersion_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = false").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UndeprecateVersion(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateVersion
// ---------------------------------------------------------------------------

func TestCreateProviderVersion_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(provVersionCreateCols).AddRow("ver-new", time.Now()))

	v := &models.ProviderVersion{ProviderID: "prov-1", Version: "6.0.0", Protocols: []string{"6.0"}}
	if err := repo.CreateVersion(context.Background(), v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "ver-new" {
		t.Errorf("ID = %s, want ver-new", v.ID)
	}
}

// ---------------------------------------------------------------------------
// CreatePlatform
// ---------------------------------------------------------------------------

func TestCreatePlatform_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("plat-new"))

	plat := &models.ProviderPlatform{
		ProviderVersionID: "ver-1", OS: "linux", Arch: "amd64",
		Filename: "file.zip", StoragePath: "path/file.zip", StorageBackend: "default",
	}
	if err := repo.CreatePlatform(context.Background(), plat); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plat.ID != "plat-new" {
		t.Errorf("ID = %s, want plat-new", plat.ID)
	}
}

// ---------------------------------------------------------------------------
// GetPlatform
// ---------------------------------------------------------------------------

func TestGetPlatform_Found(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id.*AND os.*AND arch").
		WillReturnRows(samplePlatformRow())

	plat, err := repo.GetPlatform(context.Background(), "ver-1", "linux", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plat == nil {
		t.Fatal("expected platform, got nil")
	}
}

func TestGetPlatform_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id.*AND os.*AND arch").
		WillReturnRows(emptyPlatformRows())

	plat, err := repo.GetPlatform(context.Background(), "ver-1", "windows", "arm64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plat != nil {
		t.Error("expected nil platform, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// IncrementDownloadCount / GetTotalDownloadCount / DeletePlatform
// ---------------------------------------------------------------------------

func TestIncrementProviderDownloadCount_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_platforms.*SET download_count").
		WithArgs("plat-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.IncrementDownloadCount(context.Background(), "plat-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetTotalDownloadCount_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COALESCE.*FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"total"}).AddRow(int64(42)))

	total, err := repo.GetTotalDownloadCount(context.Background(), "prov-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 42 {
		t.Errorf("total = %d, want 42", total)
	}
}

func TestDeletePlatform_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_platforms").
		WithArgs("plat-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeletePlatform(context.Background(), "plat-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseSemverParts / compareSemver pure function tests
// ---------------------------------------------------------------------------

func TestParseSemverParts_Basic(t *testing.T) {
	got := parseSemverParts("1.2.3")
	want := [3]int{1, 2, 3}
	if got != want {
		t.Errorf("parseSemverParts(1.2.3) = %v, want %v", got, want)
	}
}

func TestParseSemverParts_WithV(t *testing.T) {
	got := parseSemverParts("v2.5.0")
	want := [3]int{2, 5, 0}
	if got != want {
		t.Errorf("parseSemverParts(v2.5.0) = %v, want %v", got, want)
	}
}

func TestParseSemverParts_Prerelease(t *testing.T) {
	got := parseSemverParts("1.0.0-alpha")
	want := [3]int{1, 0, 0}
	if got != want {
		t.Errorf("parseSemverParts(1.0.0-alpha) = %v, want %v", got, want)
	}
}

func TestParseSemverParts_MajorOnly(t *testing.T) {
	got := parseSemverParts("3")
	want := [3]int{3, 0, 0}
	if got != want {
		t.Errorf("parseSemverParts(3) = %v, want %v", got, want)
	}
}

func TestCompareSemver_Equal(t *testing.T) {
	if got := compareSemver("1.2.3", "1.2.3"); got != 0 {
		t.Errorf("compareSemver(1.2.3, 1.2.3) = %d, want 0", got)
	}
}

func TestCompareSemver_ALessThanB(t *testing.T) {
	if got := compareSemver("1.0.0", "2.0.0"); got != -1 {
		t.Errorf("compareSemver(1.0.0, 2.0.0) = %d, want -1", got)
	}
}

func TestCompareSemver_AGreaterThanB(t *testing.T) {
	if got := compareSemver("2.1.0", "2.0.9"); got != 1 {
		t.Errorf("compareSemver(2.1.0, 2.0.9) = %d, want 1", got)
	}
}

func TestCompareSemver_PatchDifference(t *testing.T) {
	if got := compareSemver("1.2.3", "1.2.4"); got != -1 {
		t.Errorf("compareSemver(1.2.3, 1.2.4) = %d, want -1", got)
	}
}

// ---------------------------------------------------------------------------
// GetProviderByNamespaceType
// ---------------------------------------------------------------------------

// getProvByNSCols matches the SELECT in GetProviderByNamespaceType
var getProvByNSCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source", "created_at", "updated_at",
}

func sampleGetProvByNSRow() *sqlmock.Rows {
	return sqlmock.NewRows(getProvByNSCols).
		AddRow("prov-1", nil, "hashicorp", "aws", nil, nil, time.Now(), time.Now())
}

func TestGetProviderByNamespaceType_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sqlmock.NewRows(getProvByNSCols))

	p, err := repo.GetProviderByNamespaceType(context.Background(), "", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil, got %v", p)
	}
}

func TestGetProviderByNamespaceType_Found_WithOrg(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers WHERE organization_id").
		WillReturnRows(sampleGetProvByNSRow())

	p, err := repo.GetProviderByNamespaceType(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
	if p.Namespace != "hashicorp" {
		t.Errorf("namespace = %q, want hashicorp", p.Namespace)
	}
}

func TestGetProviderByNamespaceType_Found_NoOrg(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers WHERE namespace").
		WillReturnRows(sampleGetProvByNSRow())

	p, err := repo.GetProviderByNamespaceType(context.Background(), "", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestGetProviderByNamespaceType_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	_, err := repo.GetProviderByNamespaceType(context.Background(), "", "hashicorp", "aws")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// SearchProviders
// ---------------------------------------------------------------------------

// providerSearchCols matches the SELECT column order in SearchProviders
var providerSearchCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
}

func sampleProviderSearchRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerSearchCols).
		AddRow("prov-1", nil, "hashicorp", "aws", nil, nil, nil, nil, time.Now(), time.Now())
}

func TestSearchProviders_CountError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(errDB)

	_, _, err := repo.SearchProviders(context.Background(), "", "aws", "", 10, 0)
	if err == nil {
		t.Error("expected error on count query failure")
	}
}

func TestSearchProviders_QueryError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	_, _, err := repo.SearchProviders(context.Background(), "", "aws", "", 10, 0)
	if err == nil {
		t.Error("expected error on search query failure")
	}
}

func TestSearchProviders_Empty(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sqlmock.NewRows(providerSearchCols))

	providers, total, err := repo.SearchProviders(context.Background(), "", "", "", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 || len(providers) != 0 {
		t.Errorf("expected empty results, got total=%d, len=%d", total, len(providers))
	}
}

func TestSearchProviders_WithResults(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderSearchRow())

	providers, total, err := repo.SearchProviders(context.Background(), "org-1", "aws", "hashicorp", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(providers) != 1 {
		t.Errorf("expected 1 result, got total=%d, len=%d", total, len(providers))
	}
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

func TestUpdateProvider_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("UPDATE providers.*RETURNING updated_at").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	p := &models.Provider{ID: "prov-1", Description: func() *string { s := "desc"; return &s }()}
	if err := repo.UpdateProvider(context.Background(), p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateProvider_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("UPDATE providers.*RETURNING updated_at").
		WillReturnError(errDB)

	p := &models.Provider{ID: "prov-1"}
	if err := repo.UpdateProvider(context.Background(), p); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// SearchProvidersWithStats
// ---------------------------------------------------------------------------

// providerSearchWithStatsCols matches the SELECT column order in SearchProvidersWithStats
var providerSearchWithStatsCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
	"latest_version", "total_downloads",
}

// providerSearchWithStatsColsFTS includes the rank column returned when FTS is used.
var providerSearchWithStatsColsFTS = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
	"latest_version", "total_downloads",
	"rank",
}

func sampleProviderSearchWithStatsRow() *sqlmock.Rows {
	latestVer := "2.1.0"
	return sqlmock.NewRows(providerSearchWithStatsCols).
		AddRow("prov-1", "org-1", "hashicorp", "aws", nil, nil, nil, nil, time.Now(), time.Now(), &latestVer, int64(100))
}

func sampleProviderSearchWithStatsRowFTS() *sqlmock.Rows {
	latestVer := "2.1.0"
	return sqlmock.NewRows(providerSearchWithStatsColsFTS).
		AddRow("prov-1", "org-1", "hashicorp", "aws", nil, nil, nil, nil, time.Now(), time.Now(), &latestVer, int64(100), float64(0.5))
}

func TestSearchProvidersWithStats_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*LEFT JOIN LATERAL").
		WillReturnRows(sampleProviderSearchWithStatsRowFTS())

	results, total, err := repo.SearchProvidersWithStats(context.Background(), "org-1", "aws", "hashicorp", 10, 0, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].ID != "prov-1" {
		t.Errorf("ID = %s, want prov-1", results[0].ID)
	}
	if results[0].OrganizationID != "org-1" {
		t.Errorf("OrganizationID = %s, want org-1", results[0].OrganizationID)
	}
	if results[0].LatestVersion == nil || *results[0].LatestVersion != "2.1.0" {
		t.Errorf("LatestVersion = %v, want 2.1.0", results[0].LatestVersion)
	}
	if results[0].TotalDownloads != 100 {
		t.Errorf("TotalDownloads = %d, want 100", results[0].TotalDownloads)
	}
}

func TestSearchProvidersWithStats_Empty(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM providers.*LEFT JOIN LATERAL").
		WillReturnRows(sqlmock.NewRows(providerSearchWithStatsCols))

	results, total, err := repo.SearchProvidersWithStats(context.Background(), "", "", "", 10, 0, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 || len(results) != 0 {
		t.Errorf("expected empty results, got total=%d, len=%d", total, len(results))
	}
}

func TestSearchProvidersWithStats_CountError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(errDB)

	_, _, err := repo.SearchProvidersWithStats(context.Background(), "", "aws", "", 10, 0, "", "")
	if err == nil {
		t.Error("expected error on count query failure")
	}
}

func TestSearchProvidersWithStats_QueryError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*LEFT JOIN LATERAL").
		WillReturnError(errDB)

	_, _, err := repo.SearchProvidersWithStats(context.Background(), "", "aws", "", 10, 0, "", "")
	if err == nil {
		t.Error("expected error on search query failure")
	}
}

func TestSearchProvidersWithStats_NoOrgFilter(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*LEFT JOIN LATERAL").
		WillReturnRows(sampleProviderSearchWithStatsRowFTS())

	results, total, err := repo.SearchProvidersWithStats(context.Background(), "", "aws", "", 10, 0, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Errorf("expected 1 result, got total=%d, len=%d", total, len(results))
	}
}

func TestSearchProvidersWithStats_NullLatestVersion(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*LEFT JOIN LATERAL").
		WillReturnRows(sqlmock.NewRows(providerSearchWithStatsCols).
			AddRow("prov-2", nil, "hashicorp", "gcp", nil, nil, nil, nil, time.Now(), time.Now(), nil, int64(0)))

	results, total, err := repo.SearchProvidersWithStats(context.Background(), "", "", "", 10, 0, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("expected 1 result, got total=%d, len=%d", total, len(results))
	}
	if results[0].LatestVersion != nil {
		t.Errorf("LatestVersion = %v, want nil", results[0].LatestVersion)
	}
	if results[0].OrganizationID != "" {
		t.Errorf("OrganizationID = %q, want empty string", results[0].OrganizationID)
	}
}

// ---------------------------------------------------------------------------
// CreateProvider – additional error path
// ---------------------------------------------------------------------------

func TestCreateProvider_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnError(errDB)

	p := &models.Provider{Namespace: "hashicorp", Type: "aws"}
	if err := repo.CreateProvider(context.Background(), p); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestCreateProvider_EmptyOrgID(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(provCreateCols).AddRow("prov-new", time.Now(), time.Now()))

	p := &models.Provider{OrganizationID: "", Namespace: "hashicorp", Type: "aws"}
	if err := repo.CreateProvider(context.Background(), p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID != "prov-new" {
		t.Errorf("ID = %s, want prov-new", p.ID)
	}
}

// ---------------------------------------------------------------------------
// CreateVersion – additional error path
// ---------------------------------------------------------------------------

func TestCreateProviderVersion_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnError(errDB)

	v := &models.ProviderVersion{ProviderID: "prov-1", Version: "6.0.0", Protocols: []string{"6.0"}}
	if err := repo.CreateVersion(context.Background(), v); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetVersion – additional error path
// ---------------------------------------------------------------------------

func TestGetProviderVersion_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnError(errDB)

	_, err := repo.GetVersion(context.Background(), "prov-1", "5.0.0")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListVersions – additional error path
// ---------------------------------------------------------------------------

func TestListProviderVersions_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").
		WillReturnError(errDB)

	_, err := repo.ListVersions(context.Background(), "prov-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListPlatforms – additional error path
// ---------------------------------------------------------------------------

func TestListPlatforms_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnError(errDB)

	_, err := repo.ListPlatforms(context.Background(), "ver-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion – additional error paths
// ---------------------------------------------------------------------------

func TestDeleteProviderVersion_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_versions").
		WillReturnError(errDB)

	if err := repo.DeleteVersion(context.Background(), "ver-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestDeleteProviderVersion_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_versions").
		WithArgs("ver-missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeleteVersion(context.Background(), "ver-missing")
	if err == nil {
		t.Error("expected error for not found version, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion – additional error paths
// ---------------------------------------------------------------------------

func TestDeprecateProviderVersion_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = true").
		WillReturnError(errDB)

	msg := "old version"
	if err := repo.DeprecateVersion(context.Background(), "ver-1", &msg); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestDeprecateProviderVersion_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = true").
		WillReturnResult(sqlmock.NewResult(0, 0))

	msg := "old version"
	if err := repo.DeprecateVersion(context.Background(), "ver-missing", &msg); err == nil {
		t.Error("expected error for not found version, got nil")
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion – additional error paths
// ---------------------------------------------------------------------------

func TestUndeprecateProviderVersion_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = false").
		WillReturnError(errDB)

	if err := repo.UndeprecateVersion(context.Background(), "ver-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUndeprecateProviderVersion_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_versions.*SET deprecated = false").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.UndeprecateVersion(context.Background(), "ver-missing"); err == nil {
		t.Error("expected error for not found version, got nil")
	}
}

// ---------------------------------------------------------------------------
// CreatePlatform – additional error path
// ---------------------------------------------------------------------------

func TestCreatePlatform_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnError(errDB)

	plat := &models.ProviderPlatform{
		ProviderVersionID: "ver-1", OS: "linux", Arch: "amd64",
		Filename: "file.zip", StoragePath: "path/file.zip", StorageBackend: "default",
	}
	if err := repo.CreatePlatform(context.Background(), plat); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetPlatform – additional error path
// ---------------------------------------------------------------------------

func TestGetPlatform_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id.*AND os.*AND arch").
		WillReturnError(errDB)

	_, err := repo.GetPlatform(context.Background(), "ver-1", "linux", "amd64")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// IncrementDownloadCount – additional error path
// ---------------------------------------------------------------------------

func TestIncrementProviderDownloadCount_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("UPDATE provider_platforms.*SET download_count").
		WillReturnError(errDB)

	if err := repo.IncrementDownloadCount(context.Background(), "plat-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetTotalDownloadCount – additional error path
// ---------------------------------------------------------------------------

func TestGetTotalDownloadCount_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT COALESCE.*FROM provider_platforms").
		WillReturnError(errDB)

	_, err := repo.GetTotalDownloadCount(context.Background(), "prov-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeletePlatform – additional error paths
// ---------------------------------------------------------------------------

func TestDeletePlatform_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_platforms").
		WillReturnError(errDB)

	if err := repo.DeletePlatform(context.Background(), "plat-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestDeletePlatform_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM provider_platforms").
		WithArgs("plat-missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeletePlatform(context.Background(), "plat-missing")
	if err == nil {
		t.Error("expected error for not found platform, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider – additional error path (NotFound)
// ---------------------------------------------------------------------------

func TestDeleteProvider_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectExec("DELETE FROM providers").
		WithArgs("prov-missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeleteProvider(context.Background(), "prov-missing")
	if err == nil {
		t.Error("expected error for not found provider, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetProviderByID
// ---------------------------------------------------------------------------

func TestGetProviderByID_Found(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("prov-1").
		WillReturnRows(sampleProviderRow())

	p, err := repo.GetProviderByID(context.Background(), "prov-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
	if p.ID != "prov-1" {
		t.Errorf("ID = %q, want %q", p.ID, "prov-1")
	}
}

func TestGetProviderByID_NotFound(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("missing").
		WillReturnRows(emptyProviderRow())

	p, err := repo.GetProviderByID(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Error("expected nil for not-found provider")
	}
}

func TestGetProviderByID_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("prov-err").
		WillReturnError(errDB)

	_, err := repo.GetProviderByID(context.Background(), "prov-err")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListVersionsPaginated
// ---------------------------------------------------------------------------

func TestListVersionsPaginated_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("prov-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	protocols := []byte(`["6.0"]`)
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", 10, 0).
		WillReturnRows(sqlmock.NewRows(provVersionListCols).
			AddRow("ver-1", "prov-1", "1.0.0", protocols, "", "", "", nil, nil, false, nil, nil, time.Now()))

	versions, total, err := repo.ListVersionsPaginated(context.Background(), "prov-1", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(versions) != 1 {
		t.Errorf("len(versions) = %d, want 1", len(versions))
	}
}

func TestListVersionsPaginated_CountError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("prov-1").
		WillReturnError(errDB)

	_, _, err := repo.ListVersionsPaginated(context.Background(), "prov-1", 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListVersionsPaginated_QueryError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("prov-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WithArgs("prov-1", 10, 0).
		WillReturnError(errDB)

	_, _, err := repo.ListVersionsPaginated(context.Background(), "prov-1", 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpsertProviderVersionShasums
// ---------------------------------------------------------------------------

func TestUpsertProviderVersionShasums_Empty(t *testing.T) {
	repo, _ := newProviderRepo(t)

	// No expectations needed — empty map is a no-op
	err := repo.UpsertProviderVersionShasums(context.Background(), "ver-1", map[string]string{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpsertProviderVersionShasums_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO provider_version_shasums")
	mock.ExpectExec("INSERT INTO provider_version_shasums").
		WithArgs("ver-1", "terraform_1.0.0_linux_amd64.zip", "abc123").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := repo.UpsertProviderVersionShasums(context.Background(), "ver-1",
		map[string]string{"terraform_1.0.0_linux_amd64.zip": "abc123"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpsertProviderVersionShasums_BeginError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectBegin().WillReturnError(errDB)

	err := repo.UpsertProviderVersionShasums(context.Background(), "ver-1",
		map[string]string{"file.zip": "sha"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUpsertProviderVersionShasums_ExecError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO provider_version_shasums")
	mock.ExpectExec("INSERT INTO provider_version_shasums").
		WillReturnError(errDB)
	mock.ExpectRollback()

	err := repo.UpsertProviderVersionShasums(context.Background(), "ver-1",
		map[string]string{"file.zip": "sha"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListProviderVersionShasums
// ---------------------------------------------------------------------------

var shasumCols = []string{"provider_version_id", "filename", "sha256_hex"}

func TestListProviderVersionShasums_Success(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM provider_version_shasums").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows(shasumCols).
			AddRow("ver-1", "file.zip", "deadbeef"))

	items, err := repo.ListProviderVersionShasums(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("len = %d, want 1", len(items))
	}
}

func TestListProviderVersionShasums_Empty(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM provider_version_shasums").
		WithArgs("ver-1").
		WillReturnRows(sqlmock.NewRows(shasumCols))

	items, err := repo.ListProviderVersionShasums(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("len = %d, want 0", len(items))
	}
}

func TestListProviderVersionShasums_DBError(t *testing.T) {
	repo, mock := newProviderRepo(t)

	mock.ExpectQuery("SELECT.*FROM provider_version_shasums").
		WithArgs("ver-err").
		WillReturnError(errDB)

	_, err := repo.ListProviderVersionShasums(context.Background(), "ver-err")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpsertProvider
// ---------------------------------------------------------------------------

func TestUpsertProvider_ExistingProvider(t *testing.T) {
	repo, mock := newProviderRepo(t)
	// GetProvider returns existing — no INSERT
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("org-1", "hashicorp", "aws").
		WillReturnRows(sampleProviderRow())

	p, err := repo.UpsertProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestUpsertProvider_CreatesNew(t *testing.T) {
	repo, mock := newProviderRepo(t)
	// GetProvider returns nothing — then CreateProvider (uses RETURNING → Query)
	mock.ExpectQuery("SELECT.*FROM providers").
		WithArgs("org-1", "hashicorp", "aws").
		WillReturnRows(emptyProviderRow())
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(provCreateCols).AddRow("prov-new", time.Now(), time.Now()))

	p, err := repo.UpsertProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestUpsertProvider_LookupError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	_, err := repo.UpsertProvider(context.Background(), "org-1", "hashicorp", "aws")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpsertVersion
// ---------------------------------------------------------------------------

func TestUpsertVersion_ExistingVersion(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WithArgs("prov-1", "5.0.0").
		WillReturnRows(sampleProvVersionRow())

	v, err := repo.UpsertVersion(context.Background(), "prov-1", "5.0.0", nil, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil version")
	}
}

func TestUpsertVersion_CreatesNew(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WithArgs("prov-1", "5.0.0").
		WillReturnRows(emptyProvVersionRow())
	// CreateVersion uses RETURNING → Query
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(provVersionCreateCols).AddRow("ver-new", time.Now()))

	v, err := repo.UpsertVersion(context.Background(), "prov-1", "5.0.0", []string{"6.0"}, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil version")
	}
}

func TestUpsertVersion_LookupError(t *testing.T) {
	repo, mock := newProviderRepo(t)
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnError(errDB)

	_, err := repo.UpsertVersion(context.Background(), "prov-1", "5.0.0", nil, "", "", "")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

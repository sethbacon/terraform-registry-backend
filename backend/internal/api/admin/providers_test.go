package admin

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ---------------------------------------------------------------------------
// Mock storage backend
// ---------------------------------------------------------------------------

type mockStorage struct {
	deleteErr error
}

func (m *mockStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return &storage.UploadResult{}, nil
}
func (m *mockStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockStorage) Delete(_ context.Context, _ string) error { return m.deleteErr }
func (m *mockStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (m *mockStorage) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (m *mockStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Column definitions for provider SQL mocks
// ---------------------------------------------------------------------------

var orgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}

var providerCols = []string{
	"id", "organization_id", "namespace", "type",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
}

var versionCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "published_by_name", "deprecated", "deprecated_at",
	"deprecation_message", "created_at",
}

var platformCols = []string{
	"id", "provider_version_id", "os", "arch",
	"filename", "storage_path", "storage_backend", "size_bytes", "shasum", "h1_hash", "download_count",
}

var versionGetCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "deprecated", "deprecated_at",
	"deprecation_message", "created_at",
}

func sampleOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", "Default Org", nil, nil, time.Now(), time.Now())
}

func emptyOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols)
}

func sampleProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerCols).
		AddRow("prov-1", nil, "hashicorp", "aws", nil, nil, nil, time.Now(), time.Now(), nil)
}

func emptyProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerCols)
}

func emptyVersionRows() *sqlmock.Rows {
	return sqlmock.NewRows(versionCols)
}

func emptyVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(versionGetCols)
}

func sampleVersionRow() *sqlmock.Rows {
	protocols := []byte(`["6.0"]`)
	return sqlmock.NewRows(versionGetCols).
		AddRow("ver-1", "prov-1", "5.0.0", protocols, "", "", "", nil, false, nil, nil, time.Now())
}

func emptyPlatformRows() *sqlmock.Rows {
	return sqlmock.NewRows(platformCols)
}

// newProviderRouter creates a test gin router for provider admin handlers.
func newProviderRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewProviderAdminHandlers(db, &mockStorage{}, &config.Config{})

	r := gin.New()
	r.GET("/providers/:namespace/:type", h.GetProvider)
	r.DELETE("/providers/:namespace/:type", h.DeleteProvider)
	r.DELETE("/providers/:namespace/:type/versions/:version", h.DeleteVersion)
	r.POST("/providers/:namespace/:type/versions/:version/deprecate", h.DeprecateVersion)
	r.DELETE("/providers/:namespace/:type/versions/:version/deprecate", h.UndeprecateVersion)
	r.POST("/providers/record", h.CreateProviderRecord)
	r.GET("/providers/id/:id", h.GetProviderByID)
	r.PUT("/providers/id/:id", h.UpdateProviderRecord)

	return mock, r
}

// expectDefaultOrg sets up the mock to return an empty org (not found).
func expectNoDefaultOrg(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnRows(emptyOrgRow())
}

// expectOrgFound sets up the mock to return a found org.
func expectOrgFound(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())
}

// ---------------------------------------------------------------------------
// GetProvider tests
// ---------------------------------------------------------------------------

func TestGetProvider_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetProvider_ProviderNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetProvider_Success_NoVersions(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	// ListVersions returns empty
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(emptyVersionRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["id"] == nil {
		t.Error("response missing 'id' key")
	}
}

func TestGetProvider_ProviderDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetProvider_ListVersionsDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider tests
// ---------------------------------------------------------------------------

func TestDeleteProvider_NotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteProvider_Success_NoVersions(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	// ListVersions returns empty (no files to delete)
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(emptyVersionRows())
	// DeleteProvider
	mock.ExpectExec("DELETE FROM providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteProvider_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteProvider_ProviderDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteProvider_ListVersionsDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteProvider_DeleteDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(emptyVersionRows())
	mock.ExpectExec("DELETE FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteProvider_Success_WithVersionsAndPlatforms(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	// ListVersions returns one version
	protocols := []byte(`["6.0"]`)
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCols).
			AddRow("ver-1", "prov-1", "5.0.0", protocols, "", "", "", nil, nil, false, nil, nil, time.Now()))
	// ListPlatforms returns one platform with a non-empty StoragePath
	mock.ExpectQuery("SELECT.*FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformCols).
			AddRow("plat-1", "ver-1", "linux", "amd64",
				"terraform-provider-aws_5.0.0_linux_amd64.zip",
				"providers/hashicorp/aws/5.0.0/linux_amd64.zip",
				"local", 1024, "abc123", nil, 0))
	// DeleteProvider
	mock.ExpectExec("DELETE FROM providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion tests
// ---------------------------------------------------------------------------

func TestDeleteVersion_ProviderNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteVersion_VersionNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	// GetVersion returns not found
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(emptyVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteVersion_Success(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	// ListPlatforms (for storage cleanup)
	mock.ExpectQuery("SELECT.*FROM provider_platforms").
		WillReturnRows(emptyPlatformRows())
	// DeleteVersion
	mock.ExpectExec("DELETE FROM provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion tests
// ---------------------------------------------------------------------------

func TestDeprecateVersion_ProviderNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeprecateVersion_VersionNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(emptyVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeprecateVersion_Success(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "deprecated"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion tests
// ---------------------------------------------------------------------------

func TestUndeprecateVersion_VersionNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(emptyVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUndeprecateVersion_Success(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion — additional DB error branches
// ---------------------------------------------------------------------------

func TestDeleteVersion_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteVersion_ProviderDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteVersion_GetVersionDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteVersion_DeleteDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms").
		WillReturnRows(emptyPlatformRows())
	mock.ExpectExec("DELETE FROM provider_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion — additional DB error branches
// ---------------------------------------------------------------------------

func TestUndeprecateVersion_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateVersion_ProviderDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateVersion_GetVersionDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUndeprecateVersion_UndeprecateDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetProvider — additional uncovered branches
// ---------------------------------------------------------------------------

func TestGetProvider_OrgFound_Success_WithVersionsAndPlatforms(t *testing.T) {
	mock, r := newProviderRouter(t)

	// Org found (non-nil org)
	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	// ListVersions returns one version with deprecated fields set
	protocols := []byte(`["6.0"]`)
	deprecatedAt := time.Now()
	deprecationMsg := "use v6 instead"
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(sqlmock.NewRows(versionCols).
			AddRow("ver-1", "prov-1", "5.0.0", protocols, "", "", "", nil, nil, true, &deprecatedAt, &deprecationMsg, time.Now()))
	// ListPlatforms returns one platform
	mock.ExpectQuery("SELECT.*FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformCols).
			AddRow("plat-1", "ver-1", "linux", "amd64",
				"terraform-provider-aws_5.0.0_linux_amd64.zip",
				"providers/hashicorp/aws/5.0.0/linux_amd64.zip",
				"local", 1024, "abc123", nil, 5))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["versions"] == nil {
		t.Error("response missing 'versions' key")
	}
}

func TestGetProvider_OrgFound_ProviderNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion — additional DB error branches
// ---------------------------------------------------------------------------

func TestDeprecateVersion_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateVersion_ProviderDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateVersion_GetVersionDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestDeprecateVersion_DeprecateDBError(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestDeprecateVersion_EmptyBody(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Send empty body — req.Message will be ""
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion — platform cleanup with storage paths
// ---------------------------------------------------------------------------

func TestDeleteVersion_Success_WithPlatforms(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id").
		WillReturnRows(sampleVersionRow())
	// ListPlatforms returns one platform with non-empty StoragePath
	mock.ExpectQuery("SELECT.*FROM provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformCols).
			AddRow("plat-1", "ver-1", "linux", "amd64",
				"terraform-provider-aws_5.0.0_linux_amd64.zip",
				"providers/hashicorp/aws/5.0.0/linux_amd64.zip",
				"local", 1024, "abc123", nil, 0))
	// DeleteVersion
	mock.ExpectExec("DELETE FROM provider_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider — org found path
// ---------------------------------------------------------------------------

func TestDeleteProvider_OrgFound_Success(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions").
		WillReturnRows(emptyVersionRows())
	mock.ExpectExec("DELETE FROM providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion — provider not found
// ---------------------------------------------------------------------------

func TestUndeprecateVersion_ProviderNotFound(t *testing.T) {
	mock, r := newProviderRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(emptyProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/providers/hashicorp/aws/versions/5.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetProviderByID tests
// ---------------------------------------------------------------------------

func TestGetProviderByID_DBError(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-1").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/id/prov-1", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetProviderByID_NotFound(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-999").WillReturnRows(emptyProviderRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/id/prov-999", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetProviderByID_Success(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-1").WillReturnRows(sampleProviderRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/id/prov-1", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateProviderRecord tests
// ---------------------------------------------------------------------------

func TestUpdateProviderRecord_InvalidJSON(t *testing.T) {
	_, r := newProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/providers/id/prov-1", bytes.NewBufferString("{bad")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateProviderRecord_DBError(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-1").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/providers/id/prov-1",
		jsonBody(map[string]string{"description": "updated"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateProviderRecord_NotFound(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-999").WillReturnRows(emptyProviderRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/providers/id/prov-999",
		jsonBody(map[string]string{"description": "updated"})))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateProviderRecord_UpdateError(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-1").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/providers/id/prov-1",
		jsonBody(map[string]string{"description": "updated"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateProviderRecord_Success(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM providers").WithArgs("prov-1").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").WillReturnRows(
		sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/providers/id/prov-1",
		jsonBody(map[string]string{"description": "updated"})))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateProviderRecord tests
// ---------------------------------------------------------------------------

func TestCreateProviderRecord_InvalidJSON(t *testing.T) {
	_, r := newProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/record", bytes.NewBufferString("{bad")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateProviderRecord_OrgDBError(t *testing.T) {
	mock, r := newProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations").WithArgs("default").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/record",
		jsonBody(map[string]string{"namespace": "hashicorp", "type": "aws"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestCreateProviderRecord_AlreadyExists(t *testing.T) {
	mock, r := newProviderRouter(t)
	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").WillReturnRows(sampleProviderRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/record",
		jsonBody(map[string]string{"namespace": "hashicorp", "type": "aws"})))
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestCreateProviderRecord_CreateError(t *testing.T) {
	mock, r := newProviderRouter(t)
	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").WillReturnRows(emptyProviderRow())
	mock.ExpectQuery("INSERT INTO providers").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/record",
		jsonBody(map[string]string{"namespace": "hashicorp", "type": "aws"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestCreateProviderRecord_Success(t *testing.T) {
	mock, r := newProviderRouter(t)
	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM providers").WillReturnRows(emptyProviderRow())
	mock.ExpectQuery("INSERT INTO providers").WillReturnRows(
		sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow("prov-new", time.Now(), time.Now()))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/providers/record",
		jsonBody(map[string]string{"namespace": "hashicorp", "type": "aws"})))
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

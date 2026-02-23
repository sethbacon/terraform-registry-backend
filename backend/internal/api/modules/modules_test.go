package modules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Mock storage
// ---------------------------------------------------------------------------

type mockStore struct {
	getURLResult string
	getURLErr    error
	existsResult bool
	existsErr    error
	metadataErr  error
	downloadErr  error
}

func (m *mockStore) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return &storage.UploadResult{}, nil
}
func (m *mockStore) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	if m.downloadErr != nil {
		return nil, m.downloadErr
	}
	return io.NopCloser(bytes.NewReader([]byte("content"))), nil
}
func (m *mockStore) Delete(_ context.Context, _ string) error { return nil }
func (m *mockStore) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return m.getURLResult, m.getURLErr
}
func (m *mockStore) Exists(_ context.Context, _ string) (bool, error) {
	return m.existsResult, m.existsErr
}
func (m *mockStore) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	if m.metadataErr != nil {
		return nil, m.metadataErr
	}
	return &storage.FileMetadata{Path: "test.tgz", Size: 1234, Checksum: "abc"}, nil
}

var errDB2 = errors.New("db error")

// ---------------------------------------------------------------------------
// Column definitions (positional order must match Scan calls)
// ---------------------------------------------------------------------------

// GetByName / GetDefaultOrganization: id, name, display_name, created_at, updated_at
var orgCols2 = []string{"id", "name", "display_name", "created_at", "updated_at"}

// GetModule: id, org_id, namespace, name, system, description, source, created_by, created_at, updated_at, created_by_name
var moduleCols2 = []string{"id", "organization_id", "namespace", "name", "system", "description", "source", "created_by", "created_at", "updated_at", "created_by_name"}

// ListVersions: 18 cols (includes commit_sha, tag_name, scm_repo_id)
var moduleVersionListCols2 = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes", "checksum",
	"readme", "published_by", "published_by_name", "download_count", "deprecated",
	"deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

// GetVersion: 17 cols (no published_by_name, includes commit_sha, tag_name, scm_repo_id)
var moduleVersionGetCols2 = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes", "checksum",
	"readme", "published_by", "download_count", "deprecated",
	"deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

// SearchModulesWithStats result: id, org_id, namespace, name, system, description, source,
// created_by, created_by_name, created_at, updated_at, latest_version, total_downloads
var moduleSearchCols = []string{
	"id", "organization_id", "namespace", "name", "system", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
	"latest_version", "total_downloads",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleOrgRow2() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols2).
		AddRow("org-1", "default", "Default Org", time.Now(), time.Now())
}

func sampleModuleRow2() *sqlmock.Rows {
	return sqlmock.NewRows(moduleCols2).
		AddRow("mod-1", "org-1", "hashicorp", "consul", "aws",
			nil, "hashicorp/consul/aws", nil, time.Now(), time.Now(), nil)
}

func sampleModuleVersionsRows() *sqlmock.Rows {
	return sqlmock.NewRows(moduleVersionListCols2).
		AddRow("ver-1", "mod-1", "1.0.0", "modules/hashicorp/consul/aws/1.0.0.tgz", "local",
			1024, "abc123", nil, nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func sampleModuleVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleVersionGetCols2).
		AddRow("ver-1", "mod-1", "1.0.0", "modules/hashicorp/consul/aws/1.0.0.tgz", "local",
			1024, "abc123", nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func sampleModuleSearchRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleSearchCols).
		AddRow("mod-1", "org-1", "hashicorp", "consul", "aws",
			nil, "hashicorp/consul/aws", nil, nil, time.Now(), time.Now(),
			nil, int64(0))
}

// ---------------------------------------------------------------------------
// Router helpers
// ---------------------------------------------------------------------------

func newVersionsRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/modules/:namespace/:name/:system/versions", ListVersionsHandler(db, &config.Config{}))
	return mock, r
}

func newSearchRouter(t *testing.T, cfg *config.Config) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/modules/search", SearchHandler(db, cfg))
	return mock, r
}

func newDownloadRouter(t *testing.T, store *mockStore) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/modules/:namespace/:name/:system/:version/download", DownloadHandler(db, store, &config.Config{}))
	return mock, r
}

func newServeRouter(t *testing.T, store *mockStore) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.GET("/v1/files/*filepath", ServeFileHandler(store, &config.Config{}))
	return r
}

func doGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// ListVersionsHandler tests
// ---------------------------------------------------------------------------

func TestListVersionsHandler_Success(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE mv.module_id").WillReturnRows(sampleModuleVersionsRows())

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestListVersionsHandler_OrgError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_OrgNotFound(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sqlmock.NewRows(orgCols2))

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_ModuleError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_ModuleNotFound(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sqlmock.NewRows(moduleCols2))

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListVersionsHandler_VersionsError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SearchHandler tests
// ---------------------------------------------------------------------------

func TestSearchHandler_Success_SingleTenant(t *testing.T) {
	mock, r := newSearchRouter(t, &config.Config{})

	// No org query in single-tenant mode; SearchModulesWithStats emits 2 queries:
	// 1. COUNT, 2. LATERAL join search (no separate module_versions query)
	mock.ExpectQuery("SELECT COUNT.*FROM modules").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM modules.*ORDER BY").WillReturnRows(sampleModuleSearchRow())

	w := doGET(r, "/v1/modules/search?q=consul")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSearchHandler_Success_MultiTenant(t *testing.T) {
	cfg := &config.Config{}
	cfg.MultiTenancy.Enabled = true
	mock, r := newSearchRouter(t, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT COUNT.*FROM modules").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM modules.*ORDER BY").WillReturnRows(sqlmock.NewRows(moduleSearchCols))

	w := doGET(r, "/v1/modules/search")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSearchHandler_SearchError(t *testing.T) {
	mock, r := newSearchRouter(t, &config.Config{})

	mock.ExpectQuery("SELECT COUNT.*FROM modules").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/search")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSearchHandler_MultiTenant_OrgError(t *testing.T) {
	cfg := &config.Config{}
	cfg.MultiTenancy.Enabled = true
	mock, r := newSearchRouter(t, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/search")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DownloadHandler tests
// ---------------------------------------------------------------------------

func TestDownloadHandler_InvalidVersion(t *testing.T) {
	_, r := newDownloadRouter(t, &mockStore{})

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/notaversion/download")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDownloadHandler_OrgError(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/1.0.0/download")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDownloadHandler_ModuleNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sqlmock.NewRows(moduleCols2))

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/1.0.0/download")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDownloadHandler_VersionNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").WillReturnRows(sqlmock.NewRows(moduleVersionGetCols2))

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/1.0.0/download")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDownloadHandler_Success(t *testing.T) {
	store := &mockStore{getURLResult: "https://example.com/module.tgz"}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").WillReturnRows(sampleModuleVersionGetRow())

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/1.0.0/download")
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Terraform-Get") == "" {
		t.Error("expected X-Terraform-Get header")
	}
}

func TestDownloadHandler_StorageError(t *testing.T) {
	store := &mockStore{getURLErr: errors.New("storage error")}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").WillReturnRows(sampleModuleVersionGetRow())

	w := doGET(r, "/v1/modules/hashicorp/consul/aws/1.0.0/download")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ServeFileHandler tests
// ---------------------------------------------------------------------------

func TestServeFileHandler_SlashOnlyPath(t *testing.T) {
	// gin wildcard *filepath with path "/v1/files/" sets filepath="/"; after stripping leading slash
	// becomes empty string → Exists("") returns false → 404
	store := &mockStore{existsResult: false}
	r := newServeRouter(t, store)
	w := doGET(r, "/v1/files/")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestServeFileHandler_NotFound(t *testing.T) {
	store := &mockStore{existsResult: false}
	r := newServeRouter(t, store)

	w := doGET(r, "/v1/files/path/to/file.tgz")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestServeFileHandler_ExistsError(t *testing.T) {
	store := &mockStore{existsErr: errors.New("storage error")}
	r := newServeRouter(t, store)

	w := doGET(r, "/v1/files/path/to/file.tgz")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestServeFileHandler_MetadataError(t *testing.T) {
	store := &mockStore{existsResult: true, metadataErr: errors.New("metadata error")}
	r := newServeRouter(t, store)

	w := doGET(r, "/v1/files/path/to/file.tgz")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestServeFileHandler_Success(t *testing.T) {
	store := &mockStore{existsResult: true}
	r := newServeRouter(t, store)

	w := doGET(r, "/v1/files/path/to/file.tgz")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UploadHandler test helpers
// ---------------------------------------------------------------------------

// makeValidModuleTarGz builds an in-memory tar.gz containing a main.tf file
// so that validation.ValidateArchive accepts it.
func makeValidModuleTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	content := []byte(`resource "null_resource" "test" {}`)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "main.tf",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(content)
	tw.Close()
	gzw.Close()
	return buf.Bytes()
}

// buildModuleUploadRequest constructs a multipart/form-data POST request.
func buildModuleUploadRequest(t *testing.T, path string, fields map[string]string, fileData []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if fileData != nil {
		fw, _ := mw.CreateFormFile("file", "module.tar.gz")
		_, _ = fw.Write(fileData)
	}
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// Column sets for INSERT … RETURNING queries.
var moduleInsertCols2 = []string{"id", "created_at", "updated_at"}
var moduleVersionInsertCols2 = []string{"id", "created_at"}
var moduleUpdateCols2 = []string{"updated_at"}

func newModuleUploadRouter(t *testing.T, store storage.Storage) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.POST("/api/v1/modules", UploadHandler(db, store, &config.Config{}))
	return mock, r
}

func doPOSTReq(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// UploadHandler tests
// ---------------------------------------------------------------------------

func TestUploadHandler_MissingRequiredFields(t *testing.T) {
	_, r := newModuleUploadRouter(t, &mockStore{})

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		// name, system, version missing
	}, nil)
	w := doPOSTReq(r, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_InvalidVersion(t *testing.T) {
	_, r := newModuleUploadRouter(t, &mockStore{})

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "not-semver",
	}, nil)
	w := doPOSTReq(r, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_MissingFile(t *testing.T) {
	_, r := newModuleUploadRouter(t, &mockStore{})

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, nil) // no file
	w := doPOSTReq(r, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_InvalidArchive(t *testing.T) {
	_, r := newModuleUploadRouter(t, &mockStore{})

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, []byte("not-a-tar-gz"))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_OrgError(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnError(errDB2)

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_OrgNotFound(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sqlmock.NewRows(orgCols2))

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_ModuleQueryError(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow2())
	// UpsertModule (INSERT … ON CONFLICT) fails
	mock.ExpectQuery("INSERT INTO modules").WillReturnError(errDB2)

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_VersionConflict(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow2())
	// UpsertModule: INSERT … ON CONFLICT … RETURNING — module already exists, returns its ID
	mock.ExpectQuery("INSERT INTO modules").WillReturnRows(
		sqlmock.NewRows(moduleInsertCols2).AddRow("mod-1", time.Now(), time.Now()),
	)
	// GetVersion: existing version found → conflict
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").
		WillReturnRows(sampleModuleVersionGetRow())

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "1.0.0",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_Success_NewModule(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow2())
	// UpsertModule INSERT … ON CONFLICT … RETURNING id, created_at, updated_at
	mock.ExpectQuery("INSERT INTO modules").WillReturnRows(
		sqlmock.NewRows(moduleInsertCols2).AddRow("mod-new", time.Now(), time.Now()),
	)
	// UpdateModule: description and source are provided in this test
	mock.ExpectQuery("UPDATE modules").WillReturnRows(
		sqlmock.NewRows(moduleUpdateCols2).AddRow(time.Now()),
	)
	// GetVersion → not found (no conflict)
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").
		WillReturnRows(sqlmock.NewRows(moduleVersionGetCols2))
	// CreateVersion INSERT RETURNING id, created_at
	mock.ExpectQuery("INSERT INTO module_versions").WillReturnRows(
		sqlmock.NewRows(moduleVersionInsertCols2).AddRow("ver-new", time.Now()),
	)

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace":   "hashicorp",
		"name":        "consul",
		"system":      "aws",
		"version":     "1.0.0",
		"description": "A test module",
		"source":      "https://github.com/hashicorp/consul",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_Success_ExistingModule(t *testing.T) {
	mock, r := newModuleUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow2())
	// UpsertModule INSERT … ON CONFLICT … returns existing module ID; no description/source
	// in this request so UpdateModule is NOT called
	mock.ExpectQuery("INSERT INTO modules").WillReturnRows(
		sqlmock.NewRows(moduleInsertCols2).AddRow("mod-1", time.Now(), time.Now()),
	)
	// GetVersion → not found
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id.*AND version").
		WillReturnRows(sqlmock.NewRows(moduleVersionGetCols2))
	// CreateVersion
	mock.ExpectQuery("INSERT INTO module_versions").WillReturnRows(
		sqlmock.NewRows(moduleVersionInsertCols2).AddRow("ver-new2", time.Now()),
	)

	req := buildModuleUploadRequest(t, "/api/v1/modules", map[string]string{
		"namespace": "hashicorp",
		"name":      "consul",
		"system":    "aws",
		"version":   "2.0.0",
	}, makeValidModuleTarGz(t))
	w := doPOSTReq(r, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
}

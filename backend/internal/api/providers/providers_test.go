package providers

import (
	"archive/zip"
	"bytes"
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
}

func (m *mockStore) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return &storage.UploadResult{}, nil
}
func (m *mockStore) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (m *mockStore) Delete(_ context.Context, _ string) error { return nil }
func (m *mockStore) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return m.getURLResult, m.getURLErr
}
func (m *mockStore) Exists(_ context.Context, _ string) (bool, error) { return true, nil }
func (m *mockStore) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return &storage.FileMetadata{}, nil
}

var errDB2 = errors.New("db error")

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

// GetByName / GetDefaultOrganization: id, name, display_name, created_at, updated_at
var orgCols = []string{"id", "name", "display_name", "created_at", "updated_at"}

// GetProvider: id, org_id, namespace, type, description, source, created_by, created_at, updated_at, created_by_name
var providerCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
}

// ListVersions (provider): id, provider_id, version, protocols_json, gpg_key, shasums_url, shasums_sig_url, published_by, published_by_name, deprecated, deprecated_at, deprecation_message, created_at
var providerVersionListCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url", "published_by", "published_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// GetVersion (provider): 12 cols - no published_by_name
var providerVersionGetCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url", "published_by",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// GetPlatform: id, provider_version_id, os, arch, filename, storage_path, storage_backend, size_bytes, shasum, download_count
var platformCols = []string{
	"id", "provider_version_id", "os", "arch", "filename",
	"storage_path", "storage_backend", "size_bytes", "shasum", "download_count",
}

// SearchProviders: id, org_id, namespace, type, description, source, created_by, created_by_name, created_at, updated_at
var providerSearchCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
}

var sampleProtocolsJSON = []byte(`["6.0"]`)

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", "Default Org", time.Now(), time.Now())
}

func sampleProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerCols).
		AddRow("prov-1", nil, "hashicorp", "aws",
			nil, "hashicorp/provider-aws", nil, time.Now(), time.Now(), nil)
}

func sampleProviderVersionListRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerVersionListCols).
		AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
			"", "", nil, nil,
			false, nil, nil, time.Now())
}

func sampleProviderVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerVersionGetCols).
		AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
			"", "", nil,
			false, nil, nil, time.Now())
}

func samplePlatformRow() *sqlmock.Rows {
	return sqlmock.NewRows(platformCols).
		AddRow("plat-1", "ver-1", "linux", "amd64",
			"terraform-provider-aws_4.0.0_linux_amd64.zip",
			"providers/hashicorp/aws/4.0.0/terraform-provider-aws_linux_amd64.zip",
			"local", int64(1024000), "sha256abc", int64(0))
}

func sampleProviderSearchRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerSearchCols).
		AddRow("prov-1", nil, "hashicorp", "aws",
			nil, "hashicorp/provider-aws",
			nil, nil, time.Now(), time.Now())
}

// ---------------------------------------------------------------------------
// Router helpers
// ---------------------------------------------------------------------------

func newVersionsRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/providers/:namespace/:type/versions", ListVersionsHandler(db, &config.Config{}))
	return mock, r
}

func newSearchRouter(t *testing.T, cfg *config.Config) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/providers/search", SearchHandler(db, cfg))
	return mock, r
}

func newDownloadRouter(t *testing.T, store *mockStore) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/v1/providers/:namespace/:type/:version/download/:os/:arch", DownloadHandler(db, store, &config.Config{}))
	return mock, r
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

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").WillReturnRows(sampleProviderVersionListRow())
	// ListVersionsHandler also calls ListPlatforms for each version
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestListVersionsHandler_OrgError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_OrgNotFound(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sqlmock.NewRows(orgCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_ProviderError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListVersionsHandler_ProviderNotFound(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListVersionsHandler_VersionsError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SearchHandler tests
// ---------------------------------------------------------------------------

func TestSearchHandler_Success_SingleTenant(t *testing.T) {
	mock, r := newSearchRouter(t, &config.Config{})

	// No org query in single-tenant mode
	mock.ExpectQuery("SELECT COUNT.*FROM providers").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*ORDER BY").WillReturnRows(sampleProviderSearchRow())

	w := doGET(r, "/v1/providers/search?q=aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSearchHandler_Success_MultiTenant(t *testing.T) {
	cfg := &config.Config{}
	cfg.MultiTenancy.Enabled = true
	mock, r := newSearchRouter(t, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM providers").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM providers.*ORDER BY").WillReturnRows(sqlmock.NewRows(providerSearchCols))

	w := doGET(r, "/v1/providers/search")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSearchHandler_SearchError(t *testing.T) {
	mock, r := newSearchRouter(t, &config.Config{})

	mock.ExpectQuery("SELECT COUNT.*FROM providers").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/search")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSearchHandler_MultiTenant_OrgNotFound(t *testing.T) {
	cfg := &config.Config{}
	cfg.MultiTenancy.Enabled = true
	mock, r := newSearchRouter(t, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sqlmock.NewRows(orgCols))

	w := doGET(r, "/v1/providers/search")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DownloadHandler tests
// ---------------------------------------------------------------------------

func TestDownloadHandler_InvalidVersion(t *testing.T) {
	_, r := newDownloadRouter(t, &mockStore{})

	w := doGET(r, "/v1/providers/hashicorp/aws/notaversion/download/linux/amd64")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDownloadHandler_InvalidPlatform(t *testing.T) {
	_, r := newDownloadRouter(t, &mockStore{})

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/invalid-os/bad-arch")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDownloadHandler_OrgError(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDownloadHandler_ProviderNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDownloadHandler_VersionNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sqlmock.NewRows(providerVersionGetCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDownloadHandler_PlatformNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(sqlmock.NewRows(platformCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDownloadHandler_Success(t *testing.T) {
	store := &mockStore{getURLResult: "https://example.com/provider.zip"}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestDownloadHandler_StorageError(t *testing.T) {
	store := &mockStore{getURLErr: errors.New("storage error")}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UploadHandler helpers
// ---------------------------------------------------------------------------

// makeValidZIP creates a minimal valid ZIP file in memory.
func makeValidZIP(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("terraform-provider-test_v1.0.0_linux_amd64")
	if err != nil {
		t.Fatalf("zip.Create: %v", err)
	}
	w.Write([]byte("provider binary content"))
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// buildUploadRequest constructs a multipart/form-data POST request for the UploadHandler.
// fields maps form field names to values; if fileData is non-nil it is included as "file".
func buildUploadRequest(t *testing.T, path string, fields map[string]string, fileData []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %q: %v", k, err)
		}
	}
	if fileData != nil {
		fw, err := mw.CreateFormFile("file", "provider.zip")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		fw.Write(fileData)
	}
	mw.Close()
	req, err := http.NewRequest(http.MethodPost, path, &body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func newUploadRouter(t *testing.T, store *mockStore) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.POST("/v1/providers", UploadHandler(db, store, &config.Config{}))
	return mock, r
}

// RETURNING column helpers for INSERT…RETURNING queries
var providerInsertCols = []string{"id", "created_at", "updated_at"}
var providerVersionInsertCols = []string{"id", "created_at"}
var platformInsertCols = []string{"id"}

// ---------------------------------------------------------------------------
// UploadHandler tests — early-exit paths (no SQL mocking needed)
// ---------------------------------------------------------------------------

func TestUploadHandler_MissingRequiredFields(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	// No fields → 400 (missing namespace, type, version, os, arch)
	req := buildUploadRequest(t, "/v1/providers", map[string]string{}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing required fields)", w.Code)
	}
}

func TestUploadHandler_InvalidVersion(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "not-semver",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid semver)", w.Code)
	}
}

func TestUploadHandler_InvalidPlatform(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "beos",   // invalid
		"arch":      "mips64", // invalid
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid platform)", w.Code)
	}
}

func TestUploadHandler_InvalidProtocolsJSON(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
		"protocols": "not-json",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid protocols JSON)", w.Code)
	}
}

func TestUploadHandler_MissingFile(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, nil) // no file
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing file)", w.Code)
	}
}

func TestUploadHandler_InvalidBinary(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, []byte("not-a-zip"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid binary)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UploadHandler — SQL error paths
// ---------------------------------------------------------------------------

func TestUploadHandler_OrgError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnError(errDB2)

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (org error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_OrgNotFound(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sqlmock.NewRows(orgCols))

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (org not found): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_ProviderError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnError(errDB2)

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (provider query error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UploadHandler — success path (new provider + new version + new platform)
// ---------------------------------------------------------------------------

func TestUploadHandler_Success_NewProviderVersionPlatform(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	// 1. GetDefaultOrganization
	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	// 2. GetProvider → not found
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	// 3. CreateProvider → INSERT RETURNING id, created_at, updated_at
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	// 4. GetVersion → not found
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	// 5. CreateVersion → INSERT RETURNING id, created_at
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	// 6. GetPlatform → not found
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	// 7. CreatePlatform → INSERT RETURNING id
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (upload success): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_PlatformConflict(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	// 1. GetDefaultOrganization
	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	// 2. GetProvider → not found → create
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-1", time.Now(), time.Now()))
	// 3. GetVersion → found
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sampleProviderVersionGetRow())
	// 4. GetPlatform → found (conflict!)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (platform conflict): body=%s", w.Code, w.Body.String())
	}
}

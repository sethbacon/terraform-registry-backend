package providers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// assertErrorsArrayBody fails the test unless the response body is shaped
// {"errors": [...]}, the protocol-correct shape already used by the 4xx
// paths of these same handlers. Issue #696: 500 paths must not fall back to
// a singular {"error": "..."} string.
func assertErrorsArrayBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response body: %v; body=%s", err, w.Body.String())
	}
	if _, ok := body["error"]; ok {
		t.Errorf(`response body uses singular "error" key, want "errors" array; body=%s`, w.Body.String())
	}
	errs, ok := body["errors"].([]interface{})
	if !ok || len(errs) == 0 {
		t.Errorf(`response body missing "errors" array; body=%s`, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Mock storage
// ---------------------------------------------------------------------------

type mockStore struct {
	getURLResult string
	getURLErr    error
	uploadErr    error
	uploadResult *storage.UploadResult
	deleteErr    error
	// uploadFailSuffix, when non-empty, makes Upload fail (with uploadErr, or
	// a generic error if unset) only for paths ending in this suffix —
	// letting a test simulate one file of a multi-file upload sequence
	// failing after an earlier one already succeeded, without affecting the
	// other tests that rely on the unconditional uploadErr.
	uploadFailSuffix string
	// deletedPaths records every path passed to Delete, so tests can assert
	// that a partial-failure cleanup happened (issue #685).
	deletedPaths []string
}

func (m *mockStore) Upload(_ context.Context, path string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	if m.uploadFailSuffix != "" && strings.HasSuffix(path, m.uploadFailSuffix) {
		if m.uploadErr != nil {
			return nil, m.uploadErr
		}
		return nil, errors.New("mock upload failure")
	}
	if m.uploadErr != nil {
		return nil, m.uploadErr
	}
	if m.uploadResult != nil {
		return m.uploadResult, nil
	}
	return &storage.UploadResult{Path: "providers/test/path.zip", Size: 1024}, nil
}
func (m *mockStore) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (m *mockStore) Delete(_ context.Context, path string) error {
	m.deletedPaths = append(m.deletedPaths, path)
	return m.deleteErr
}
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
var orgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}

// GetProvider: id, org_id, namespace, type, description, source, created_by, created_at, updated_at, created_by_name
var providerCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
}

// ListVersions (provider): id, provider_id, version, protocols_json, gpg_key,
// shasums_url, shasums_sig_url, shasum_storage_key, shasum_signature_storage_key,
// published_by, published_by_name, deprecated, deprecated_at, deprecation_message, created_at
var providerVersionListCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url",
	"shasum_storage_key", "shasum_signature_storage_key",
	"published_by", "published_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// GetVersion (provider): no published_by_name; otherwise same column set
var providerVersionGetCols = []string{
	"id", "provider_id", "version", "protocols", "gpg_public_key",
	"shasums_url", "shasums_signature_url",
	"shasum_storage_key", "shasum_signature_storage_key",
	"published_by",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// GetPlatform: id, provider_version_id, os, arch, filename, storage_path, storage_backend, size_bytes, shasum, h1_hash, download_count
var platformCols = []string{
	"id", "provider_version_id", "os", "arch", "filename",
	"storage_path", "storage_backend", "size_bytes", "shasum", "h1_hash", "download_count",
}

// SearchProvidersWithStats result: id, org_id, namespace, type, description, source,
// created_by, created_by_name, created_at, updated_at, latest_version, total_downloads
var providerSearchCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
	"latest_version", "total_downloads",
}

// providerSearchColsFTS adds the rank column for FTS queries (searchQuery >= 3 chars).
var providerSearchColsFTS = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_by_name", "created_at", "updated_at",
	"latest_version", "total_downloads",
	"rank",
}

var sampleProtocolsJSON = []byte(`["6.0"]`)

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", "Default Org", nil, nil, time.Now(), time.Now())
}

func sampleProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerCols).
		AddRow("prov-1", nil, "hashicorp", "aws",
			nil, "hashicorp/provider-aws", nil, time.Now(), time.Now(), nil)
}

func sampleProviderVersionListRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerVersionListCols).
		AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
			"", "",
			nil, nil, // shasum_storage_key, shasum_signature_storage_key
			nil, nil, // published_by, published_by_name
			false, nil, nil, time.Now())
}

func sampleProviderVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(providerVersionGetCols).
		AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
			"", "",
			nil, nil, // shasum_storage_key, shasum_signature_storage_key
			nil, // published_by
			false, nil, nil, time.Now())
}

func samplePlatformRow() *sqlmock.Rows {
	return sqlmock.NewRows(platformCols).
		AddRow("plat-1", "ver-1", "linux", "amd64",
			"terraform-provider-aws_4.0.0_linux_amd64.zip",
			"providers/hashicorp/aws/4.0.0/terraform-provider-aws_linux_amd64.zip",
			"local", int64(1024000), "sha256abc", nil, int64(0))
}

func sampleProviderSearchRowFTS() *sqlmock.Rows {
	return sqlmock.NewRows(providerSearchColsFTS).
		AddRow("prov-1", nil, "hashicorp", "aws",
			nil, "hashicorp/provider-aws",
			nil, nil, time.Now(), time.Now(),
			nil, int64(0), float64(0.5))
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
	r.GET("/v1/providers/:namespace/:type/:version/download/:os/:arch", DownloadHandler(db, store, &config.Config{}, nil))
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
	// ListVersionsPaginated — COUNT query
	mock.ExpectQuery("SELECT COUNT.*FROM provider_versions").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	// ListVersionsPaginated — data query with LIMIT/OFFSET
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
	assertErrorsArrayBody(t, w)
}

func TestListVersionsHandler_OrgNotFound(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sqlmock.NewRows(orgCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	assertErrorsArrayBody(t, w)
}

func TestListVersionsHandler_ProviderError(t *testing.T) {
	mock, r := newVersionsRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/versions")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	assertErrorsArrayBody(t, w)
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
	assertErrorsArrayBody(t, w)
}

// ---------------------------------------------------------------------------
// SearchHandler tests
// ---------------------------------------------------------------------------

func TestSearchHandler_Success_SingleTenant(t *testing.T) {
	mock, r := newSearchRouter(t, &config.Config{})

	// No org query in single-tenant mode
	// "aws" is >= 3 chars so FTS mode adds rank column
	mock.ExpectQuery("SELECT COUNT.*FROM providers").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM providers.*ORDER BY").WillReturnRows(sampleProviderSearchRowFTS())

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
	assertErrorsArrayBody(t, w)
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
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
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
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestDownloadHandler_PendingApprovalHidden verifies the approval gate: a
// mirrored version still pending approval is not downloadable by direct version
// reference and returns 404 (same as a missing version), before any platform
// lookup or storage URL generation.
func TestDownloadHandler_PendingApprovalHidden(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow("pending_approval"))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (pending version must be hidden)", w.Code)
	}
}

// TestDownloadHandler_RejectedHidden verifies a rejected mirrored version is
// likewise not downloadable.
func TestDownloadHandler_RejectedHidden(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow("rejected"))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (rejected version must be hidden)", w.Code)
	}
}

func TestDownloadHandler_StorageError(t *testing.T) {
	store := &mockStore{getURLErr: errors.New("storage error")}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	assertErrorsArrayBody(t, w)
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
	return buildUploadRequestWithFiles(t, path, fields, fileData, nil)
}

// buildUploadRequestWithFiles is buildUploadRequest with extra named file
// uploads (e.g. shasums_file, shasums_signature_file). A nil/empty map omits
// the extra files entirely. Each value is written verbatim as the file body
// under the given form-field name.
func buildUploadRequestWithFiles(
	t *testing.T,
	path string,
	fields map[string]string,
	fileData []byte,
	extraFiles map[string][]byte,
) *http.Request {
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
	for fieldName, data := range extraFiles {
		fw, err := mw.CreateFormFile(fieldName, fieldName)
		if err != nil {
			t.Fatalf("CreateFormFile %q: %v", fieldName, err)
		}
		fw.Write(data)
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
	return newUploadRouterWithConfig(t, store, &config.Config{})
}

// newUploadRouterWithConfig is newUploadRouter with a caller-supplied config,
// for tests that need non-default settings (e.g. providers.require_signing).
func newUploadRouterWithConfig(t *testing.T, store *mockStore, cfg *config.Config) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.POST("/v1/providers", UploadHandler(db, store, cfg))
	return mock, r
}

// RETURNING column helpers for INSERT…RETURNING queries
var providerInsertCols = []string{"id", "created_at", "updated_at"}
var providerVersionInsertCols = []string{"id", "created_at"}
var platformInsertCols = []string{"id"}

func strPtr(s string) *string { return &s }

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

// ---------------------------------------------------------------------------
// UploadHandler — SHA256SUMS / signature handling (issue #404)
// ---------------------------------------------------------------------------

// uploadHappyPathExpectations sets up the SQL mocks for the normal
// upload path (create provider + version + check-no-platform + insert
// platform) so the signature-file validation paths can be exercised
// without re-stating the entire fixture chain in every test.
func uploadHappyPathExpectations(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
}

func TestUploadHandler_RejectsSignatureWithoutSums(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)
	uploadHappyPathExpectations(mock)
	// Note: no platform-query / insert-platform expectations — the request
	// must be rejected before that point.

	// No gpg_public_key supplied — the validator skips key parsing entirely
	// so the request reaches the signature-file pairing check.
	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t), map[string][]byte{
		"shasums_signature_file": []byte("fake-sig-bytes"),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (sig without sums): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "shasums_signature_file requires shasums_file") {
		t.Errorf("body should explain the missing companion file; got: %s", w.Body.String())
	}
}

func TestUploadHandler_RejectsSignatureWithoutGPGKey(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)
	uploadHappyPathExpectations(mock)

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
		// NOTE: no gpg_public_key
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           []byte("abc123  terraform-provider-aws_4.0.0_linux_amd64.zip\n"),
		"shasums_signature_file": []byte("fake-sig-bytes"),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (sig without gpg key): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "requires gpg_public_key") {
		t.Errorf("body should explain the missing gpg key; got: %s", w.Body.String())
	}
}

// NOTE: GPG verification-failure path is covered exhaustively in
// internal/validation/gpg_test.go; the upload handler simply delegates to
// validation.VerifySignature, so duplicating the positive/negative crypto
// matrix here would only test the same code through a different door.

// TestUploadHandler_StoresShasumsFileWithoutSignature exercises the happy
// path of persistSignatureFiles when the caller supplies only the
// SHA256SUMS file (no signature). No GPG verification is required, so this
// covers the storage upload and the UPDATE-version SQL step without needing
// a real key/signature pair.
func TestUploadHandler_StoresShasumsFileWithoutSignature(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	// Normal new-provider, new-version flow.
	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	// persistSignatureFiles -> UpdateVersionSignatureStorage UPDATE.
	mock.ExpectExec("UPDATE provider_versions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Back to the main flow.
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file": []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n"),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UploadHandler — providers.require_signing policy (issue #658)
// ---------------------------------------------------------------------------

// generateProviderTestGPGEntity returns an armored public key and its
// matching entity, for building a real signature in the require_signing
// happy-path test below.
func generateProviderTestGPGEntity(t *testing.T) (armoredPubKey string, entity *openpgp.Entity) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test User", "test", "test@example.com", nil)
	if err != nil {
		t.Fatalf("openpgp.NewEntity() error: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode() error: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("entity.Serialize() error: %v", err)
	}
	w.Close()
	return buf.String(), entity
}

// armoredProviderDetachSign creates an ASCII-armored detached signature of
// data using entity.
func armoredProviderDetachSign(t *testing.T, data []byte, entity *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatalf("armor.Encode() for signature error: %v", err)
	}
	if err := openpgp.DetachSign(w, entity, bytes.NewReader(data), nil); err != nil {
		t.Fatalf("openpgp.DetachSign() error: %v", err)
	}
	w.Close()
	return buf.String()
}

func TestUploadHandler_RequireSigning_RejectsUnsignedUpload(t *testing.T) {
	store := &mockStore{}
	cfg := &config.Config{}
	cfg.Providers.RequireSigning = true
	mock, r := newUploadRouterWithConfig(t, store, cfg)
	uploadHappyPathExpectations(mock)
	// No platform-query / insert-platform expectations — the request must be
	// rejected before that point.

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (signing required): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "requires signed provider publishes") {
		t.Errorf("body should explain the signing requirement; got: %s", w.Body.String())
	}
}

func TestUploadHandler_RequireSigning_AllowsSignedUpload(t *testing.T) {
	armoredPubKey, entity := generateProviderTestGPGEntity(t)
	sumsData := []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n")
	sigData := armoredProviderDetachSign(t, sumsData, entity)

	store := &mockStore{}
	cfg := &config.Config{}
	cfg.Providers.RequireSigning = true
	mock, r := newUploadRouterWithConfig(t, store, cfg)
	uploadHappyPathExpectations(mock)
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "linux",
		"arch":           "amd64",
		"gpg_public_key": armoredPubKey,
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           sumsData,
		"shasums_signature_file": []byte(sigData),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (signed upload allowed): body=%s", w.Code, w.Body.String())
	}
}

// TestUploadHandler_RequireSigning_AllowsLaterPlatformWithoutFiles exercises
// the "checked once per version" behavior: once a version already has a
// persisted shasum_signature_storage_key (from an earlier platform upload),
// later platform uploads for the same version may omit the signing fields
// entirely, matching the endpoint's existing "attach once per version" design.
func TestUploadHandler_RequireSigning_AllowsLaterPlatformWithoutFiles(t *testing.T) {
	store := &mockStore{}
	cfg := &config.Config{}
	cfg.Providers.RequireSigning = true
	mock, r := newUploadRouterWithConfig(t, store, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-1", time.Now(), time.Now()))
	// GetVersion -> found, already signed from a prior platform upload.
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "armored-key",
				"", "",
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"), strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"),
				nil,
				false, nil, nil, time.Now()))
	// No shasums_file/shasums_signature_file this time — persistSignatureFiles no-ops.
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "darwin",
		"arch":      "arm64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (later platform on already-signed version): body=%s", w.Code, w.Body.String())
	}
}

// TestUploadHandler_RequireSigning_RejectsBeforeCreatingVersionRow is the
// regression test for the blocking finding on issue #658: the require_signing
// gate must run BEFORE providerRepo.CreateVersion, so a rejected request never
// commits an unsigned provider_versions row. No "INSERT INTO provider_versions"
// expectation is registered on the mock at all — if the handler regressed to
// creating the version before the gate check, that unmocked call would error
// out of order and the assertions below (400 + exact error message +
// ExpectationsWereMet) would fail.
func TestUploadHandler_RequireSigning_RejectsBeforeCreatingVersionRow(t *testing.T) {
	store := &mockStore{}
	cfg := &config.Config{}
	cfg.Providers.RequireSigning = true
	mock, r := newUploadRouterWithConfig(t, store, cfg)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	// Deliberately no "INSERT INTO provider_versions" expectation, and no
	// platform-query / insert-platform expectations — the request must be
	// rejected right after the version lookup, before any of that runs.

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (signing required, rejected before version creation): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "requires signed provider publishes") {
		t.Errorf("body should explain the signing requirement; got: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected/unfulfilled SQL calls (version row must not be created before the gate check): %v", err)
	}
}

// TestUploadHandler_PersistsGPGKeyOnExistingVersion is the regression test for
// the "new high" finding on issue #658: a request against an existing
// provider_versions row must persist a newly supplied gpg_public_key via
// UpdateVersionGPGKey, not silently drop it. Without this, a later signed
// platform upload could satisfy the require_signing gate (via
// ShasumSignatureStorageKey) while gpg_public_key stayed empty forever, since
// it was previously only ever set inside the "create new version" branch.
//
// The new key is only persisted when THIS request also supplies a
// shasums_file and a matching, GPG-verified shasums_signature_file — proving
// the key actually signed this version's checksums. See
// TestUploadHandler_DoesNotPersistUnverifiedGPGKeyOnExistingVersion for the
// negative case (blocking finding on #658: an unverified bare gpg_public_key
// must never overwrite the persisted key).
func TestUploadHandler_PersistsGPGKeyOnExistingVersion(t *testing.T) {
	armoredPubKey, entity := generateProviderTestGPGEntity(t)
	sumsData := []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n")
	sigData := armoredProviderDetachSign(t, sumsData, entity)

	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	// GetVersion -> found, with gpg_public_key empty (e.g. an earlier unsigned
	// attempt, or a platform upload that predates key rotation).
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sampleProviderVersionGetRow())
	// The GPG key must be persisted onto the existing version row (UpdateVersionGPGKey)...
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	// ...and persistSignatureFiles persists the freshly-verified SUMS/sig storage keys.
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "linux",
		"arch":           "amd64",
		"gpg_public_key": armoredPubKey,
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           sumsData,
		"shasums_signature_file": []byte(sigData),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (gpg key persisted onto existing version): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected UpdateVersionGPGKey to run against the existing version row: %v", err)
	}
}

// TestUploadHandler_DoesNotPersistUnverifiedGPGKeyOnExistingVersion is the
// regression test for the blocking finding on issue #658: a request against
// an existing provider_versions row that supplies only gpg_public_key (no
// shasums_file/shasums_signature_file) must NOT call UpdateVersionGPGKey.
// Without this gate, any authenticated upload could overwrite the persisted
// signing key with a value never verified against the version's checksums —
// including on an already-signed version, since alreadySigned lets the
// require_signing gate pass on this request regardless of its own signing
// status. No "UPDATE provider_versions" mock expectation is registered at
// all: if the handler regressed to the unconditional update, the unmocked
// call would error out of order and ExpectationsWereMet would fail.
func TestUploadHandler_DoesNotPersistUnverifiedGPGKeyOnExistingVersion(t *testing.T) {
	armoredPubKey, _ := generateProviderTestGPGEntity(t)

	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	// GetVersion -> found, already fully signed by a prior platform upload.
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "original-armored-key",
				"", "",
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"), strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"),
				nil,
				false, nil, nil, time.Now()))
	// Deliberately no "UPDATE provider_versions" expectation — an unverified
	// gpg_public_key must not trigger UpdateVersionGPGKey, and no
	// shasums_file/shasums_signature_file was supplied so persistSignatureFiles
	// no-ops too.
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "darwin",
		"arch":           "arm64",
		"gpg_public_key": armoredPubKey, // differs from "original-armored-key", but unverified
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (platform upload still succeeds): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected/unfulfilled SQL calls (unverified gpg_public_key must not persist): %v", err)
	}
}

// TestUploadHandler_RejectsShasumsFileOnlyReuploadAgainstSignedVersion is the
// regression test for the #658 follow-up finding: a version that already has
// a persisted shasum_signature_storage_key must not have its SHA256SUMS
// content silently replaced by a shasums_file-only re-upload with no
// accompanying signature. Storage paths are deterministic, so such a
// re-upload would overwrite the existing (verified) SUMS blob in place while
// the DB's shasum_signature_storage_key kept pointing at the untouched old
// .sig file — the version would keep looking signed even though its SUMS
// content had changed with no verification at all, silently undoing the
// require_signing guarantee that a signed version stays properly signed. No
// "UPDATE provider_versions" expectation (beyond the provider metadata
// update) is registered — the request must be rejected right after the
// version lookup, before persistSignatureFiles or the platform query run.
func TestUploadHandler_RejectsShasumsFileOnlyReuploadAgainstSignedVersion(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	// GetVersion -> found, already fully signed by a prior upload.
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "original-armored-key",
				"", "",
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"), strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"),
				nil,
				false, nil, nil, time.Now()))
	// Deliberately no further expectations: the bare shasums_file re-upload
	// must be rejected right after the version lookup.

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "darwin",
		"arch":      "arm64",
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file": []byte("evil-attacker-controlled-sums-content\n"),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (shasums_file-only re-upload against a signed version): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already signed") {
		t.Errorf("body should explain the already-signed rejection; got: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected/unfulfilled SQL calls (shasums_file-only re-upload must be rejected before persistSignatureFiles runs): %v", err)
	}
}

// TestUploadHandler_AllowsReSignAgainstAlreadySignedVersion is the positive
// counterpart to TestUploadHandler_RejectsShasumsFileOnlyReuploadAgainstSignedVersion:
// a version that already has a persisted signature can still be legitimately
// re-signed (e.g. key rotation, or adding a platform with refreshed SUMS
// content) as long as this same request supplies a matching, GPG-verified
// shasums_signature_file alongside shasums_file.
func TestUploadHandler_AllowsReSignAgainstAlreadySignedVersion(t *testing.T) {
	armoredPubKey, entity := generateProviderTestGPGEntity(t)
	sumsData := []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\ndef456abc  terraform-provider-aws_4.0.0_darwin_arm64.zip\n")
	sigData := armoredProviderDetachSign(t, sumsData, entity)

	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	// GetVersion -> found, already signed with a different (rotated-away-from) key.
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "original-armored-key",
				"", "",
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"), strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"),
				nil,
				false, nil, nil, time.Now()))
	// UpdateVersionGPGKey (the newly-verified key differs from the stored one).
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	// persistSignatureFiles -> UpdateVersionSignatureStorage.
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "darwin",
		"arch":           "arm64",
		"gpg_public_key": armoredPubKey,
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           sumsData,
		"shasums_signature_file": []byte(sigData),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (legitimate re-sign of an already-signed version): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected/unfulfilled SQL calls: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UploadHandler — orphaned signature-file blobs on partial failure (issue #685)
// ---------------------------------------------------------------------------

// TestUploadHandler_SigUploadFailure_CleansUpOrphanedSumsBlob covers the
// SHA256SUMS.sig upload failing after SHA256SUMS already uploaded
// successfully: the now-orphaned SUMS blob must be deleted rather than left
// behind with no corresponding DB row.
func TestUploadHandler_SigUploadFailure_CleansUpOrphanedSumsBlob(t *testing.T) {
	armoredPubKey, entity := generateProviderTestGPGEntity(t)
	sumsData := []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n")
	sigData := armoredProviderDetachSign(t, sumsData, entity)

	store := &mockStore{uploadFailSuffix: "SHA256SUMS.sig"}
	mock, r := newUploadRouter(t, store)
	uploadHappyPathExpectations(mock)
	// No platform-query / insert-platform expectations — the request must be
	// rejected before that point.

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "linux",
		"arch":           "amd64",
		"gpg_public_key": armoredPubKey,
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           sumsData,
		"shasums_signature_file": []byte(sigData),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (sig upload failure): body=%s", w.Code, w.Body.String())
	}
	wantPath := "providers/hashicorp/aws/4.0.0/SHA256SUMS"
	found := false
	for _, p := range store.deletedPaths {
		if p == wantPath {
			found = true
		}
	}
	if !found {
		t.Errorf("expected orphaned SUMS blob %q to be deleted after sig upload failure; deleted=%v", wantPath, store.deletedPaths)
	}
}

// TestUploadHandler_SignatureStorageUpdateFailure_CleansUpOrphanedSumsBlob
// covers UpdateVersionSignatureStorage failing after the SHA256SUMS blob was
// already uploaded successfully: the orphaned blob must be deleted.
func TestUploadHandler_SignatureStorageUpdateFailure_CleansUpOrphanedSumsBlob(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)
	uploadHappyPathExpectations(mock)
	mock.ExpectExec("UPDATE provider_versions").WillReturnError(errDB2)
	// No platform-query / insert-platform expectations — the request must be
	// rejected before that point.

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file": []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n"),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (signature storage update failure): body=%s", w.Code, w.Body.String())
	}
	wantPath := "providers/hashicorp/aws/4.0.0/SHA256SUMS"
	found := false
	for _, p := range store.deletedPaths {
		if p == wantPath {
			found = true
		}
	}
	if !found {
		t.Errorf("expected orphaned SUMS blob %q to be deleted after signature-storage DB update failure; deleted=%v", wantPath, store.deletedPaths)
	}
}

// TestUploadHandler_SignatureStorageUpdateFailure_PreservesPreExistingSumsBlob
// is the regression test for the "new low" finding on issue #685: storage
// paths for SHA256SUMS/SHA256SUMS.sig are deterministic per version, so a
// legitimate re-upload (key rotation) overwrites an already-persisted blob in
// place rather than creating a new one. If persistSignatureFiles then fails
// (here, the UpdateVersionSignatureStorage DB write), cleanup must NOT delete
// a blob that a pre-existing DB row still references — that row was never
// touched, since the UPDATE failed, and would otherwise be left pointing at
// nothing. Only the sig blob, which is genuinely new to this call (the
// version had no signature before), is deleted.
func TestUploadHandler_SignatureStorageUpdateFailure_PreservesPreExistingSumsBlob(t *testing.T) {
	armoredPubKey, entity := generateProviderTestGPGEntity(t)
	sumsData := []byte("abc123def  terraform-provider-aws_4.0.0_linux_amd64.zip\n")
	sigData := armoredProviderDetachSign(t, sumsData, entity)

	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	// GetVersion -> found, with a SUMS blob already persisted from an earlier
	// upload that supplied shasums_file but no gpg_public_key/signature yet
	// (a legal combination — see TestUploadHandler_StoresShasumsFileWithoutSignature).
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
				"", "",
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"), nil,
				nil,
				false, nil, nil, time.Now()))
	// This request supplies a verified signature, so the UpdateVersionGPGKey
	// branch fires first (and succeeds) before persistSignatureFiles re-uploads
	// SUMS (overwriting the existing blob) and its DB write fails.
	mock.ExpectExec("UPDATE provider_versions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE provider_versions").WillReturnError(errDB2)
	// No platform-query / insert-platform expectations — the request must be
	// rejected before that point.

	req := buildUploadRequestWithFiles(t, "/v1/providers", map[string]string{
		"namespace":      "hashicorp",
		"type":           "aws",
		"version":        "4.0.0",
		"os":             "linux",
		"arch":           "amd64",
		"gpg_public_key": armoredPubKey,
	}, makeValidZIP(t), map[string][]byte{
		"shasums_file":           sumsData,
		"shasums_signature_file": []byte(sigData),
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (signature storage update failure): body=%s", w.Code, w.Body.String())
	}

	preExistingSumsPath := "providers/hashicorp/aws/4.0.0/SHA256SUMS"
	for _, p := range store.deletedPaths {
		if p == preExistingSumsPath {
			t.Errorf("pre-existing SUMS blob %q must not be deleted (an untouched DB row still references it); deleted=%v", preExistingSumsPath, store.deletedPaths)
		}
	}

	newSigPath := "providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"
	found := false
	for _, p := range store.deletedPaths {
		if p == newSigPath {
			found = true
		}
	}
	if !found {
		t.Errorf("expected newly-uploaded (unreferenced) sig blob %q to be deleted; deleted=%v", newSigPath, store.deletedPaths)
	}
}

// ---------------------------------------------------------------------------
// UploadHandler — additional error paths
// ---------------------------------------------------------------------------

func TestUploadHandler_EmptyFile(t *testing.T) {
	_, r := newUploadRouter(t, &mockStore{})

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace": "hashicorp",
		"type":      "aws",
		"version":   "4.0.0",
		"os":        "linux",
		"arch":      "amd64",
	}, []byte{}) // empty file
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty file): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_CreateProviderError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").WillReturnError(errDB2)

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
		t.Errorf("status = %d, want 500 (create provider error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_ExistingProvider_UpdateError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").WillReturnError(errDB2)

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace":   "hashicorp",
		"type":        "aws",
		"version":     "4.0.0",
		"os":          "linux",
		"arch":        "amd64",
		"description": "Updated description",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (update provider error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_ExistingProvider_Success(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("UPDATE providers").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows(platformInsertCols).AddRow("plat-new"))

	req := buildUploadRequest(t, "/v1/providers", map[string]string{
		"namespace":   "hashicorp",
		"type":        "aws",
		"version":     "4.0.0",
		"os":          "linux",
		"arch":        "amd64",
		"description": "Updated AWS provider",
		"source":      "https://github.com/hashicorp/terraform-provider-aws",
	}, makeValidZIP(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (existing provider upload): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_VersionQueryError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnError(errDB2)

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
		t.Errorf("status = %d, want 500 (version query error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_CreateVersionError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").WillReturnError(errDB2)

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
		t.Errorf("status = %d, want 500 (create version error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_PlatformQueryError(t *testing.T) {
	mock, r := newUploadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnError(errDB2)

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
		t.Errorf("status = %d, want 500 (platform query error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_StorageUploadError(t *testing.T) {
	store := &mockStore{uploadErr: errors.New("storage upload failed")}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))

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
		t.Errorf("status = %d, want 500 (storage upload error): body=%s", w.Code, w.Body.String())
	}
}

func TestUploadHandler_CreatePlatformError(t *testing.T) {
	store := &mockStore{}
	mock, r := newUploadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
	mock.ExpectQuery("INSERT INTO provider_platforms").WillReturnError(errDB2)

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
		t.Errorf("status = %d, want 500 (create platform error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DownloadHandler — additional error paths
// ---------------------------------------------------------------------------

func TestDownloadHandler_OrgNotFound(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnRows(sqlmock.NewRows(orgCols))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (org not found): body=%s", w.Code, w.Body.String())
	}
	assertErrorsArrayBody(t, w)
}

func TestDownloadHandler_ProviderQueryError(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (provider query error): body=%s", w.Code, w.Body.String())
	}
	assertErrorsArrayBody(t, w)
}

func TestDownloadHandler_VersionQueryError(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (version query error): body=%s", w.Code, w.Body.String())
	}
	assertErrorsArrayBody(t, w)
}

func TestDownloadHandler_PlatformQueryError(t *testing.T) {
	mock, r := newDownloadRouter(t, &mockStore{})

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnError(errDB2)

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (platform query error): body=%s", w.Code, w.Body.String())
	}
	assertErrorsArrayBody(t, w)
}

func TestDownloadHandler_SuccessWithGPGKey(t *testing.T) {
	store := &mockStore{getURLResult: "https://example.com/provider.zip"}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(
		sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON,
				"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----",
				"", "",
				nil, nil, // shasum_storage_key, shasum_signature_storage_key
				nil, false, nil, nil, time.Now()),
	)
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ascii_armor") {
		t.Errorf("response should contain ascii_armor for GPG key; body: %s", w.Body.String())
	}
}

// Issue #564 finding [33]: signing_keys.gpg_public_keys[].key_id must be populated
// from the armored key's real long key ID, not left empty.
func TestDownloadHandler_SuccessWithGPGKey_PopulatesKeyID(t *testing.T) {
	entity, err := openpgp.NewEntity("Test User", "test", "test@example.com", nil)
	if err != nil {
		t.Fatalf("openpgp.NewEntity() error: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode() error: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("entity.Serialize() error: %v", err)
	}
	w.Close()
	armoredKey := buf.String()
	wantKeyID := entity.PrimaryKey.KeyIdString()

	store := &mockStore{getURLResult: "https://example.com/provider.zip"}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(
		sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON,
				armoredKey,
				"", "",
				nil, nil, // shasum_storage_key, shasum_signature_storage_key
				nil, false, nil, nil, time.Now()),
	)
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	w2 := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), `"key_id":"`+wantKeyID+`"`) {
		t.Errorf("response should contain key_id %q; body: %s", wantKeyID, w2.Body.String())
	}
}

func TestDownloadHandler_SuccessWithShasumURLs(t *testing.T) {
	store := &mockStore{getURLResult: "https://example.com/provider.zip"}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(
		sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
				"https://example.com/shasums", "https://example.com/shasums.sig",
				nil, nil, // shasum_storage_key, shasum_signature_storage_key
				nil, false, nil, nil, time.Now()),
	)
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "https://example.com/shasums") {
		t.Errorf("response should contain shasums_url; body: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "https://example.com/shasums.sig") {
		t.Errorf("response should contain shasums_signature_url; body: %s", w.Body.String())
	}
}

// Issue #404: when the upload path has stored SHA256SUMS + .sig files in
// our own storage backend, the download handler must generate pre-signed
// URLs from the storage keys and prefer them over the (empty) external
// ShasumURL / ShasumSignatureURL columns.
func TestDownloadHandler_SuccessWithStorageKeys(t *testing.T) {
	const presignedURL = "https://storage.example.com/presigned"
	store := &mockStore{getURLResult: presignedURL}
	mock, r := newDownloadRouter(t, store)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(
		sqlmock.NewRows(providerVersionGetCols).
			AddRow("ver-1", "prov-1", "4.0.0", sampleProtocolsJSON, "",
				"", "", // external URLs empty (this is an uploaded provider)
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS"),
				strPtr("providers/hashicorp/aws/4.0.0/SHA256SUMS.sig"),
				nil, false, nil, nil, time.Now()),
	)
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(samplePlatformRow())

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Both signature URLs must be the pre-signed URL produced by the storage
	// backend; the JSON contains it three times (binary + sums + sig) for an
	// uploaded provider since the mock returns the same URL for any key.
	if got := strings.Count(w.Body.String(), presignedURL); got < 3 {
		t.Errorf("expected pre-signed URL to appear for binary, sums, and sig (3 times); got %d in body: %s", got, w.Body.String())
	}
}

func TestDownloadHandler_SuccessWithAuditContext(t *testing.T) {
	store := &mockStore{getURLResult: "https://example.com/provider.zip"}
	db, mock, _ := sqlmock.New()
	mock.MatchExpectationsInOrder(false)
	t.Cleanup(func() { db.Close() })

	auditRepo := repositories.NewAuditRepository(db)
	r := gin.New()
	// Inject user_id and organization_id into context via middleware
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "test-user-id")
		c.Set("organization_id", "test-org-id")
		c.Next()
	})
	r.GET("/v1/providers/:namespace/:type/:version/download/:os/:arch",
		DownloadHandler(db, store, &config.Config{}, auditRepo))

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").WillReturnRows(sampleProviderRow())
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").WillReturnRows(sampleProviderVersionGetRow())
	mock.ExpectQuery("SELECT approval_status FROM mirrored_provider_versions").WillReturnRows(sqlmock.NewRows([]string{"approval_status"}).AddRow(nil))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").WillReturnRows(samplePlatformRow())
	mock.ExpectExec("UPDATE provider_platforms").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))

	w := doGET(r, "/v1/providers/hashicorp/aws/4.0.0/download/linux/amd64")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Give async goroutines a moment to fire (best-effort)
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// UploadHandler — the provider row is bound to the AUTHORIZED organization
// (issue #778)
// ---------------------------------------------------------------------------

// uploadOwnerOrg is the organization the route's publish guard resolved and
// authorized the upload against. It is deliberately not the default
// organization sampleOrgRow returns.
const uploadOwnerOrg = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee"

// TestUploadHandler_BindsProviderToAuthorizedOrganization pins the invariant:
// the provider row is stamped with the organization the route authorized, which
// nsAuthz.RequirePublishAccessFromForm resolves from the namespace and
// publishes as owner_org_id.
//
// Two things make the row fail if the handler reverts to
// GetDefaultOrganization: the WithArgs on the existence check and on the INSERT
// name the authorized organization, and NO organizations lookup is primed, so
// reaching for the default organization is itself an unexpected statement.
func TestUploadHandler_BindsProviderToAuthorizedOrganization(t *testing.T) {
	db, mock, _ := sqlmock.New()
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.POST("/v1/providers",
		func(c *gin.Context) { c.Set("owner_org_id", uploadOwnerOrg) },
		UploadHandler(db, &mockStore{}, &config.Config{}))

	// GetProvider must look for a collision in the AUTHORIZED organization: the
	// providers unique key is (organization_id, namespace, type), so a lookup in
	// the wrong organization reports "not found" for a provider that exists.
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE").
		WithArgs(uploadOwnerOrg, "hashicorp", "aws").
		WillReturnRows(sqlmock.NewRows(providerCols))
	mock.ExpectQuery("INSERT INTO providers").
		WithArgs(uploadOwnerOrg, "hashicorp", "aws",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(providerInsertCols).AddRow("prov-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE provider_id.*AND version").
		WillReturnRows(sqlmock.NewRows(providerVersionGetCols))
	mock.ExpectQuery("INSERT INTO provider_versions").
		WillReturnRows(sqlmock.NewRows(providerVersionInsertCols).AddRow("ver-new", time.Now()))
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(platformCols))
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
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("provider was not written into the authorized organization: %v", err)
	}
}

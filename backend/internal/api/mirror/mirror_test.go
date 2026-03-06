package mirror

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
)

var mirrorErrDB = errors.New("db error")

// ---------------------------------------------------------------------------
// Column definitions  (positional scans from the repositories)
// ---------------------------------------------------------------------------

var mirrorOrgCols = []string{"id", "name", "display_name", "created_at", "updated_at"}

// 10 columns from GetProvider positional scan
var mirrorProvCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
}

// 13 columns from ListVersions row.Scan
var mirrorVersionCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "published_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleMirrorAPIOrg() *sqlmock.Rows {
	return sqlmock.NewRows(mirrorOrgCols).
		AddRow("org-1", "default", "Default Org", time.Now(), time.Now())
}

func sampleMirrorAPIProvider() *sqlmock.Rows {
	return sqlmock.NewRows(mirrorProvCols).
		AddRow("prov-1", nil, "hashicorp", "aws", nil, nil, nil, time.Now(), time.Now(), nil)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newMirrorAPIRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{}
	r := gin.New()
	r.GET("/providers/:hostname/:namespace/:type/index.json", IndexHandler(db, cfg))
	r.GET("/providers/:hostname/:namespace/:type/:versionfile", PlatformIndexHandler(db, cfg, nil))
	return mock, r
}

// ---------------------------------------------------------------------------
// IndexHandler tests
// ---------------------------------------------------------------------------

func TestIndex_OrgDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestIndex_OrgNotFound(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	// GetByName returns no rows → org == nil → 500
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorOrgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestIndex_ProviderDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestIndex_ProviderNotFound(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sqlmock.NewRows(mirrorProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestIndex_ListVersionsDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	// ListVersions fails
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestIndex_Success_NoVersions(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	// ListVersions returns empty
	mock.ExpectQuery("SELECT.*FROM provider_versions.*WHERE pv.provider_id").
		WillReturnRows(sqlmock.NewRows(mirrorVersionCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/index.json", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// PlatformIndexHandler tests
// ---------------------------------------------------------------------------

func TestPlatformIndex_InvalidVersion(t *testing.T) {
	_, r := newMirrorAPIRouter(t)
	w := httptest.NewRecorder()
	// "not-a-semver" fails ValidateSemver → 400 before any DB call
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/not-a-semver.json", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPlatformIndex_OrgDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_OrgNotFound(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorOrgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_ProviderNotFound(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sqlmock.NewRows(mirrorProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestPlatformIndex_VersionNotFound(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	// GetVersion returns no rows
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// formatZhHash
// ---------------------------------------------------------------------------

func TestFormatZhHash_ZeroHash(t *testing.T) {
	// 64 hex chars (32 bytes = sha256.Size) all zeros
	result := formatZhHash("0000000000000000000000000000000000000000000000000000000000000000")
	if !strings.HasPrefix(result, "zh:") {
		t.Errorf("result = %q, should start with zh:", result)
	}
}

func TestFormatZhHash_KnownHash(t *testing.T) {
	// SHA256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	// zh: prepends the prefix directly to the hex string (lowercase hex, per Terraform spec)
	result := formatZhHash("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	expected := "zh:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result != expected {
		t.Errorf("result = %q, want %q", result, expected)
	}
	// Verify it's different from zero hash
	zeroResult := formatZhHash("0000000000000000000000000000000000000000000000000000000000000000")
	if result == zeroResult {
		t.Error("non-zero hash should differ from zero hash")
	}
}

func TestFormatZhHash_Empty(t *testing.T) {
	result := formatZhHash("")
	if result != "" {
		t.Errorf("result = %q, want empty string for empty input", result)
	}
}

// ---------------------------------------------------------------------------
// PlatformIndexHandler — additional uncovered branches
// ---------------------------------------------------------------------------

// mirrorVersionGetCols are the 12 columns returned by ProviderRepository.GetVersion positional scan
var mirrorVersionGetCols = []string{
	"id", "provider_id", "version", "protocols",
	"gpg_public_key", "shasums_url", "shasums_signature_url",
	"published_by", "deprecated", "deprecated_at",
	"deprecation_message", "created_at",
}

// mirrorPlatformCols are the 11 columns returned by ProviderRepository.ListPlatforms positional scan
var mirrorPlatformCols = []string{
	"id", "provider_version_id", "os", "arch",
	"filename", "storage_path", "storage_backend", "size_bytes", "shasum", "h1_hash", "download_count",
}

func sampleMirrorVersionGetRow() *sqlmock.Rows {
	protocols := []byte(`["6.0"]`)
	return sqlmock.NewRows(mirrorVersionGetCols).
		AddRow("ver-1", "prov-1", "1.2.3", protocols, "", "", "", nil, false, nil, nil, time.Now())
}

func TestPlatformIndex_ProviderDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_GetVersionDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_ListPlatformsDBError(t *testing.T) {
	mock, r := newMirrorAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnRows(sampleMirrorVersionGetRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnError(mirrorErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_StorageInitError(t *testing.T) {
	// Use a config with invalid storage backend to trigger storage init error
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = "nonexistent-backend"

	r := gin.New()
	r.GET("/providers/:hostname/:namespace/:type/:versionfile", PlatformIndexHandler(db, cfg, nil))

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnRows(sampleMirrorVersionGetRow())
	// ListPlatforms returns empty (still triggers storage init due to storageOnce.Do)
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(mirrorPlatformCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPlatformIndex_Success_EmptyPlatforms(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = "local"
	cfg.Storage.Local.BasePath = t.TempDir()
	cfg.Server.BaseURL = "http://localhost:8080"

	r := gin.New()
	r.GET("/providers/:hostname/:namespace/:type/:versionfile", PlatformIndexHandler(db, cfg, nil))

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnRows(sampleMirrorVersionGetRow())
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(mirrorPlatformCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "archives") {
		t.Error("response should contain 'archives' key")
	}
}

func TestPlatformIndex_Success_WithPlatforms(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	tmpDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = "local"
	cfg.Storage.Local.BasePath = tmpDir
	cfg.Storage.Local.ServeDirectly = true
	cfg.Server.BaseURL = "http://localhost:8080"

	// Create dummy files so GetURL's Exists check passes
	for _, p := range []string{
		"providers/hashicorp/aws/1.2.3/linux_amd64.zip",
		"providers/hashicorp/aws/1.2.3/darwin_amd64.zip",
	} {
		fullPath := filepath.Join(tmpDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte("fake-zip"), 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	r := gin.New()
	r.GET("/providers/:hostname/:namespace/:type/:versionfile", PlatformIndexHandler(db, cfg, nil))

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleMirrorAPIOrg())
	mock.ExpectQuery("SELECT.*FROM providers.*WHERE.*organization_id").
		WillReturnRows(sampleMirrorAPIProvider())
	mock.ExpectQuery("SELECT.*FROM provider_versions WHERE provider_id").
		WillReturnRows(sampleMirrorVersionGetRow())

	// Return two platforms — one with h1_hash, one without
	h1Hash := "h1:abcdef1234567890abcdef1234567890abcdef1234567890"
	mock.ExpectQuery("SELECT.*FROM provider_platforms.*WHERE provider_version_id").
		WillReturnRows(sqlmock.NewRows(mirrorPlatformCols).
			AddRow("plat-1", "ver-1", "linux", "amd64",
				"terraform-provider-aws_1.2.3_linux_amd64.zip",
				"providers/hashicorp/aws/1.2.3/linux_amd64.zip",
				"local", 1024, "abc123def", &h1Hash, 0).
			AddRow("plat-2", "ver-1", "darwin", "amd64",
				"terraform-provider-aws_1.2.3_darwin_amd64.zip",
				"providers/hashicorp/aws/1.2.3/darwin_amd64.zip",
				"local", 2048, "xyz789def", nil, 0))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/1.2.3.json", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "linux_amd64") {
		t.Error("response should contain linux_amd64 platform")
	}
	if !strings.Contains(body, "darwin_amd64") {
		t.Error("response should contain darwin_amd64 platform")
	}
	if !strings.Contains(body, "h1:") {
		t.Error("response should contain h1: hash for linux_amd64 platform")
	}
	if !strings.Contains(body, "zh:") {
		t.Error("response should contain zh: hash")
	}
}

func TestPlatformIndex_VersionWithoutJsonSuffix(t *testing.T) {
	// Short version string (< 5 chars) should not strip .json
	_, r := newMirrorAPIRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/providers/registry.terraform.io/hashicorp/aws/abc", nil))

	// "abc" is not valid semver → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

package mirror

import (
	"errors"
	"strings"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
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
	r.GET("/providers/:hostname/:namespace/:type/:versionfile", PlatformIndexHandler(db, cfg))
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
// formatH1Hash
// ---------------------------------------------------------------------------

func TestFormatH1Hash_ZeroHash(t *testing.T) {
	// 64 hex chars (32 bytes = sha256.Size) all zeros
	result := formatH1Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if !strings.HasPrefix(result, "h1:") {
		t.Errorf("result = %q, should start with h1:", result)
	}
}

func TestFormatH1Hash_KnownHash(t *testing.T) {
	// SHA256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	result := formatH1Hash("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	if !strings.HasPrefix(result, "h1:") {
		t.Errorf("result = %q, should start with h1:", result)
	}
	// Verify it's different from zero hash
	zeroResult := formatH1Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if result == zeroResult {
		t.Error("non-zero hash should differ from zero hash")
	}
}

func TestFormatH1Hash_Empty(t *testing.T) {
	result := formatH1Hash("")
	if !strings.HasPrefix(result, "h1:") {
		t.Errorf("result = %q, should start with h1:", result)
	}
}

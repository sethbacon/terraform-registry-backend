// scans_test.go tests the admin scan result endpoint.
package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

var scanAdminCols = []string{
	"id", "module_version_id", "scanner", "scanner_version", "expected_version",
	"status", "scanned_at", "critical_count", "high_count", "medium_count", "low_count",
	"raw_results", "error_message", "created_at", "updated_at",
}

var orgColsScan = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
var moduleColsScan = []string{
	"id", "organization_id", "namespace", "name", "system",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
}
var modVersionGetColsScan = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "replacement_source", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

func newScanAdminRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/modules/:namespace/:name/:system/versions/:version/scan",
		GetModuleScanHandler(db))
	return mock, r
}

func doScanGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w
}

func sampleOrgRowScan() *sqlmock.Rows {
	return sqlmock.NewRows(orgColsScan).
		AddRow("org-1", "default", "Default Org", nil, nil, time.Now(), time.Now())
}

func sampleModuleRowScan() *sqlmock.Rows {
	return sqlmock.NewRows(moduleColsScan).
		AddRow("mod-1", "org-1", "hashicorp", "vpc", "aws",
			nil, nil, nil, time.Now(), time.Now(), nil, false, nil, nil, nil)
}

func sampleVersionRowScan() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionGetColsScan).
		AddRow("ver-1", "mod-1", "1.0.0", "path/file.tgz", "local",
			int64(1024), "abc123", nil, nil, int64(0), false, nil, nil, nil, time.Now(),
			nil, nil, nil)
}

func sampleScanResultRow() *sqlmock.Rows {
	return sqlmock.NewRows(scanAdminCols).AddRow(
		"scan-1", "ver-1", "trivy", "0.50.0", nil,
		"clean", time.Now(), 0, 0, 0, 0,
		`{}`, nil, time.Now(), time.Now(),
	)
}

// ---------------------------------------------------------------------------
// GetModuleScanHandler tests
// ---------------------------------------------------------------------------

func TestGetModuleScan_Success(t *testing.T) {
	mock, r := newScanAdminRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WithArgs("org-1", "hashicorp", "vpc", "aws").
		WillReturnRows(sampleModuleRowScan())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "1.0.0").
		WillReturnRows(sampleVersionRowScan())
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WithArgs("ver-1").
		WillReturnRows(sampleScanResultRow())

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestGetModuleScan_OrgError(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnError(errors.New("db error"))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleScan_OrgNotFound(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnRows(sqlmock.NewRows(orgColsScan))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleScan_ModuleDBError(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnError(errors.New("db error"))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleScan_ModuleNotFound(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WillReturnRows(sqlmock.NewRows(moduleColsScan))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleScan_VersionDBError(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRowScan())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnError(errors.New("db error"))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleScan_VersionNotFound(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRowScan())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sqlmock.NewRows(modVersionGetColsScan))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/9.9.9/scan")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleScan_ScanDBError(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRowScan())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleVersionRowScan())
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WillReturnError(errors.New("db error"))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleScan_ScanNotFound(t *testing.T) {
	mock, r := newScanAdminRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRowScan())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRowScan())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleVersionRowScan())
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WillReturnRows(sqlmock.NewRows(scanAdminCols))

	w := doScanGET(r, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

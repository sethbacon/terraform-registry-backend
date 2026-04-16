package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Column definitions for module SQL mocks
// ---------------------------------------------------------------------------

var moduleCols = []string{
	"id", "organization_id", "namespace", "name", "system",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
}

var modVersionListCols = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "published_by_name", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id", "has_docs",
}

var modVersionGetCols = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

var modCreateCols = []string{"id", "created_at", "updated_at"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleModuleRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleCols).
		AddRow("mod-1", "org-1", "hashicorp", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil, false, nil, nil, nil)
}

func emptyModuleRow() *sqlmock.Rows {
	return sqlmock.NewRows(moduleCols)
}

func sampleModVersionListRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionListCols).
		AddRow("ver-1", "mod-1", "1.0.0", "modules/hashicorp/vpc/aws/vpc-1.0.0.tar.gz", "default",
			int64(1024), "abc123", nil, nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil, false)
}

func emptyModVersionListRows() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionListCols)
}

func sampleModVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionGetCols).
		AddRow("ver-1", "mod-1", "1.0.0", "modules/hashicorp/vpc/aws/vpc-1.0.0.tar.gz", "default",
			int64(1024), "abc123", nil, nil, int64(5), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func emptyModVersionGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(modVersionGetCols)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newModuleRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewModuleAdminHandlers(db, &mockStorage{}, &config.Config{})

	r := gin.New()
	r.POST("/modules/create", h.CreateModuleRecord)
	r.GET("/modules/:namespace/:name/:system", h.GetModule)
	r.DELETE("/modules/:namespace/:name/:system", h.DeleteModule)
	r.DELETE("/modules/:namespace/:name/:system/versions/:version", h.DeleteVersion)
	r.POST("/modules/:namespace/:name/:system/versions/:version/deprecate", h.DeprecateVersion)
	r.DELETE("/modules/:namespace/:name/:system/versions/:version/deprecate", h.UndeprecateVersion)
	r.GET("/modules/id/:id", h.GetModuleByIDRecord)
	r.PUT("/modules/id/:id", h.UpdateModuleRecord)
	r.POST("/modules/:namespace/:name/:system/deprecate", h.DeprecateModule)
	r.DELETE("/modules/:namespace/:name/:system/deprecate", h.UndeprecateModule)

	return mock, r
}

// ---------------------------------------------------------------------------
// CreateModuleRecord tests
// ---------------------------------------------------------------------------

func TestCreateModuleRecord_InvalidJSON(t *testing.T) {
	_, r := newModuleRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create", bytes.NewBufferString("{bad json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateModuleRecord_MissingNamespace(t *testing.T) {
	_, r := newModuleRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create",
		jsonBody(map[string]string{"name": "vpc", "system": "aws"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateModuleRecord_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create",
		jsonBody(map[string]string{"namespace": "hashicorp", "name": "vpc", "system": "aws"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestCreateModuleRecord_ExistingModule_ReturnsOK(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create",
		jsonBody(map[string]string{"namespace": "hashicorp", "name": "vpc", "system": "aws"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestCreateModuleRecord_Success(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectOrgFound(mock)
	// GetModule returns not found (no existing module)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())
	// CreateModule INSERT RETURNING
	mock.ExpectQuery("INSERT INTO modules").
		WillReturnRows(sqlmock.NewRows(modCreateCols).
			AddRow("mod-new", time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create",
		jsonBody(map[string]string{"namespace": "hashicorp", "name": "vpc", "system": "aws"})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestCreateModuleRecord_CreateError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectOrgFound(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())
	mock.ExpectQuery("INSERT INTO modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/create",
		jsonBody(map[string]string{"namespace": "hashicorp", "name": "vpc", "system": "aws"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetModule tests
// ---------------------------------------------------------------------------

func TestGetModule_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModule_NotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModule_ModuleDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModule_Success_NoVersions(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WillReturnRows(emptyModVersionListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["id"] == nil {
		t.Error("response missing 'id' key")
	}
}

func TestGetModule_Success_WithVersions(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions").
		WillReturnRows(sampleModVersionListRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteModule tests
// ---------------------------------------------------------------------------

func TestDeleteModule_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModule_ModuleDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModule_ListVersionsDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*module_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModule_DeleteDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*module_id").
		WillReturnRows(emptyModVersionListRows())
	mock.ExpectExec("DELETE FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModule_NotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteModule_Success_NoVersions(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*module_id").
		WillReturnRows(emptyModVersionListRows())
	mock.ExpectExec("DELETE FROM modules").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteModule_Success_WithVersions(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*module_id").
		WillReturnRows(sampleModVersionListRow())
	mock.ExpectExec("DELETE FROM modules").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion (module) tests
// ---------------------------------------------------------------------------

func TestDeleteModuleVersion_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModuleVersion_ModuleDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModuleVersion_GetVersionDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModuleVersion_DeleteDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("DELETE FROM module_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteModuleVersion_ModuleNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteModuleVersion_VersionNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(emptyModVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteModuleVersion_Success(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("DELETE FROM module_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion (module) tests
// ---------------------------------------------------------------------------

func TestDeprecateModuleVersion_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateModuleVersion_ModuleDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateModuleVersion_GetVersionDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateModuleVersion_DeprecateDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("UPDATE module_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate",
		jsonBody(map[string]string{"message": "deprecated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateModuleVersion_ModuleNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate",
		jsonBody(map[string]string{"message": "outdated"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeprecateModuleVersion_VersionNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(emptyModVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeprecateModuleVersion_Success(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("UPDATE module_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate",
		jsonBody(map[string]string{"message": "deprecated"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UndeprecateVersion (module) tests
// ---------------------------------------------------------------------------

func TestUndeprecateModuleVersion_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateModuleVersion_ModuleDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateModuleVersion_ModuleNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUndeprecateModuleVersion_GetVersionDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateModuleVersion_UndeprecateDBError(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("UPDATE module_versions").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateModuleVersion_VersionNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(emptyModVersionGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUndeprecateModuleVersion_Success(t *testing.T) {
	mock, r := newModuleRouter(t)

	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WillReturnRows(sampleModVersionGetRow())
	mock.ExpectExec("UPDATE module_versions").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/versions/1.0.0/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetModuleByIDRecord tests
// ---------------------------------------------------------------------------

func TestGetModuleByIDRecord_DBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-1").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/id/mod-1", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleByIDRecord_NotFound(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-999").WillReturnRows(emptyModuleRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/id/mod-999", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleByIDRecord_Success(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-1").WillReturnRows(sampleModuleRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/id/mod-1", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateModuleRecord tests
// ---------------------------------------------------------------------------

func TestUpdateModuleRecord_InvalidJSON(t *testing.T) {
	_, r := newModuleRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/id/mod-1", bytes.NewBufferString("{bad")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateModuleRecord_DBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-1").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/id/mod-1",
		jsonBody(map[string]string{"description": "new desc"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateModuleRecord_NotFound(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-999").WillReturnRows(emptyModuleRow())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/id/mod-999",
		jsonBody(map[string]string{"description": "new desc"})))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateModuleRecord_UpdateError(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-1").WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("UPDATE modules").WillReturnError(errDB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/id/mod-1",
		jsonBody(map[string]string{"description": "new desc"})))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateModuleRecord_Success(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM modules").WithArgs("mod-1").WillReturnRows(sampleModuleRow())
	mock.ExpectQuery("UPDATE modules").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/id/mod-1",
		jsonBody(map[string]string{"description": "new desc"})))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeprecateModule tests
// ---------------------------------------------------------------------------

func TestDeprecateModule_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/deprecate",
		jsonBody(map[string]string{"message": "end of life"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeprecateModule_ModuleNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/deprecate",
		jsonBody(map[string]string{"message": "end of life"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeprecateModule_Success(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectExec("UPDATE modules SET deprecated").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/deprecate",
		jsonBody(map[string]string{"message": "use vpc-v2 instead"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestDeprecateModule_EmptyBody(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectExec("UPDATE modules SET deprecated").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestDeprecateModule_DBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectExec("UPDATE modules SET deprecated").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/hashicorp/vpc/aws/deprecate",
		jsonBody(map[string]string{"message": "deprecated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UndeprecateModule tests
// ---------------------------------------------------------------------------

func TestUndeprecateModule_OrgDBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations").
		WithArgs("default").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUndeprecateModule_ModuleNotFound(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(emptyModuleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUndeprecateModule_Success(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectExec("UPDATE modules SET deprecated").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUndeprecateModule_DBError(t *testing.T) {
	mock, r := newModuleRouter(t)
	expectNoDefaultOrg(mock)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sampleModuleRow())
	mock.ExpectExec("UPDATE modules SET deprecated").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/hashicorp/vpc/aws/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

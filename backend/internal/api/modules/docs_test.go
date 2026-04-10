package modules

import (
	"net/http"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

// Column sets reused from modules_test.go (same package)
var moduleVersionGetColsDoc = []string{
	"id", "module_id", "version", "storage_path", "storage_backend", "size_bytes",
	"checksum", "readme", "published_by", "download_count",
	"deprecated", "deprecated_at", "deprecation_message", "created_at",
	"commit_sha", "tag_name", "scm_repo_id",
}

var docResultCols = []string{"inputs", "outputs", "providers", "requirements"}

func sampleVersionGetRowForDocs() *sqlmock.Rows {
	return sqlmock.NewRows(moduleVersionGetColsDoc).
		AddRow("ver-1", "mod-1", "1.0.0", "path/to/file.tgz", "local",
			int64(1024), "abc123", nil, nil, int64(0), false, nil, nil, time.Now(),
			nil, nil, nil)
}

func sampleDocsResultRow() *sqlmock.Rows {
	return sqlmock.NewRows(docResultCols).AddRow(
		`[{"name":"region","type":"string","required":false}]`,
		`[{"name":"vpc_id"}]`,
		`[{"name":"aws","source":"hashicorp/aws"}]`,
		nil,
	)
}

func newDocsAPIRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := gin.New()
	r.GET("/api/v1/modules/:namespace/:name/:system/versions/:version/docs",
		GetModuleDocsHandler(db))
	return mock, r
}

// ---------------------------------------------------------------------------
// GetModuleDocsHandler
// ---------------------------------------------------------------------------

func TestGetModuleDocs_Success(t *testing.T) {
	mock, r := newDocsAPIRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "1.0.0").
		WillReturnRows(sampleVersionGetRowForDocs())
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WithArgs("ver-1").
		WillReturnRows(sampleDocsResultRow())

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestGetModuleDocs_OrgError(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnError(errDB2)

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleDocs_OrgNotFound(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnRows(sqlmock.NewRows(orgCols2))

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleDocs_ModuleNotFound(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").
		WillReturnRows(sqlmock.NewRows(moduleCols2))

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleDocs_ModuleDBError(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnError(errDB2)

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleDocs_VersionNotFound(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "9.9.9").
		WillReturnRows(sqlmock.NewRows(moduleVersionGetColsDoc))

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/9.9.9/docs")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleDocs_VersionDBError(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "1.0.0").
		WillReturnError(errDB2)

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetModuleDocs_DocsNotFound(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "1.0.0").
		WillReturnRows(sampleVersionGetRowForDocs())
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WillReturnRows(sqlmock.NewRows(docResultCols))

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetModuleDocs_DocsDBError(t *testing.T) {
	mock, r := newDocsAPIRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").WillReturnRows(sampleOrgRow2())
	mock.ExpectQuery("SELECT.*FROM modules.*WHERE").WillReturnRows(sampleModuleRow2())
	mock.ExpectQuery("SELECT.*FROM module_versions.*WHERE module_id").
		WithArgs("mod-1", "1.0.0").
		WillReturnRows(sampleVersionGetRowForDocs())
	mock.ExpectQuery("SELECT inputs, outputs, providers, requirements").
		WillReturnError(errDB2)

	w := doGET(r, "/api/v1/modules/hashicorp/consul/aws/versions/1.0.0/docs")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

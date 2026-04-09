package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

// auditLogListCols mirrors the SELECT in ListAuditLogs (9 base + 2 JOIN fields).
var auditLogListCols = []string{
	"id", "user_id", "organization_id", "action", "resource_type", "resource_id",
	"metadata", "ip_address", "created_at", "user_email", "user_name",
}

// auditLogGetCols mirrors the SELECT in GetAuditLog (9 base columns only).
var auditLogGetCols = []string{
	"id", "user_id", "organization_id", "action", "resource_type", "resource_id",
	"metadata", "ip_address", "created_at",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleAuditLogListRows() *sqlmock.Rows {
	ip := "127.0.0.1"
	email := "alice@example.com"
	name := "Alice"
	return sqlmock.NewRows(auditLogListCols).
		AddRow(
			knownUUID, knownUserUUID, nil, "POST /api/v1/modules", "module", nil,
			nil, ip, time.Now(), email, name,
		)
}

func emptyAuditLogListRows() *sqlmock.Rows {
	return sqlmock.NewRows(auditLogListCols)
}

func sampleAuditLogGetRow() *sqlmock.Rows {
	ip := "127.0.0.1"
	return sqlmock.NewRows(auditLogGetCols).
		AddRow(
			knownUUID, knownUserUUID, nil, "POST /api/v1/modules", "module", nil,
			nil, ip, time.Now(),
		)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newAuditLogRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewAuditLogHandlers(db)

	r := gin.New()
	r.GET("/audit-logs", h.ListAuditLogsHandler())
	r.GET("/audit-logs/:id", h.GetAuditLogHandler())

	return mock, r
}

// ---------------------------------------------------------------------------
// ListAuditLogsHandler
// ---------------------------------------------------------------------------

func TestListAuditLogs_Success(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	// Expect COUNT query then SELECT query
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(sampleAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListAuditLogs_EmptyResult(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListAuditLogs_DBError(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListAuditLogs_InvalidStartDate(t *testing.T) {
	_, r := newAuditLogRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?start_date=not-a-date", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestListAuditLogs_InvalidEndDate(t *testing.T) {
	_, r := newAuditLogRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?end_date=not-a-date", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestListAuditLogs_Pagination(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?page=2&per_page=2", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetAuditLogHandler
// ---------------------------------------------------------------------------

func TestGetAuditLog_Found(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WithArgs(knownUUID).
		WillReturnRows(sampleAuditLogGetRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestGetAuditLog_NotFound(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WithArgs(knownUUID).
		WillReturnRows(sqlmock.NewRows(auditLogGetCols)) // empty → sql.ErrNoRows

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetAuditLog_DBError(t *testing.T) {
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WithArgs(knownUUID).
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListAuditLogs_WithFilters(t *testing.T) {
	// Exercises action/resource_type/user_id/user_email filter branches
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET",
		"/audit-logs?action=create&resource_type=module&user_id=abc&user_email=x@y.com", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestListAuditLogs_PageBelowOne(t *testing.T) {
	// page=0 should be normalised to 1
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?page=0&per_page=0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestListAuditLogs_PerPageExceedsMax(t *testing.T) {
	// per_page=500 (>200) should be capped at 25
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?per_page=500", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestListAuditLogs_WithDateFilters(t *testing.T) {
	// Exercises valid start_date and end_date filter branches
	mock, r := newAuditLogRouter(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(emptyAuditLogListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET",
		"/audit-logs?start_date=2024-01-01T00:00:00Z&end_date=2024-12-31T23:59:59Z", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

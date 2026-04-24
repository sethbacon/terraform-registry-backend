package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newAuditExportRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	auditRepo := repositories.NewAuditRepository(db)

	r := gin.New()
	r.GET("/audit-logs/export", ExportAuditLogs(auditRepo, "test"))

	return mock, r
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — invalid start_date
// ---------------------------------------------------------------------------

func TestExportAuditLogs_InvalidStartDate(t *testing.T) {
	_, r := newAuditExportRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export?start_date=not-a-date", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["error"]; !ok {
		t.Error("expected 'error' key in response body")
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — invalid end_date
// ---------------------------------------------------------------------------

func TestExportAuditLogs_InvalidEndDate(t *testing.T) {
	_, r := newAuditExportRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export?end_date=2024-13-99", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["error"]; !ok {
		t.Error("expected 'error' key in response body")
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — valid start_date but invalid end_date
// ---------------------------------------------------------------------------

func TestExportAuditLogs_ValidStartInvalidEnd(t *testing.T) {
	_, r := newAuditExportRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET",
		"/audit-logs/export?start_date=2024-01-01T00:00:00Z&end_date=bad", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — DB error returns 500
// ---------------------------------------------------------------------------

func TestExportAuditLogs_DBError(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	mock.ExpectQuery("SELECT al\\.id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — valid date range with DB query
// ---------------------------------------------------------------------------

func TestExportAuditLogs_ValidDates_DBError(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	mock.ExpectQuery("SELECT al\\.id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET",
		"/audit-logs/export?start_date=2024-01-01T00:00:00Z&end_date=2024-12-31T23:59:59Z", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — success with rows
// ---------------------------------------------------------------------------

// auditExportCols mirrors the Scan call order in ExportAuditLogs.
var auditExportCols = []string{
	"id", "user_id", "organization_id", "action", "resource_type", "resource_id",
	"metadata", "ip_address", "created_at", "user_email", "user_name",
}

func TestExportAuditLogs_Success(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	email := "alice@example.com"
	name := "Alice"
	rows := sqlmock.NewRows(auditExportCols).
		AddRow("entry-1", nil, nil, "module.create", "module", "mod-1",
			nil, "10.0.0.1", time.Now(), &email, &name)

	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}

	cd := w.Header().Get("Content-Disposition")
	if cd == "" {
		t.Error("expected Content-Disposition header to be set")
	}

	// Body should contain valid JSON line(s)
	var entry map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse NDJSON line: %v\nbody: %s", err, w.Body.String())
	}
	if entry["id"] != "entry-1" {
		t.Errorf("entry[id] = %v, want entry-1", entry["id"])
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — success with metadata JSON
// ---------------------------------------------------------------------------

func TestExportAuditLogs_WithMetadata(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	metaJSON := []byte(`{"key":"value"}`)
	rows := sqlmock.NewRows(auditExportCols).
		AddRow("entry-2", nil, nil, "module.delete", nil, nil,
			metaJSON, nil, time.Now(), nil, nil)

	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse NDJSON line: %v", err)
	}
	meta, ok := entry["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected metadata to be a map, got %T", entry["metadata"])
	}
	if meta["key"] != "value" {
		t.Errorf("metadata[key] = %v, want value", meta["key"])
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — empty result set
// ---------------------------------------------------------------------------

func TestExportAuditLogs_EmptyResult(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	rows := sqlmock.NewRows(auditExportCols)
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	if body := w.Body.String(); body != "" {
		t.Errorf("expected empty body for empty result, got %q", body)
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — defaults to last 30 days when no params provided
// ---------------------------------------------------------------------------

func TestExportAuditLogs_DefaultDateRange(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	rows := sqlmock.NewRows(auditExportCols)
	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export", nil))

	// Should succeed with 200 — no date params means default 30-day window
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — invalid format parameter
// ---------------------------------------------------------------------------

func TestExportAuditLogs_InvalidFormat(t *testing.T) {
	_, r := newAuditExportRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export?format=xml", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["error"]; !ok {
		t.Error("expected 'error' key in response body")
	}
}

// ---------------------------------------------------------------------------
// ExportAuditLogs — OCSF format returns valid OCSF events
// ---------------------------------------------------------------------------

func TestExportAuditLogs_OCSFFormat(t *testing.T) {
	mock, r := newAuditExportRouter(t)

	email := "bob@example.com"
	name := "Bob"
	userID := "user-42"
	orgID := "org-99"
	resType := "module"
	resID := "mod-7"
	ip := "192.168.1.1"

	rows := sqlmock.NewRows(auditExportCols).
		AddRow("entry-ocsf", &userID, &orgID, "create_module", &resType, &resID,
			nil, &ip, time.Now(), &email, &name)

	mock.ExpectQuery("SELECT al\\.id").
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/export?format=ocsf", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}

	cd := w.Header().Get("Content-Disposition")
	if cd == "" {
		t.Error("expected Content-Disposition header")
	}

	// OCSF event must have class_uid 6003 and correct actor fields.
	var ev map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &ev); err != nil {
		t.Fatalf("failed to parse OCSF NDJSON line: %v\nbody: %s", err, w.Body.String())
	}
	if ev["class_uid"] != float64(6003) {
		t.Errorf("class_uid = %v, want 6003", ev["class_uid"])
	}
	actor, ok := ev["actor"].(map[string]interface{})
	if !ok {
		t.Fatalf("actor is not a map: %T", ev["actor"])
	}
	user, ok := actor["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("actor.user is not a map: %T", actor["user"])
	}
	if user["uid"] != "user-42" {
		t.Errorf("actor.user.uid = %v, want user-42", user["uid"])
	}
	if user["name"] != "Bob" {
		t.Errorf("actor.user.name = %v, want Bob", user["name"])
	}
	unmapped, ok := ev["unmapped"].(map[string]interface{})
	if !ok {
		t.Fatalf("unmapped is not a map: %T", ev["unmapped"])
	}
	if unmapped["user_email"] != "bob@example.com" {
		t.Errorf("unmapped.user_email = %v, want bob@example.com", unmapped["user_email"])
	}
}

package advisories

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var advisoryCols = []string{
	"id", "source", "source_id", "severity", "summary", "details",
	"references", "published_at", "modified_at", "fetched_at",
	"withdrawn_at", "created_at", "updated_at",
}

var targetCols = []string{
	"id", "advisory_id", "target_kind", "fingerprint", "target_ref",
	"terraform_version_id", "provider_version_id", "created_at",
}

var errDB = errors.New("database error")

func newAdvisoriesRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewHandlers(db)
	r := gin.New()
	r.GET("/advisories/active", h.ListActive())
	return mock, r
}

// ---------------------------------------------------------------------------
// ListActive
// ---------------------------------------------------------------------------

func TestListActive_Empty(t *testing.T) {
	mock, r := newAdvisoriesRouter(t)

	// ListActive queries two separate queries: the main advisory query,
	// then listTargetsForAdvisory for each row (none here).
	mock.ExpectQuery("cve_advisories").WillReturnRows(sqlmock.NewRows(advisoryCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/advisories/active", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var result []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty array, got %d items", len(result))
	}
}

func TestListActive_CacheControlHeader(t *testing.T) {
	mock, r := newAdvisoriesRouter(t)
	mock.ExpectQuery("cve_advisories").WillReturnRows(sqlmock.NewRows(advisoryCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/advisories/active", nil)
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want 'public, max-age=300'", got)
	}
}

func TestListActive_WithAdvisory(t *testing.T) {
	now := time.Now()
	advisoryID := uuid.New()
	targetID := uuid.New()

	mock, r := newAdvisoriesRouter(t)

	// Advisory row
	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(advisoryCols).AddRow(
			advisoryID, "osv", "CVE-2024-5678", "high", "Critical advisory", "Details",
			[]byte(`["https://example.com"]`), &now, &now, now, nil, now, now,
		))

	// Target rows for this advisory
	mock.ExpectQuery("cve_affected_targets").
		WithArgs(advisoryID).
		WillReturnRows(sqlmock.NewRows(targetCols).AddRow(
			targetID, advisoryID, "binary", "cfg:ver", []byte(`{"tool":"terraform","version":"1.5.0"}`),
			nil, nil, now,
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/advisories/active", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(result))
	}
	if result[0]["source_id"] != "CVE-2024-5678" {
		t.Errorf("source_id = %v", result[0]["source_id"])
	}
	if result[0]["severity"] != "high" {
		t.Errorf("severity = %v", result[0]["severity"])
	}
	if result[0]["target_kind"] != "binary" {
		t.Errorf("target_kind = %v", result[0]["target_kind"])
	}
}

func TestListActive_DBError(t *testing.T) {
	mock, r := newAdvisoriesRouter(t)
	mock.ExpectQuery("cve_advisories").WillReturnError(errDB)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/advisories/active", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestListActive_NoTargets_TargetKindEmpty(t *testing.T) {
	now := time.Now()
	advisoryID := uuid.New()

	mock, r := newAdvisoriesRouter(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(advisoryCols).AddRow(
			advisoryID, "osv", "GHSA-0001", "low", "Low advisory", "",
			[]byte(`[]`), nil, nil, now, nil, now, now,
		))
	// No targets
	mock.ExpectQuery("cve_affected_targets").
		WithArgs(advisoryID).
		WillReturnRows(sqlmock.NewRows(targetCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/advisories/active", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var result []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(result))
	}
	// target_kind should be empty string when no targets
	if result[0]["target_kind"] != "" {
		t.Errorf("expected empty target_kind, got %v", result[0]["target_kind"])
	}
}

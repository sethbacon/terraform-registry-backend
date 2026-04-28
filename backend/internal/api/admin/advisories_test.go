package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
)

// advisoryCols matches the column order scanned in cve_repository.ListAll.
var advisoryCols = []string{
	"id", "source", "source_id", "severity", "summary", "details",
	"references", "published_at", "modified_at", "fetched_at",
	"withdrawn_at", "created_at", "updated_at",
}

func newAdvisoryRouter(t *testing.T, pollJob *jobs.CVEPollJob) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewAdvisoryHandlers(db, pollJob)
	r := gin.New()
	r.GET("/admin/advisories", h.ListAdvisories())
	r.POST("/admin/advisories/poll", h.TriggerPoll())
	return mock, r
}

func newMinimalPollJob() *jobs.CVEPollJob {
	cveCfg := &config.CVEConfig{Enabled: false, IntervalHours: 24, OSVEndpoint: "https://api.osv.dev"}
	scanCfg := &config.ScanningConfig{}
	notifCfg := &config.NotificationsConfig{}
	return jobs.NewCVEPollJob(nil, nil, scanCfg, cveCfg, notifCfg)
}

// ---------------------------------------------------------------------------
// ListAdvisories
// ---------------------------------------------------------------------------

func TestListAdvisories_Empty(t *testing.T) {
	mock, r := newAdvisoryRouter(t, nil)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(advisoryCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/advisories", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	advisories, ok := body["advisories"].([]interface{})
	if !ok {
		t.Fatalf("expected advisories array, got %T", body["advisories"])
	}
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestListAdvisories_WithRows(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	refsJSON := []byte(`["https://example.com"]`)

	mock, r := newAdvisoryRouter(t, nil)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(advisoryCols).AddRow(
			id, "osv", "CVE-2024-1234", "high", "Test advisory", "Details here",
			refsJSON, &now, &now, now, nil, now, now,
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/advisories", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	advisories, ok := body["advisories"].([]interface{})
	if !ok {
		t.Fatalf("expected advisories array")
	}
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	item := advisories[0].(map[string]interface{})
	if item["source_id"] != "CVE-2024-1234" {
		t.Errorf("source_id = %v, want CVE-2024-1234", item["source_id"])
	}
	if item["severity"] != "high" {
		t.Errorf("severity = %v, want high", item["severity"])
	}
	if item["withdrawn"].(bool) {
		t.Error("expected withdrawn=false for nil withdrawn_at")
	}
}

func TestListAdvisories_Withdrawn(t *testing.T) {
	now := time.Now()
	id := uuid.New()

	mock, r := newAdvisoryRouter(t, nil)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(advisoryCols).AddRow(
			id, "osv", "GHSA-0001", "medium", "Withdrawn advisory", "",
			[]byte(`[]`), nil, nil, now, &now, now, now,
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/advisories", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	advisories := body["advisories"].([]interface{})
	item := advisories[0].(map[string]interface{})
	if !item["withdrawn"].(bool) {
		t.Error("expected withdrawn=true for set withdrawn_at")
	}
}

func TestListAdvisories_DBError(t *testing.T) {
	mock, r := newAdvisoryRouter(t, nil)

	mock.ExpectQuery("cve_advisories").WillReturnError(errDB)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/advisories", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TriggerPoll
// ---------------------------------------------------------------------------

func TestTriggerPoll_NoPollJob_Returns503(t *testing.T) {
	_, r := newAdvisoryRouter(t, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/advisories/poll", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestTriggerPoll_WithPollJob_Returns202(t *testing.T) {
	pollJob := newMinimalPollJob()
	_, r := newAdvisoryRouter(t, pollJob)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/admin/advisories/poll", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["message"] != "CVE poll queued" {
		t.Errorf("message = %v, want 'CVE poll queued'", body["message"])
	}
}

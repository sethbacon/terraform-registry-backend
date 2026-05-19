package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

var quotaRowCols = []string{
	"organization_id", "storage_bytes_limit", "publishes_per_day", "downloads_per_day",
	"storage_bytes_used", "publishes_today", "downloads_today",
}

func newQuotaRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sqlxDB := sqlx.NewDb(db, "postgres")
	h := NewQuotaHandlers(sqlxDB)
	r := gin.New()
	r.GET("/admin/quotas", h.ListQuotas())
	return mock, r
}

func TestListQuotas_Empty(t *testing.T) {
	mock, r := newQuotaRouter(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnRows(sqlmock.NewRows(quotaRowCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/quotas", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	arr, _ := body["quotas"].([]any)
	if len(arr) != 0 {
		t.Errorf("expected 0 quotas, got %d", len(arr))
	}
}

func TestListQuotas_ComputesRatios(t *testing.T) {
	mock, r := newQuotaRouter(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnRows(sqlmock.NewRows(quotaRowCols).
			AddRow("org-1", 1000, 100, 200, 500, 50, 50).
			AddRow("org-2", 0, 0, 0, 999999, 42, 42)) // unlimited (limit=0)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/quotas", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Quotas []struct {
			OrganizationID string  `json:"organization_id"`
			StorageRatio   float64 `json:"storage_utilization_ratio"`
			PublishRatio   float64 `json:"publish_utilization_ratio"`
			DownloadRatio  float64 `json:"download_utilization_ratio"`
		} `json:"quotas"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Quotas) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(body.Quotas))
	}
	got := body.Quotas[0]
	if got.StorageRatio != 0.5 || got.PublishRatio != 0.5 || got.DownloadRatio != 0.25 {
		t.Errorf("org-1 ratios = %+v, want 0.5/0.5/0.25", got)
	}
	// Unlimited (limit=0) must produce ratio 0 — the dashboard treats 0 as "no warn".
	got2 := body.Quotas[1]
	if got2.StorageRatio != 0 || got2.PublishRatio != 0 || got2.DownloadRatio != 0 {
		t.Errorf("org-2 ratios = %+v, want 0/0/0", got2)
	}
}

func TestListQuotas_WithOrgFilter(t *testing.T) {
	mock, r := newQuotaRouter(t)
	mock.ExpectQuery(`FROM organizations`).
		WithArgs("org-only").
		WillReturnRows(sqlmock.NewRows(quotaRowCols).
			AddRow("org-only", 100, 10, 10, 25, 1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/quotas?organization_id=org-only", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestListQuotas_DBError(t *testing.T) {
	mock, r := newQuotaRouter(t)
	mock.ExpectQuery(`FROM organizations`).
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/quotas", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

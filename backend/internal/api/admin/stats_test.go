package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newStatsRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	h := NewStatsHandler(sqlxDB)

	r := gin.New()
	r.GET("/stats/dashboard", h.GetDashboardStats)
	return mock, r
}

// ---------------------------------------------------------------------------
// GetDashboardStats tests
// ---------------------------------------------------------------------------

func TestGetDashboardStats_Success(t *testing.T) {
	mock, r := newStatsRouter(t)

	// Combined single-query returns 7 values
	combinedCols := []string{
		"module_count", "provider_count", "provider_version_count",
		"user_count", "org_count", "module_downloads", "provider_downloads",
	}
	mock.ExpectQuery("module_count").
		WillReturnRows(sqlmock.NewRows(combinedCols).
			AddRow(int64(10), int64(5), int64(20), int64(15), int64(1), int64(100), int64(200)))
	// Optional mirrored-table queries (errors are silently ignored by handler)
	mock.ExpectQuery("mirrored_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(2)))
	mock.ExpectQuery("mirrored_provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(8)))
	mock.ExpectQuery("scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(3)))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["modules"] == nil {
		t.Error("response missing 'modules' key")
	}
	if resp["providers"] == nil {
		t.Error("response missing 'providers' key")
	}
}

func TestGetDashboardStats_ModulesCountFails(t *testing.T) {
	mock, r := newStatsRouter(t)

	// Combined query failure → 500
	mock.ExpectQuery("module_count").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetDashboardStats_ProvidersCountFails(t *testing.T) {
	mock, r := newStatsRouter(t)

	// Combined query failure → 500 (providers count is part of the same combined query)
	mock.ExpectQuery("module_count").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

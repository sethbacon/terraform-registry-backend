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

// expectCount registers a COUNT query expectation returning the given value.
func expectCount(mock sqlmock.Sqlmock, pattern string, val int64) {
	mock.ExpectQuery(pattern).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(val))
}

// ---------------------------------------------------------------------------
// GetDashboardStats tests
// ---------------------------------------------------------------------------

func TestGetDashboardStats_Success(t *testing.T) {
	mock, r := newStatsRouter(t)

	// Required queries (must succeed) and optional ones (failures are ignored by handler)
	// All set in the exact order they are called by the handler.
	expectCount(mock, "SELECT COUNT.*FROM modules", 10)
	expectCount(mock, "SELECT COUNT.*FROM providers", 5)
	expectCount(mock, "SELECT COUNT.*FROM mirrored_providers", 2)
	expectCount(mock, "SELECT COUNT.*FROM provider_versions", 20)
	expectCount(mock, "SELECT COUNT.*FROM mirrored_provider_versions", 8)
	expectCount(mock, "SELECT COUNT.*FROM users", 15)
	expectCount(mock, "SELECT COUNT.*FROM organizations", 1)
	expectCount(mock, "SELECT COUNT.*FROM scm_providers", 3)
	expectCount(mock, "SELECT.*FROM module_versions", 100)
	expectCount(mock, "SELECT.*FROM provider_platforms", 200)

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

	mock.ExpectQuery("SELECT COUNT.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetDashboardStats_ProvidersCountFails(t *testing.T) {
	mock, r := newStatsRouter(t)

	expectCount(mock, "SELECT COUNT.*FROM modules", 10)
	mock.ExpectQuery("SELECT COUNT.*FROM providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

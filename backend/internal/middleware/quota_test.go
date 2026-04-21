package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

func TestNewQuotaChecker(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	qc := NewQuotaChecker(db)
	if qc == nil {
		t.Fatal("NewQuotaChecker returned nil")
	}
}

func quotaRouter(qc *QuotaChecker, quotaType string) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("organization_id", "org-1")
		c.Next()
	})
	if quotaType == "publish" {
		r.Use(qc.CheckPublishQuota())
	} else {
		r.Use(qc.CheckDownloadQuota())
	}
	r.POST("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestCheckPublishQuota_NoOrgID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	qc := NewQuotaChecker(db)
	r := gin.New()
	r.Use(qc.CheckPublishQuota())
	r.POST("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when no org_id", w.Code)
	}
}

func TestCheckPublishQuota_NotExceeded(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"limit", "used"}).AddRow(100, 5)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "publish")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when quota not exceeded", w.Code)
	}
}

func TestCheckPublishQuota_Exceeded(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"limit", "used"}).AddRow(10, 10)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "publish")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 when quota exceeded", w.Code)
	}
	if w.Header().Get("X-Quota-Reset") == "" {
		t.Error("missing X-Quota-Reset header")
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestCheckPublishQuota_DBError_FailOpen(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery("SELECT").WillReturnError(sqlmock.ErrCancelled)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "publish")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fail open on DB error)", w.Code)
	}
}

func TestCheckPublishQuota_UnlimitedQuota(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"limit", "used"}).AddRow(0, 999)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "publish")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when limit=0 (unlimited)", w.Code)
	}
}

func TestCheckDownloadQuota_NoOrgID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	qc := NewQuotaChecker(db)
	r := gin.New()
	r.Use(qc.CheckDownloadQuota())
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when no org_id", w.Code)
	}
}

func TestCheckDownloadQuota_Exceeded(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"limit", "used"}).AddRow(1000, 1000)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "download")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", w.Code)
	}
}

func TestCheckDownloadQuota_DBError_FailOpen(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery("SELECT").WillReturnError(sqlmock.ErrCancelled)

	qc := NewQuotaChecker(db)
	r := quotaRouter(qc, "download")

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fail open)", w.Code)
	}
}

func TestIncrementPublishCount(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("INSERT INTO org_quota_usage").
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	qc := NewQuotaChecker(db)
	err := qc.IncrementPublishCount(t.Context(), "org-1")
	if err != nil {
		t.Fatalf("IncrementPublishCount() = %v", err)
	}
}

func TestIncrementDownloadCount(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("INSERT INTO org_quota_usage").
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	qc := NewQuotaChecker(db)
	err := qc.IncrementDownloadCount(t.Context(), "org-1")
	if err != nil {
		t.Fatalf("IncrementDownloadCount() = %v", err)
	}
}

func TestUpdateStorageUsage(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("INSERT INTO org_quota_usage").
		WithArgs("org-1", int64(1024)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	qc := NewQuotaChecker(db)
	err := qc.UpdateStorageUsage(t.Context(), "org-1", 1024)
	if err != nil {
		t.Fatalf("UpdateStorageUsage() = %v", err)
	}
}

func TestUpdateMetrics(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"org_id", "storage_limit", "storage_used", "pub_limit", "pub_used", "dl_limit", "dl_used"}).
		AddRow("org-1", int64(1000000), int64(500000), 100, 50, 10000, 5000)

	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	qc := NewQuotaChecker(db)
	// Should not panic
	qc.UpdateMetrics(t.Context())
}

func TestUpdateMetrics_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery("SELECT").WillReturnError(sqlmock.ErrCancelled)

	qc := NewQuotaChecker(db)
	// Should not panic
	qc.UpdateMetrics(t.Context())
}

func TestNextMidnightUTC(t *testing.T) {
	midnight := nextMidnightUTC()
	now := time.Now().UTC()

	if !midnight.After(now) {
		t.Error("nextMidnightUTC() should be in the future")
	}
	if midnight.Hour() != 0 || midnight.Minute() != 0 || midnight.Second() != 0 {
		t.Errorf("nextMidnightUTC() = %v, not midnight", midnight)
	}
}

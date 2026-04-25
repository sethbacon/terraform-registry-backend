package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// GetScanningConfigHandler
// ---------------------------------------------------------------------------

func TestGetScanningConfigHandler_Success(t *testing.T) {
	cfg := &config.ScanningConfig{
		Enabled:           true,
		Tool:              "trivy",
		ExpectedVersion:   "0.50.0",
		SeverityThreshold: "HIGH",
		Timeout:           5 * time.Minute,
		WorkerCount:       4,
		ScanIntervalMins:  10,
		// BinaryPath intentionally empty so binary_found=false without a real binary.
	}

	r := gin.New()
	r.GET("/scanning/config", GetScanningConfigHandler(cfg))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/scanning/config", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp ScanningConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Enabled {
		t.Error("expected Enabled=true")
	}
	if resp.Tool != "trivy" {
		t.Errorf("Tool = %q, want trivy", resp.Tool)
	}
	if resp.WorkerCount != 4 {
		t.Errorf("WorkerCount = %d, want 4", resp.WorkerCount)
	}
	if resp.ScanIntervalMins != 10 {
		t.Errorf("ScanIntervalMins = %d, want 10", resp.ScanIntervalMins)
	}
	if resp.BinaryFound {
		t.Error("expected BinaryFound=false when BinaryPath is empty")
	}
	if resp.DetectedVersion != nil {
		t.Error("expected DetectedVersion=nil when binary not found")
	}
}

func TestGetScanningConfigHandler_Disabled(t *testing.T) {
	cfg := &config.ScanningConfig{
		Enabled: false,
		Timeout: time.Second,
	}

	r := gin.New()
	r.GET("/scanning/config", GetScanningConfigHandler(cfg))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/scanning/config", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp ScanningConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Enabled {
		t.Error("expected Enabled=false")
	}
}

// ---------------------------------------------------------------------------
// GetScanningStatsHandler
// ---------------------------------------------------------------------------

func TestGetScanningStatsHandler_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")

	r := gin.New()
	r.GET("/scanning/stats", GetScanningStatsHandler(sqlxDB))

	// Mock aggregate counts
	mock.ExpectQuery("module_version_scans").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "pending", "scanning", "clean", "findings", "error_count",
		}).AddRow(100, 5, 2, 80, 10, 3))

	// Mock recent scans
	now := time.Now()
	mock.ExpectQuery("module_version_scans s").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "version", "name", "namespace", "system",
			"scanner", "status",
			"critical_count", "high_count", "medium_count", "low_count",
			"scanned_at", "created_at",
		}).AddRow(
			"scan-1", "1.0.0", "vpc", "hashicorp", "aws",
			"trivy", "findings",
			1, 2, 3, 0,
			now, now,
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/scanning/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp ScanningStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 100 {
		t.Errorf("Total = %d, want 100", resp.Total)
	}
	if resp.Clean != 80 {
		t.Errorf("Clean = %d, want 80", resp.Clean)
	}
	if len(resp.RecentScans) != 1 {
		t.Errorf("len(RecentScans) = %d, want 1", len(resp.RecentScans))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetScanningStatsHandler_CountQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")

	r := gin.New()
	r.GET("/scanning/stats", GetScanningStatsHandler(sqlxDB))

	mock.ExpectQuery("module_version_scans").
		WillReturnError(&scanTestDBErr{"query failed"})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/scanning/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestGetScanningStatsHandler_RecentQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")

	r := gin.New()
	r.GET("/scanning/stats", GetScanningStatsHandler(sqlxDB))

	// Aggregate succeeds
	mock.ExpectQuery("module_version_scans").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "pending", "scanning", "clean", "findings", "error_count",
		}).AddRow(10, 0, 0, 10, 0, 0))

	// Recent scans query fails
	mock.ExpectQuery("module_version_scans s").
		WillReturnError(&scanTestDBErr{"recent query failed"})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/scanning/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

type scanTestDBErr struct{ msg string }

func (e *scanTestDBErr) Error() string { return e.msg }

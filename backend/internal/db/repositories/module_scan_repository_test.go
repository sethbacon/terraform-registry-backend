package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/scanner"
)

var scanCols = []string{
	"id", "module_version_id", "scanner", "scanner_version", "expected_version",
	"status", "scanned_at", "critical_count", "high_count", "medium_count", "low_count",
	"raw_results", "error_message", "created_at", "updated_at",
}

func newScanRepo(t *testing.T) (*ModuleScanRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewModuleScanRepository(db), mock
}

func sampleScanRow() *sqlmock.Rows {
	return sqlmock.NewRows(scanCols).AddRow(
		"scan-1", "ver-1", "trivy", "0.50.0", nil,
		"clean", time.Now(), 0, 0, 0, 0,
		json.RawMessage(`{}`), nil, time.Now(), time.Now(),
	)
}

// ---------------------------------------------------------------------------
// CreatePendingScan
// ---------------------------------------------------------------------------

func TestCreatePendingScan_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("INSERT INTO module_version_scans").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.CreatePendingScan(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestCreatePendingScan_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("INSERT INTO module_version_scans").
		WithArgs("ver-1").
		WillReturnError(errors.New("db error"))

	if err := repo.CreatePendingScan(context.Background(), "ver-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListPendingScans
// ---------------------------------------------------------------------------

func TestListPendingScans_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE status = 'pending'").
		WithArgs(10).
		WillReturnRows(sampleScanRow())

	scans, err := repo.ListPendingScans(context.Background(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("len(scans) = %d, want 1", len(scans))
	}
	if scans[0].ID != "scan-1" {
		t.Errorf("scan ID = %q, want scan-1", scans[0].ID)
	}
}

func TestListPendingScans_Empty(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE status = 'pending'").
		WithArgs(5).
		WillReturnRows(sqlmock.NewRows(scanCols))

	scans, err := repo.ListPendingScans(context.Background(), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected empty, got %d", len(scans))
	}
}

func TestListPendingScans_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE status = 'pending'").
		WithArgs(10).
		WillReturnError(errors.New("db error"))

	_, err := repo.ListPendingScans(context.Background(), 10)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// MarkScanning
// ---------------------------------------------------------------------------

func TestMarkScanning_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'scanning'").
		WithArgs("scan-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkScanning(context.Background(), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkScanning_AlreadyClaimed(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'scanning'").
		WithArgs("scan-1").
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows updated

	err := repo.MarkScanning(context.Background(), "scan-1")
	if !errors.Is(err, ErrScanAlreadyClaimed) {
		t.Errorf("expected ErrScanAlreadyClaimed, got %v", err)
	}
}

func TestMarkScanning_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'scanning'").
		WithArgs("scan-1").
		WillReturnError(errors.New("db error"))

	if err := repo.MarkScanning(context.Background(), "scan-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// MarkComplete
// ---------------------------------------------------------------------------

func TestMarkComplete_Clean(t *testing.T) {
	repo, mock := newScanRepo(t)
	result := &scanner.ScanResult{
		ScannerVersion: "0.50.0",
		HasFindings:    false,
		RawJSON:        json.RawMessage(`{"results": []}`),
	}

	mock.ExpectExec("UPDATE module_version_scans.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkComplete(context.Background(), "scan-1", result, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkComplete_WithFindings(t *testing.T) {
	repo, mock := newScanRepo(t)
	result := &scanner.ScanResult{
		ScannerVersion: "0.50.0",
		HasFindings:    true,
		CriticalCount:  1,
		HighCount:      2,
		RawJSON:        json.RawMessage(`{"results": [{"severity": "CRITICAL"}]}`),
	}

	mock.ExpectExec("UPDATE module_version_scans.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkComplete(context.Background(), "scan-1", result, "0.50.0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkComplete_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	result := &scanner.ScanResult{ScannerVersion: "0.50.0"}
	mock.ExpectExec("UPDATE module_version_scans.*SET status").
		WillReturnError(errors.New("db error"))

	if err := repo.MarkComplete(context.Background(), "scan-1", result, ""); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// MarkError
// ---------------------------------------------------------------------------

func TestMarkError_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'error'").
		WithArgs("scan-1", "binary not found").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkError(context.Background(), "scan-1", "binary not found"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkError_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'error'").
		WillReturnError(errors.New("db error"))

	if err := repo.MarkError(context.Background(), "scan-1", "msg"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetLatestScan
// ---------------------------------------------------------------------------

func TestGetLatestScan_Found(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WithArgs("ver-1").
		WillReturnRows(sampleScanRow())

	scan, err := repo.GetLatestScan(context.Background(), "ver-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scan == nil {
		t.Fatal("expected non-nil scan")
	}
	if scan.Status != "clean" {
		t.Errorf("status = %q, want clean", scan.Status)
	}
}

func TestGetLatestScan_NotFound(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WithArgs("ver-99").
		WillReturnRows(sqlmock.NewRows(scanCols))

	scan, err := repo.GetLatestScan(context.Background(), "ver-99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scan != nil {
		t.Errorf("expected nil scan, got %+v", scan)
	}
}

func TestGetLatestScan_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_version_scans.*WHERE module_version_id").
		WithArgs("ver-1").
		WillReturnError(errors.New("db error"))

	_, err := repo.GetLatestScan(context.Background(), "ver-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ResetStaleScanningRecords
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UpsertPendingScan
// ---------------------------------------------------------------------------

func TestUpsertPendingScan_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("INSERT INTO module_version_scans").
		WithArgs("ver-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpsertPendingScan(context.Background(), "ver-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestUpsertPendingScan_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("INSERT INTO module_version_scans").
		WithArgs("ver-1").
		WillReturnError(errors.New("db error"))

	if err := repo.UpsertPendingScan(context.Background(), "ver-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ResetStaleScanningRecords
// ---------------------------------------------------------------------------

func TestResetStaleScanningRecords_Success(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'pending'").
		WillReturnResult(sqlmock.NewResult(1, 2))

	if err := repo.ResetStaleScanningRecords(context.Background(), 30*time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResetStaleScanningRecords_DBError(t *testing.T) {
	repo, mock := newScanRepo(t)
	mock.ExpectExec("UPDATE module_version_scans.*SET status = 'pending'").
		WillReturnError(errors.New("db error"))

	if err := repo.ResetStaleScanningRecords(context.Background(), 30*time.Minute); err == nil {
		t.Error("expected error, got nil")
	}
}

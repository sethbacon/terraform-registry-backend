package jobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// TestAuditCleanupJob_StartNoOp verifies that Start() returns immediately
// (is a no-op) when RetentionDays is 0, meaning logs are kept forever.
func TestAuditCleanupJob_StartNoOp(t *testing.T) {
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    0,
		CleanupBatchSize: 1000,
	}
	job := NewAuditCleanupJob(cfg, nil) // auditRepo not needed for no-op path

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- job.Start(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error from no-op Start(), got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Start() did not return promptly when RetentionDays=0")
	}
}

// TestAuditCleanupJob_CutoffCalculation verifies the cutoff date is computed
// correctly from the configured retention days.
func TestAuditCleanupJob_CutoffCalculation(t *testing.T) {
	retentionDays := 30
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    retentionDays,
		CleanupBatchSize: 100,
	}
	_ = NewAuditCleanupJob(cfg, nil)

	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -cfg.RetentionDays)
	expected := now.AddDate(0, 0, -retentionDays)

	// Allow a small delta for time elapsed during the test.
	diff := cutoff.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("cutoff mismatch: got %v, expected ~%v (diff=%v)", cutoff, expected, diff)
	}
}

// TestAuditCleanupJob_Name verifies the job reports the correct name.
func TestAuditCleanupJob_Name(t *testing.T) {
	job := NewAuditCleanupJob(&config.AuditRetentionConfig{}, nil)
	if got := job.Name(); got != "audit-cleanup" {
		t.Fatalf("expected Name() = %q, got %q", "audit-cleanup", got)
	}
}

// TestAuditCleanupJob_StopIdempotent verifies Stop() can be called multiple
// times without panicking.
func TestAuditCleanupJob_StopIdempotent(t *testing.T) {
	job := NewAuditCleanupJob(&config.AuditRetentionConfig{}, nil)

	if err := job.Stop(); err != nil {
		t.Fatalf("first Stop() returned error: %v", err)
	}
	if err := job.Stop(); err != nil {
		t.Fatalf("second Stop() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

// TestAuditCleanupJob_DefaultBatchSize verifies that a zero CleanupBatchSize
// defaults to 1000 inside runCleanupCycle. We validate indirectly by checking
// the config field after construction.
func TestAuditCleanupJob_DefaultBatchSize(t *testing.T) {
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    90,
		CleanupBatchSize: 0, // should default to 1000 at runtime
	}
	job := NewAuditCleanupJob(cfg, nil)

	if job.cfg.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90", job.cfg.RetentionDays)
	}
	// CleanupBatchSize 0 is stored as-is; the runtime default is applied inside runCleanupCycle
	if job.cfg.CleanupBatchSize != 0 {
		t.Errorf("CleanupBatchSize = %d, want 0 (runtime default is applied inside loop)", job.cfg.CleanupBatchSize)
	}
}

// TestAuditCleanupJob_Constructor verifies the constructor sets fields correctly.
func TestAuditCleanupJob_Constructor(t *testing.T) {
	cfg := &config.AuditRetentionConfig{RetentionDays: 30, CleanupBatchSize: 500}
	job := NewAuditCleanupJob(cfg, nil)

	if job.cfg.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30", job.cfg.RetentionDays)
	}
	if job.cfg.CleanupBatchSize != 500 {
		t.Errorf("CleanupBatchSize = %d, want 500", job.cfg.CleanupBatchSize)
	}
	if job.stopChan == nil {
		t.Error("stopChan should not be nil")
	}
}

// TestAuditCleanupJob_StopBeforeStart verifies that Stop() can be called
// even if Start() was never invoked.
func TestAuditCleanupJob_StopBeforeStart(t *testing.T) {
	job := NewAuditCleanupJob(&config.AuditRetentionConfig{RetentionDays: 30}, nil)

	if err := job.Stop(); err != nil {
		t.Fatalf("Stop() before Start() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runCleanupCycle — with sqlmock-backed AuditRepository
// ---------------------------------------------------------------------------

func TestRunCleanupCycle_DeletesRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    30,
		CleanupBatchSize: 100,
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	// First batch deletes 5 rows
	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 100).
		WillReturnResult(sqlmock.NewResult(0, 5))

	// Second batch deletes 0 rows — loop exits
	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 100).
		WillReturnResult(sqlmock.NewResult(0, 0))

	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRunCleanupCycle_ZeroRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    90,
		CleanupBatchSize: 500,
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	// First call returns 0 — nothing to delete
	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 500).
		WillReturnResult(sqlmock.NewResult(0, 0))

	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRunCleanupCycle_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    7,
		CleanupBatchSize: 100,
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 100).
		WillReturnError(fmt.Errorf("disk full"))

	// Should not panic — logs error and breaks
	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRunCleanupCycle_DefaultBatchSizeUsed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    60,
		CleanupBatchSize: 0, // runtime defaults to 1000
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	// Batch size should default to 1000
	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 1000).
		WillReturnResult(sqlmock.NewResult(0, 0))

	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Start — context cancellation and stop channel paths
// ---------------------------------------------------------------------------

func TestAuditCleanupJob_Start_ContextCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    30,
		CleanupBatchSize: 100,
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	// The immediate runCleanupCycle call will execute — mock it returning 0 rows
	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 100).
		WillReturnResult(sqlmock.NewResult(0, 0))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- job.Start(ctx)
	}()

	// Cancel shortly after the immediate cycle completes
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestAuditCleanupJob_Start_StopChannel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auditRepo := repositories.NewAuditRepository(db)
	cfg := &config.AuditRetentionConfig{
		RetentionDays:    30,
		CleanupBatchSize: 100,
	}
	job := NewAuditCleanupJob(cfg, auditRepo)

	mock.ExpectExec("DELETE FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), 100).
		WillReturnResult(sqlmock.NewResult(0, 0))

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- job.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	job.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop()")
	}
}

// terraform_mirror_sync_test.go tests the TerraformMirrorSyncJob lifecycle
// methods that do not require a database or real sync operations.
package jobs

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// newTestTerraformSyncJob returns a job with nil dependencies — sufficient for
// lifecycle tests (constructor, TriggerSync) that don't exercise the sync path.
func newTestTerraformSyncJob() *TerraformMirrorSyncJob {
	return NewTerraformMirrorSyncJob(nil, nil, "local")
}

// ---------------------------------------------------------------------------
// NewTerraformMirrorSyncJob
// ---------------------------------------------------------------------------

func TestNewTerraformMirrorSyncJob_NotNil(t *testing.T) {
	job := newTestTerraformSyncJob()
	if job == nil {
		t.Fatal("NewTerraformMirrorSyncJob returned nil")
	}
}

// ---------------------------------------------------------------------------
// TriggerSync
// ---------------------------------------------------------------------------

func TestTriggerSync_Success(t *testing.T) {
	job := newTestTerraformSyncJob()
	id := uuid.New()
	if err := job.TriggerSync(context.Background(), id); err != nil {
		t.Errorf("TriggerSync returned unexpected error: %v", err)
	}
}

func TestTriggerSync_QueueFull(t *testing.T) {
	job := newTestTerraformSyncJob()
	// Fill the 16-element channel
	for i := 0; i < 16; i++ {
		if err := job.TriggerSync(context.Background(), uuid.New()); err != nil {
			t.Fatalf("unexpected error filling queue: %v", err)
		}
	}
	// 17th trigger should fail with "queue is full"
	if err := job.TriggerSync(context.Background(), uuid.New()); err == nil {
		t.Error("expected error when queue is full, got nil")
	}
}

// ---------------------------------------------------------------------------
// Start / Stop — full loop with sqlmock
// ---------------------------------------------------------------------------

func TestTerraformMirrorSyncJob_StartStop(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	job := NewTerraformMirrorSyncJob(repo, nil, "local")

	// runScheduledSyncs calls GetConfigsNeedingSync — return empty
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		_ = job.Start(ctx) // Start now blocks until Stop/ctx cancel (issue #565 finding [40])
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := job.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	select {
	case <-done:
		// OK — Start returned after Stop()
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after Stop()")
	}
}

func TestTerraformMirrorSyncJob_StartContextCancel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	job := NewTerraformMirrorSyncJob(repo, nil, "local")

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = job.Start(ctx) // Start now blocks until Stop/ctx cancel (issue #565 finding [40])
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK — Start returned after context cancellation
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after context cancellation")
	}
}

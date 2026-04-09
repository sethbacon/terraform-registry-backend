// terraform_mirror_sync_test.go tests the TerraformMirrorSyncJob lifecycle
// methods that do not require a database or real sync operations.
package jobs

import (
	"context"
	"testing"

	"github.com/google/uuid"
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

// module_scanner_job_test.go tests the ModuleScannerJob constructor and lifecycle
// methods that do not require a real scanner binary.
package jobs

import (
	"context"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// newTestScannerJob returns a job configured with scanning disabled so that
// Start() returns immediately without attempting to exec a binary.
func newTestScannerJob(enabled bool, binaryPath string) *ModuleScannerJob {
	cfg := &config.ScanningConfig{
		Enabled:    enabled,
		BinaryPath: binaryPath,
	}
	return NewModuleScannerJob(cfg, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// NewModuleScannerJob
// ---------------------------------------------------------------------------

func TestNewModuleScannerJob_NotNil(t *testing.T) {
	job := newTestScannerJob(false, "")
	if job == nil {
		t.Fatal("NewModuleScannerJob returned nil")
	}
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestModuleScannerJob_Name(t *testing.T) {
	job := newTestScannerJob(false, "")
	if got := job.Name(); got != "module-scanner" {
		t.Errorf("Name() = %q, want module-scanner", got)
	}
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

func TestModuleScannerJob_Stop(t *testing.T) {
	job := newTestScannerJob(false, "")
	if err := job.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestModuleScannerJob_StopIdempotent(t *testing.T) {
	// Calling Stop twice should not panic (select catches closed channel).
	job := newTestScannerJob(false, "")
	if err := job.Stop(); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := job.Stop(); err != nil {
		t.Errorf("second Stop() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Start — early-exit branches (no binary required)
// ---------------------------------------------------------------------------

func TestModuleScannerJob_Start_Disabled(t *testing.T) {
	job := newTestScannerJob(false, "")
	if err := job.Start(context.Background()); err != nil {
		t.Errorf("Start (disabled) error = %v", err)
	}
}

func TestModuleScannerJob_Start_EmptyBinaryPath(t *testing.T) {
	job := newTestScannerJob(true, "") // enabled but no binary
	if err := job.Start(context.Background()); err != nil {
		t.Errorf("Start (empty binary) error = %v", err)
	}
}

func TestModuleScannerJob_Start_InaccessibleBinary(t *testing.T) {
	// Enabled with a non-existent binary — scanner.New() fails; Start returns nil (non-fatal)
	job := newTestScannerJob(true, "/nonexistent/path/to/scanner")
	if err := job.Start(context.Background()); err != nil {
		t.Errorf("Start (inaccessible binary) error = %v", err)
	}
}

func TestModuleScannerJob_Start_AlreadyRunning(t *testing.T) {
	// Simulate a job that is already started; calling Start again must be a no-op.
	job := newTestScannerJob(true, "/nonexistent/path/to/scanner")
	job.started = true
	if err := job.Start(context.Background()); err != nil {
		t.Errorf("Start (already running) error = %v", err)
	}
}

func TestModuleScannerJob_Stop_ResetsStarted(t *testing.T) {
	job := newTestScannerJob(false, "")
	job.started = true
	if err := job.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if job.started {
		t.Error("Stop() did not reset started flag")
	}
}

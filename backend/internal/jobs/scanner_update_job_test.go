// scanner_update_job_test.go contains pure-logic unit tests for ScannerUpdateJob
// that require no live database: resolveScannerApproval decision logic and the
// non-blocking TriggerCheck channel semantics. Full runCheck/Activate flows need
// a live Postgres and are intentionally not covered here.
package jobs

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// newTestScannerUpdateJob builds a ScannerUpdateJob with only scanCfg populated,
// sufficient for resolveScannerApproval which reads scanCfg exclusively.
func newTestScannerUpdateJob(scanCfg *config.ScanningConfig) *ScannerUpdateJob {
	return NewScannerUpdateJob(
		scanCfg,
		&config.NotificationsConfig{},
		&config.CVEConfig{},
		nil, // sbvRepo
		nil, // approvalRepo
		nil, // oidcCfgRepo
		nil, // scannerJob
		nil, // check (defaults to installer.CheckLatest, unused here)
		nil, // download (defaults to installer.DownloadVerified, unused here)
	)
}

func TestSupersededDirsToRemove(t *testing.T) {
	installDir := t.TempDir()
	activeID := uuid.New()
	active := &models.ScannerBinaryVersion{ID: activeID, Tool: "trivy", Version: "0.72.0"}

	activeDir := filepath.Join(installDir, "trivy-0.72.0")
	supersededDir := filepath.Join(installDir, "trivy-0.71.0")
	bp := func(s string) *string { return &s }

	rows := []models.ScannerBinaryVersion{
		// the active row itself — skipped by id
		{ID: activeID, Tool: "trivy", Version: "0.72.0", BinaryPath: bp(filepath.Join(activeDir, "trivy"))},
		// a stale DUPLICATE row for the active version with a different id — must be
		// skipped by the active-version-dir guard (this is the incident scenario)
		{ID: uuid.New(), Tool: "trivy", Version: "0.72.0", BinaryPath: bp(filepath.Join(activeDir, "trivy"))},
		// a genuinely superseded version — removable
		{ID: uuid.New(), Tool: "trivy", Version: "0.71.0", BinaryPath: bp(filepath.Join(supersededDir, "trivy"))},
		// a row with no recorded binary path — skipped
		{ID: uuid.New(), Tool: "trivy", Version: "0.70.0", BinaryPath: nil},
		// the bare symlink path (dir is InstallDir, not a versioned dir) — skipped
		{ID: uuid.New(), Tool: "trivy", Version: "sym", BinaryPath: bp(filepath.Join(installDir, "trivy"))},
	}

	got := supersededDirsToRemove(rows, active, installDir)

	if len(got) != 1 || got[0] != supersededDir {
		t.Fatalf("supersededDirsToRemove = %v, want [%s]", got, supersededDir)
	}
	// The active version's directory must never be scheduled for removal, even though
	// a duplicate row referenced it with a different id.
	for _, d := range got {
		if d == activeDir {
			t.Fatalf("active version dir %q must never be removed", activeDir)
		}
	}
}

func TestResolveScannerApproval(t *testing.T) {
	tests := []struct {
		name              string
		requiresApproval  bool
		autoApproveRules  string
		version           string
		signatureVerified bool
		existing          []string
		wantStatus        string // "" means expect nil pointer
		wantRule          string
	}{
		{
			name:             "requires_approval false always approves, no rule",
			requiresApproval: false,
			version:          "0.53.0",
			wantStatus:       "approved",
			wantRule:         "",
		},
		{
			name:             "requires_approval true, no rules configured -> pending",
			requiresApproval: true,
			autoApproveRules: "",
			version:          "0.53.0",
			wantStatus:       "pending_approval",
			wantRule:         "",
		},
		{
			name:              "requires_approval true, matching patch_only + gpg_verified rule -> approved",
			requiresApproval:  true,
			autoApproveRules:  `{"mode":"any","rules":[{"type":"patch_only"},{"type":"gpg_verified"}]}`,
			version:           "0.53.1",
			signatureVerified: true,
			existing:          []string{"0.53.0"},
			wantStatus:        "approved",
			wantRule:          "patch_only",
		},
		{
			name:              "requires_approval true, non-matching rule -> pending",
			requiresApproval:  true,
			autoApproveRules:  `{"mode":"any","rules":[{"type":"patch_only"}]}`,
			version:           "1.0.0",
			signatureVerified: true,
			existing:          []string{"0.53.0"},
			wantStatus:        "pending_approval",
			wantRule:          "",
		},
		{
			name:             "requires_approval true, invalid rules JSON -> pending",
			requiresApproval: true,
			autoApproveRules: "not json",
			version:          "0.53.0",
			wantStatus:       "pending_approval",
			wantRule:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanCfg := &config.ScanningConfig{
				AutoUpdate: config.ScannerAutoUpdateConfig{
					RequiresApproval: tt.requiresApproval,
					AutoApproveRules: tt.autoApproveRules,
				},
			}
			job := newTestScannerUpdateJob(scanCfg)

			status, rule := job.resolveScannerApproval(tt.version, tt.signatureVerified, tt.existing)

			if tt.wantStatus == "" {
				if status != nil {
					t.Fatalf("status = %v, want nil", *status)
				}
			} else {
				if status == nil {
					t.Fatalf("status = nil, want %q", tt.wantStatus)
				}
				if *status != tt.wantStatus {
					t.Errorf("status = %q, want %q", *status, tt.wantStatus)
				}
			}
			if rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", rule, tt.wantRule)
			}
		})
	}
}

// TestScannerUpdateJob_RestartSafety proves Stop() is idempotent and that a
// stopped job can be re-armed for a subsequent Start() (previously Stop() did
// a one-shot close() with no reset, so a second Stop() panicked and
// Start-after-Stop exited immediately on the already-closed channel). This
// exercises the mutex/started/stopChan bookkeeping directly rather than
// running the full check/reconcile loop, which needs live repos.
func TestScannerUpdateJob_RestartSafety(t *testing.T) {
	scanCfg := &config.ScanningConfig{
		AutoUpdate: config.ScannerAutoUpdateConfig{Enabled: true},
	}
	job := newTestScannerUpdateJob(scanCfg)

	// Stop() before any Start() must not panic (never started).
	job.Stop()
	if job.started {
		t.Fatal("expected started=false after Stop() on a never-started job")
	}

	// Simulate what Start() does under the mutex without invoking the full
	// check/reconcile loop.
	job.mu.Lock()
	job.started = true
	job.mu.Unlock()

	job.Stop()
	if job.started {
		t.Fatal("expected started=false after Stop()")
	}

	// A second Stop() call must not panic (previously: double-close panic).
	job.Stop()

	// stopChan must be a fresh, open channel after Stop() so Start() can run
	// again (previously the closed channel would make the select's
	// case <-stopChan fire immediately).
	job.mu.Lock()
	stopChan := job.stopChan
	job.mu.Unlock()
	select {
	case <-stopChan:
		t.Fatal("stopChan should be open (freshly reset) after Stop(), not already closed")
	default:
	}

	// Re-arm and stop again to prove the cycle repeats without panicking.
	job.mu.Lock()
	job.started = true
	job.mu.Unlock()
	job.Stop()
}

func TestScannerUpdateJob_Name(t *testing.T) {
	job := newTestScannerUpdateJob(&config.ScanningConfig{})
	if got := job.Name(); got != "scanner-update" {
		t.Errorf("Name() = %q, want %q", got, "scanner-update")
	}
}

func TestScannerUpdateJob_TriggerCheck_NonBlocking(t *testing.T) {
	job := newTestScannerUpdateJob(&config.ScanningConfig{})

	// Fill the buffered channel, then confirm further triggers don't block.
	job.TriggerCheck()

	done := make(chan struct{})
	go func() {
		job.TriggerCheck()
		job.TriggerCheck()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TriggerCheck blocked with a full buffer")
	}
}

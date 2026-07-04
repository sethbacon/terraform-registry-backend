// scanner_update_job_test.go contains pure-logic unit tests for ScannerUpdateJob
// that require no live database: resolveScannerApproval decision logic and the
// non-blocking TriggerCheck channel semantics. Full runCheck/Activate flows need
// a live Postgres and are intentionally not covered here.
package jobs

import (
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
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

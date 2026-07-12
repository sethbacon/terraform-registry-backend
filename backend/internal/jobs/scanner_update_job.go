// scanner_update_job.go implements ScannerUpdateJob, a background job that checks
// upstream for newer module security-scanner (trivy/terrascan/checkov) releases,
// downloads and verifies them into a versioned present-but-inactive path, files a
// version-approval row (auto-approved when a matching rule fires, otherwise
// pending), and emails admins. Approved-but-inactive versions are picked up by
// the activation reconciler, which updates the scanning configuration and
// restarts ModuleScannerJob against the new binary.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/notify"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// ScannerUpdateJob periodically checks upstream for newer scanner releases and
// reconciles approved-but-inactive versions into the running scanner.
type ScannerUpdateJob struct {
	scanCfg      *config.ScanningConfig
	notifCfg     *config.NotificationsConfig
	cveCfg       *config.CVEConfig
	sbvRepo      *repositories.ScannerBinaryVersionRepository
	approvalRepo *repositories.VersionApprovalRepository
	oidcCfgRepo  *repositories.OIDCConfigRepository
	scannerJob   *ModuleScannerJob
	mailer       *notify.Mailer
	check        installer.CheckFunc
	download     installer.InstallFunc
	stopChan     chan struct{}
	manualCh     chan struct{}
	mu           sync.Mutex
	started      bool
}

// NewScannerUpdateJob constructs a ScannerUpdateJob. check and download default to
// installer.CheckLatest and installer.DownloadVerified when nil, allowing tests to
// inject stubs.
func NewScannerUpdateJob(
	scanCfg *config.ScanningConfig,
	notifCfg *config.NotificationsConfig,
	cveCfg *config.CVEConfig,
	sbvRepo *repositories.ScannerBinaryVersionRepository,
	approvalRepo *repositories.VersionApprovalRepository,
	oidcCfgRepo *repositories.OIDCConfigRepository,
	scannerJob *ModuleScannerJob,
	check installer.CheckFunc,
	download installer.InstallFunc,
) *ScannerUpdateJob {
	if check == nil {
		check = installer.CheckLatest
	}
	if download == nil {
		download = installer.DownloadVerified
	}
	return &ScannerUpdateJob{
		scanCfg:      scanCfg,
		notifCfg:     notifCfg,
		cveCfg:       cveCfg,
		sbvRepo:      sbvRepo,
		approvalRepo: approvalRepo,
		oidcCfgRepo:  oidcCfgRepo,
		scannerJob:   scannerJob,
		mailer:       notify.New(&notifCfg.SMTP),
		check:        check,
		download:     download,
		stopChan:     make(chan struct{}),
		manualCh:     make(chan struct{}, 1),
	}
}

// Name returns the human-readable job name used in logs.
func (j *ScannerUpdateJob) Name() string { return "scanner-update" }

// Start begins the background update-check loop. It runs an initial check (plus
// activation reconciliation) immediately on startup, then repeats on the
// configured interval. The loop exits when ctx is cancelled or Stop() is called.
// coverage:skip:integration-only — drives runCheck/reconcileActivations on a live ticker loop against a real GitHub release feed, DB, and SMTP; TestScannerUpdateJob_RestartSafety exercises the mu/started/stopChan bookkeeping directly without invoking the loop body.
func (j *ScannerUpdateJob) Start(ctx context.Context) error {
	if !j.scanCfg.AutoUpdate.Enabled {
		log.Println("[scanner-update] disabled (scanning.auto_update.enabled=false)")
		return nil
	}

	j.mu.Lock()
	if j.started {
		j.mu.Unlock()
		log.Println("[scanner-update] already running, ignoring duplicate Start")
		return nil
	}
	j.started = true
	stopChan := j.stopChan // capture under mutex; Stop() may replace the field concurrently
	j.mu.Unlock()

	intervalHours := j.scanCfg.AutoUpdate.IntervalHours
	if intervalHours <= 0 {
		intervalHours = 24
	}
	interval := time.Duration(intervalHours) * time.Hour

	log.Printf("[scanner-update] started (interval: %v)", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately at startup.
	j.runCheck(ctx)
	j.reconcileActivations(ctx)

	for {
		select {
		case <-ticker.C:
			j.runCheck(ctx)
			j.reconcileActivations(ctx)
		case <-j.manualCh:
			log.Println("[scanner-update] manual trigger received")
			j.runCheck(ctx)
			j.reconcileActivations(ctx)
		case <-stopChan:
			log.Println("[scanner-update] stopped")
			return nil
		case <-ctx.Done():
			log.Println("[scanner-update] context cancelled")
			j.mu.Lock()
			j.started = false
			j.mu.Unlock()
			return nil
		}
	}
}

// TriggerCheck sends a non-blocking signal to run a check immediately.
// If a check is already queued, this call is a no-op.
func (j *ScannerUpdateJob) TriggerCheck() {
	select {
	case j.manualCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit. Safe to call multiple times and
// safe to call when the job was never started; a subsequent Start() can run
// again since the stop channel is replaced with a fresh one.
func (j *ScannerUpdateJob) Stop() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.started {
		close(j.stopChan)
		j.stopChan = make(chan struct{}) // fresh channel so Start() can be called again
		j.started = false
	}
	return nil
}

// runCheck queries upstream for the latest release of the configured tool and,
// if newer than the active/expected version and not already discovered,
// downloads+verifies it into a versioned present-but-inactive path, records it,
// and notifies admins.
// coverage:skip:integration-only — calls the live GitHub release check + download and the real ScannerBinaryVersionRepository; resolveScannerApproval (the pure decision logic it delegates to) is unit-tested independently.
func (j *ScannerUpdateJob) runCheck(ctx context.Context) {
	tool := j.scanCfg.Tool
	if j.scanCfg.InstallDir == "" {
		log.Println("[scanner-update] scanning.install_dir is not configured; skipping check")
		return
	}

	latest, err := j.check(ctx, installer.InstallConfig{InstallDir: j.scanCfg.InstallDir}, tool)
	if err != nil {
		log.Printf("[scanner-update] failed to check latest version for %s: %v", tool, err)
		return
	}

	current := j.scanCfg.ExpectedVersion
	if active, err := j.sbvRepo.GetActive(ctx, tool); err == nil && active != nil {
		current = active.Version
	}
	if strings.TrimPrefix(latest.LatestVersion, "v") == strings.TrimPrefix(current, "v") {
		log.Printf("[scanner-update] %s is up to date (version %s)", tool, latest.LatestVersion)
		return
	}

	if existing, err := j.sbvRepo.GetByToolVersion(ctx, tool, latest.LatestVersion); err == nil && existing != nil {
		// Already discovered on a previous check/tick.
		return
	}

	res, err := j.download(ctx, installer.InstallConfig{InstallDir: j.scanCfg.InstallDir, SignatureMode: j.scanCfg.SignatureVerification}, tool, latest.LatestVersion)
	if err != nil {
		log.Printf("[scanner-update] failed to download %s %s: %v", tool, latest.LatestVersion, err)
		failed := &models.ScannerBinaryVersion{
			ID:         uuid.New(),
			Tool:       tool,
			Version:    latest.LatestVersion,
			SyncStatus: "failed",
		}
		if upErr := j.sbvRepo.Upsert(ctx, failed); upErr != nil {
			log.Printf("[scanner-update] failed to record failed download for %s %s: %v", tool, latest.LatestVersion, upErr)
		}
		return
	}

	var existingVersions []string
	if rows, err := j.sbvRepo.ListForTool(ctx, tool); err == nil {
		for _, row := range rows {
			existingVersions = append(existingVersions, row.Version)
		}
	}

	status, autoRule := j.resolveScannerApproval(latest.LatestVersion, res.SignatureVerified, existingVersions)

	v := &models.ScannerBinaryVersion{
		ID:                uuid.New(),
		Tool:              tool,
		Version:           latest.LatestVersion,
		SourceURL:         &res.SourceURL,
		Sha256:            &res.Sha256,
		SignatureVerified: res.SignatureVerified,
		SignatureType:     res.SignatureType,
		SyncStatus:        "downloaded",
		BinaryPath:        &res.BinaryPath,
		ApprovalStatus:    status,
	}
	if err := j.sbvRepo.Upsert(ctx, v); err != nil {
		log.Printf("[scanner-update] failed to record discovered version %s %s: %v", tool, latest.LatestVersion, err)
		return
	}

	if autoRule != "" && j.approvalRepo != nil {
		rule := autoRule
		if err := j.approvalRepo.RecordEvent(ctx, &models.VersionApprovalEvent{
			ScannerBinaryVersionID: &v.ID,
			Action:                 models.VersionApprovalActionAuto,
			AutoApproveRule:        &rule,
		}); err != nil {
			log.Printf("[scanner-update] failed to record auto-approve event for %s %s: %v", tool, latest.LatestVersion, err)
		}
	}

	j.notify(ctx, v, status)
}

// resolveScannerApproval decides the approval_status for a freshly discovered
// scanner version. It returns an approved pointer immediately when the operator
// has opted out of approval gating, a pending pointer when review is required,
// or an approved pointer plus the matched rule name when an auto-approve rule
// fires.
func (j *ScannerUpdateJob) resolveScannerApproval(version string, signatureVerified bool, existing []string) (*string, string) {
	pending := models.VersionApprovalStatusPending
	approved := models.VersionApprovalStatusApproved

	if !j.scanCfg.AutoUpdate.RequiresApproval {
		return &approved, ""
	}

	rules, err := mirror.ParseAutoApproveRules(&j.scanCfg.AutoUpdate.AutoApproveRules)
	if err != nil {
		log.Printf("[scanner-update] invalid scanning.auto_update.auto_approve_rules: %v", err)
		return &pending, ""
	}
	if rules == nil {
		return &pending, ""
	}

	matched, rule := mirror.EvaluateAutoApprove(rules, mirror.AutoApproveInput{
		Version:          version,
		GPGVerified:      signatureVerified,
		ExistingVersions: existing,
		VersionAge:       0, // just discovered; delay_hours rules never match immediately
	})
	if matched {
		return &approved, rule
	}
	return &pending, ""
}

// reconcileActivations picks up approved-but-inactive scanner versions and
// activates them.
// coverage:skip:integration-only — requires a live ScannerBinaryVersionRepository (PostgreSQL) to list approved-inactive rows and drives Activate for each.
func (j *ScannerUpdateJob) reconcileActivations(ctx context.Context) {
	rows, err := j.sbvRepo.ListApprovedInactive(ctx)
	if err != nil {
		log.Printf("[scanner-update] failed to list approved-inactive versions: %v", err)
		return
	}
	for i := range rows {
		row := rows[i]
		if err := j.Activate(ctx, &row); err != nil {
			log.Printf("[scanner-update] failed to activate %s %s: %v", row.Tool, row.Version, err)
		}
	}
}

// Activate installs the given already-downloaded version as the running scanner
// binary: it updates the scanning configuration (binary path + expected
// version), persists it, restarts ModuleScannerJob, marks the version active,
// and best-effort cleans up superseded versioned binaries for the tool. Shared
// by the activation reconciler and the manual install+activate admin endpoint.
// coverage:skip:integration-only — persists scanning config via a live OIDCConfigRepository (PostgreSQL), restarts a real ModuleScannerJob, and marks the version active via a live ScannerBinaryVersionRepository; exercised by the integration suite.
func (j *ScannerUpdateJob) Activate(ctx context.Context, v *models.ScannerBinaryVersion) error {
	if v.BinaryPath == nil {
		return fmt.Errorf("scanner binary version %s (%s %s) has no binary_path", v.ID, v.Tool, v.Version)
	}

	if j.scanCfg.InstallDir != "" {
		cleanBinary := filepath.Clean(*v.BinaryPath)
		cleanInstall := filepath.Clean(j.scanCfg.InstallDir)
		if !strings.HasPrefix(cleanBinary, cleanInstall+string(filepath.Separator)) {
			return fmt.Errorf("binary_path %q is outside the scanner install directory", *v.BinaryPath)
		}
	}

	j.scanCfg.BinaryPath = *v.BinaryPath
	j.scanCfg.ExpectedVersion = v.Version

	persisted := config.ScanningConfigDB{
		Enabled:           j.scanCfg.Enabled,
		Tool:              j.scanCfg.Tool,
		BinaryPath:        j.scanCfg.BinaryPath,
		ExpectedVersion:   j.scanCfg.ExpectedVersion,
		SeverityThreshold: j.scanCfg.SeverityThreshold,
		TimeoutSecs:       int(j.scanCfg.Timeout.Seconds()),
		WorkerCount:       j.scanCfg.WorkerCount,
		ScanIntervalMins:  j.scanCfg.ScanIntervalMins,
		InstallDir:        j.scanCfg.InstallDir,
		AutoUpdate: config.ScannerAutoUpdateDB{
			Enabled:          j.scanCfg.AutoUpdate.Enabled,
			IntervalHours:    j.scanCfg.AutoUpdate.IntervalHours,
			RequiresApproval: j.scanCfg.AutoUpdate.RequiresApproval,
			AutoApproveRules: j.scanCfg.AutoUpdate.AutoApproveRules,
		},
	}
	jsonBytes, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("marshal scanning config: %w", err)
	}
	if j.oidcCfgRepo != nil {
		if err := j.oidcCfgRepo.SetScanningConfig(ctx, jsonBytes); err != nil {
			return fmt.Errorf("persist scanning config: %w", err)
		}
	}

	if j.scannerJob != nil {
		_ = j.scannerJob.Stop()
		// ModuleScannerJob is a long-lived daemon (indefinite polling loop). Its restart
		// must outlive the caller's ctx — which, via the admin install+activate handler,
		// is the HTTP request context and would cancel the job the moment the request
		// returns. context.Background() is therefore intentional here, not a leak.
		go func() { // #nosec G118 -- long-lived daemon restart must not inherit the request-scoped caller ctx
			if err := j.scannerJob.Start(context.Background()); err != nil {
				log.Printf("[scanner-update] scanner job failed to restart after activation: %v", err)
			}
		}()
	}

	if err := j.sbvRepo.MarkActive(ctx, v.ID); err != nil {
		return fmt.Errorf("mark scanner binary version active: %w", err)
	}

	j.cleanupSuperseded(ctx, v)
	return nil
}

// cleanupSuperseded best-effort removes versioned install directories for other
// versions of the tool now that active is the current version. Never fails
// activation; errors are logged only. The set of directories to remove is decided
// by supersededDirsToRemove (unit-tested); this method performs only the IO.
// coverage:skip:integration-only — requires a live ScannerBinaryVersionRepository (PostgreSQL) plus real filesystem directories under InstallDir; only ever called from Activate. The removal decision is covered by TestSupersededDirsToRemove.
func (j *ScannerUpdateJob) cleanupSuperseded(ctx context.Context, active *models.ScannerBinaryVersion) {
	rows, err := j.sbvRepo.ListForTool(ctx, active.Tool)
	if err != nil {
		log.Printf("[scanner-update] cleanup: failed to list versions for %s: %v", active.Tool, err)
		return
	}
	for _, dir := range supersededDirsToRemove(rows, active, j.scanCfg.InstallDir) {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[scanner-update] cleanup: failed to remove superseded dir %s: %v", dir, err)
		}
	}
}

// supersededDirsToRemove returns the versioned install directories safe to remove
// now that active is the current version. A directory qualifies only when it
// belongs to a different row, sits under the tool's versioned prefix
// ({InstallDir}/{tool}-), and is NOT the active version's own directory. That last
// guard is critical: a stale/duplicate row for the active version (a different id
// pointing at the same versioned dir) must never cause the just-activated binary to
// be deleted — the bug this guards against left an empty dir and a dangling symlink.
func supersededDirsToRemove(rows []models.ScannerBinaryVersion, active *models.ScannerBinaryVersion, installDir string) []string {
	versionedPrefix := filepath.Join(installDir, active.Tool+"-")
	activeVersionDir := filepath.Join(installDir, active.Tool+"-"+active.Version)
	var dirs []string
	for _, row := range rows {
		if row.ID == active.ID || row.BinaryPath == nil {
			continue
		}
		dir := filepath.Dir(*row.BinaryPath)
		if dir == activeVersionDir {
			continue // never remove the active version's directory
		}
		if !strings.HasPrefix(dir, versionedPrefix) {
			continue // not a versioned dir (e.g. the active symlink path)
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// notify sends an admin notification email about a newly discovered scanner
// version, guarded by notifications being enabled/configured and recipients
// being present. Never fails the caller; send errors are logged only.
// coverage:skip:integration-only — calls the shared mailer, which requires live SMTP.
func (j *ScannerUpdateJob) notify(_ context.Context, v *models.ScannerBinaryVersion, status *string) {
	if j.notifCfg == nil || !j.notifCfg.Enabled || j.notifCfg.SMTP.Host == "" || len(j.cveCfg.EmailRecipients) == 0 {
		return
	}

	approved := status != nil && *status == models.VersionApprovalStatusApproved

	var subject string
	var body strings.Builder
	if approved {
		subject = fmt.Sprintf("[Security] Scanner update available: %s %s (approved/auto)", v.Tool, v.Version)
	} else {
		subject = fmt.Sprintf("[Security] Scanner update available: %s %s (pending approval)", v.Tool, v.Version)
	}

	fmt.Fprintf(&body, "A new version of the %s security scanner has been discovered.\n\n", v.Tool)
	fmt.Fprintf(&body, "Tool: %s\nVersion: %s\nSignature type: %s\nSignature verified: %t\n\n", v.Tool, v.Version, v.SignatureType, v.SignatureVerified)
	if approved {
		body.WriteString("This version was automatically approved and will be activated automatically.\n")
	} else {
		body.WriteString("This version is pending approval. Log in to review and approve it before it is activated.\n")
	}

	if err := j.mailer.Send(j.cveCfg.EmailRecipients, subject, body.String()); err != nil {
		log.Printf("[scanner-update] failed to send notification email: %v", err)
	}
}

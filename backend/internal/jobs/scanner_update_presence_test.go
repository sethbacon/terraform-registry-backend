// scanner_update_presence_test.go covers issue #1073: [scanner-update] decided
// whether the scanner was current by comparing a database row against the
// upstream release without ever checking that the binary existed. When the two
// disagreed the job logged "up to date" and returned — and that early return is
// the only path to a re-download, so the condition was permanent and
// self-concealing. These tests drive runCheck with a stubbed release check and
// download against sqlmock, so no live Postgres or GitHub access is needed.
package jobs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

var presenceCols = []string{
	"id", "tool", "version", "source_url", "sha256", "signature_verified", "signature_type",
	"sync_status", "approval_status", "is_active", "binary_path", "discovered_at", "created_at",
}

// presenceHarness wires a ScannerUpdateJob whose release check always reports
// latestVersion and whose download records that it was called instead of
// reaching the network.
type presenceHarness struct {
	job          *ScannerUpdateJob
	mock         sqlmock.Sqlmock
	downloadedTo []string
}

func newPresenceHarness(t *testing.T, scanCfg *config.ScanningConfig, latestVersion string) *presenceHarness {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := &presenceHarness{mock: mock}

	check := func(context.Context, installer.InstallConfig, string) (*installer.LatestInfo, error) {
		return &installer.LatestInfo{LatestVersion: latestVersion}, nil
	}
	download := func(_ context.Context, cfg installer.InstallConfig, tool, version string) (*installer.Result, error) {
		h.downloadedTo = append(h.downloadedTo, version)
		return &installer.Result{
			BinaryPath: filepath.Join(cfg.InstallDir, tool+"-"+version, tool),
			Version:    version,
			Sha256:     "deadbeef",
			SourceURL:  "https://example.invalid/" + tool,
		}, nil
	}

	h.job = NewScannerUpdateJob(
		scanCfg,
		&config.NotificationsConfig{},
		&config.CVEConfig{},
		repositories.NewScannerBinaryVersionRepository(sqlx.NewDb(db, "sqlmock")),
		nil, // approvalRepo
		nil, // oidcCfgRepo
		nil, // scannerJob
		check,
		download,
	)
	return h
}

func (h *presenceHarness) expectGetActive(tool, version string, binaryPath *string) uuid.UUID {
	id := uuid.New()
	now := time.Now()
	h.mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions\s+WHERE tool = \$1 AND is_active`).
		WithArgs(tool).
		WillReturnRows(sqlmock.NewRows(presenceCols).AddRow(
			id, tool, version, nil, nil, false, "none",
			"downloaded", models.VersionApprovalStatusApproved, true, binaryPath, now, now,
		))
	return id
}

// installBinary creates a fake scanner binary at {installDir}/{tool} — the
// symlink path ResolveBinaryPath falls back to — and returns its path.
func installBinary(t *testing.T, installDir, tool string) string {
	t.Helper()
	p := filepath.Join(installDir, tool)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

// The #1073 scenario: the DB says trivy 0.74.0 is active, upstream agrees that
// 0.74.0 is latest, and /app/scanners is empty. The job used to log "up to
// date" and return, so the deployment could never heal.
func TestRunCheck_MissingBinaryReinstallsInsteadOfReportingUpToDate(t *testing.T) {
	installDir := t.TempDir()
	scanCfg := &config.ScanningConfig{
		Tool:       "trivy",
		InstallDir: installDir,
		BinaryPath: filepath.Join(installDir, "trivy-0.74.0", "trivy"), // never created
		AutoUpdate: config.ScannerAutoUpdateConfig{RequiresApproval: false},
	}
	h := newPresenceHarness(t, scanCfg, "0.74.0")

	activeID := h.expectGetActive("trivy", "0.74.0", &scanCfg.BinaryPath)

	// The row must stop claiming a version that is not installed.
	h.mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = false, sync_status = 'missing'`).
		WithArgs(activeID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// ListForTool, then the Upsert of the re-downloaded version.
	h.mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions\s+WHERE tool = \$1`).
		WithArgs("trivy").
		WillReturnRows(sqlmock.NewRows(presenceCols))
	now := time.Now()
	h.mock.ExpectQuery(`INSERT INTO scanner_binary_versions`).
		WillReturnRows(sqlmock.NewRows(presenceCols).AddRow(
			uuid.New(), "trivy", "0.74.0", nil, nil, false, "none",
			"downloaded", models.VersionApprovalStatusApproved, false,
			filepath.Join(installDir, "trivy-0.74.0", "trivy"), now, now,
		))

	h.job.runCheck(context.Background())

	if len(h.downloadedTo) == 0 {
		t.Fatal("no download was attempted for a scanner whose binary does not exist; " +
			"the job reported the DB's active version as current and returned, which is the " +
			"only path to a re-install — the deployment can never recover on its own")
	}
	if h.downloadedTo[0] != "0.74.0" {
		t.Errorf("reinstalled version = %q, want 0.74.0", h.downloadedTo[0])
	}
	if err := h.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The same missing binary, but a row for the latest version already exists. The
// "already discovered on a previous check" guard is the second early return
// that blocks repair, so it must not fire while the binary is absent.
func TestRunCheck_MissingBinarySkipsAlreadyDiscoveredGuard(t *testing.T) {
	installDir := t.TempDir()
	scanCfg := &config.ScanningConfig{
		Tool:       "trivy",
		InstallDir: installDir,
		BinaryPath: filepath.Join(installDir, "trivy-0.73.0", "trivy"), // never created
		AutoUpdate: config.ScannerAutoUpdateConfig{RequiresApproval: false},
	}
	h := newPresenceHarness(t, scanCfg, "0.74.0")

	activeID := h.expectGetActive("trivy", "0.73.0", &scanCfg.BinaryPath)
	h.mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = false, sync_status = 'missing'`).
		WithArgs(activeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	h.mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions\s+WHERE tool = \$1`).
		WithArgs("trivy").
		WillReturnRows(sqlmock.NewRows(presenceCols))
	now := time.Now()
	h.mock.ExpectQuery(`INSERT INTO scanner_binary_versions`).
		WillReturnRows(sqlmock.NewRows(presenceCols).AddRow(
			uuid.New(), "trivy", "0.74.0", nil, nil, false, "none",
			"downloaded", models.VersionApprovalStatusApproved, false,
			filepath.Join(installDir, "trivy-0.74.0", "trivy"), now, now,
		))

	h.job.runCheck(context.Background())

	if len(h.downloadedTo) == 0 {
		t.Fatal("the already-discovered guard suppressed a re-download while the binary was absent")
	}
	if err := h.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// With the binary actually present, "up to date" is still a no-op — the fix
// must not turn every tick into a re-download.
func TestRunCheck_UpToDateWhenBinaryPresent(t *testing.T) {
	installDir := t.TempDir()
	binary := installBinary(t, installDir, "trivy")
	scanCfg := &config.ScanningConfig{
		Tool:       "trivy",
		InstallDir: installDir,
		BinaryPath: binary,
	}
	h := newPresenceHarness(t, scanCfg, "0.74.0")
	h.expectGetActive("trivy", "0.74.0", &binary)

	h.job.runCheck(context.Background())

	if len(h.downloadedTo) != 0 {
		t.Fatalf("downloaded %v for an up-to-date scanner whose binary is present", h.downloadedTo)
	}
	if err := h.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Marking a row active asserts the binary is there; Activate is how the DB
// came to assert something false in the first place.
func TestActivate_RefusesVersionWhoseBinaryIsAbsent(t *testing.T) {
	installDir := t.TempDir()
	scanCfg := &config.ScanningConfig{Tool: "trivy", InstallDir: installDir}
	h := newPresenceHarness(t, scanCfg, "0.74.0")

	missing := filepath.Join(installDir, "trivy-0.74.0", "trivy")
	err := h.job.Activate(context.Background(), &models.ScannerBinaryVersion{
		ID: uuid.New(), Tool: "trivy", Version: "0.74.0", BinaryPath: &missing,
	})
	if err == nil {
		t.Fatal("Activate promoted a version whose binary does not exist; the scanning config " +
			"and the active row would both name a file that is not there")
	}
	if scanCfg.BinaryPath != "" {
		t.Errorf("scanning config was mutated by a rejected activation: binary_path = %q",
			scanCfg.BinaryPath)
	}
}

func TestVersionsEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.74.0", "0.74.0", true},
		{"0.74.0", "v0.74.0", true},
		{"0.74.0", "0.74.0", true},
		{"v0.74.0", "v0.73.0", false},
		{"0.74.0", "", false},
	}
	for _, c := range cases {
		if got := versionsEqual(c.a, c.b); got != c.want {
			t.Errorf("versionsEqual(%q, %q) = %t, want %t", c.a, c.b, got, c.want)
		}
	}
}

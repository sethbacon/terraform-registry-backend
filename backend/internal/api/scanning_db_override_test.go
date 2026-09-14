package api

import (
	"os"
	"path/filepath"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #1072: scanning.enabled=false was not an off switch. It was the exact
// condition under which the persisted DB config was applied wholesale, so a
// database restored from another environment silently re-enabled scanning and
// pointed it at that environment's filesystem paths. These tests pin the three
// states down: config wins when enabled, the DB may still turn scanning on for
// the setup-wizard flow, and allow_db_override=false makes the operator's "no"
// final.

// installedScanner creates a fake scanner binary under a temp install dir and
// returns (installDir, binaryPath). The reload path now stats the binary before
// trusting a persisted config, so a test asserting the happy path must provide
// one that actually exists.
func installedScanner(t *testing.T, tool, version string) (string, string) {
	t.Helper()
	installDir := t.TempDir()
	versionDir := filepath.Join(installDir, tool+"-"+version)
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	binaryPath := filepath.Join(versionDir, tool)
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return installDir, binaryPath
}

func scanningRepo(t *testing.T, blob string) *repositories.OIDCConfigRepository {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.MatchExpectationsInOrder(false)
	// reloadScanningConfigFromDB used to read the row twice; one expectation
	// that may match any number of times keeps this test honest either way.
	mock.ExpectQuery("SELECT scanning_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_config"}).AddRow([]byte(blob))).
		RowsWillBeClosed()

	return repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))
}

func TestReloadScanningConfigFromDB_AllowDBOverrideFalseKeepsScanningOff(t *testing.T) {
	installDir, binaryPath := installedScanner(t, "trivy", "0.74.0")

	blob := `{"enabled":true,"tool":"trivy","binary_path":"` + filepath.ToSlash(binaryPath) +
		`","install_dir":"` + filepath.ToSlash(installDir) +
		`","auto_update":{"enabled":true,"interval_hours":6}}`

	cfg := &config.Config{}
	cfg.Scanning.Enabled = false
	cfg.Scanning.AllowDBOverride = false
	cfg.Scanning.InstallDir = "/opt/scanners"

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if cfg.Scanning.Enabled {
		t.Fatal("scanning.enabled=false with allow_db_override=false was overridden by the database; " +
			"the operator has no way to turn scanning off")
	}
	if cfg.Scanning.InstallDir != "/opt/scanners" {
		t.Errorf("install_dir = %q, want the config value /opt/scanners; the DB path leaked in",
			cfg.Scanning.InstallDir)
	}
	// The auto-update job gates only on AutoUpdate.Enabled, never on
	// Scanning.Enabled, so a DB-sourced true here would start downloading
	// scanner binaries on a deployment that asked for none.
	if cfg.Scanning.AutoUpdate.Enabled {
		t.Error("auto_update.enabled was loaded from the database despite allow_db_override=false")
	}
}

func TestReloadScanningConfigFromDB_EnablesFromDBWhenBinaryPresent(t *testing.T) {
	installDir, binaryPath := installedScanner(t, "trivy", "0.74.0")

	blob := `{"enabled":true,"tool":"trivy","binary_path":"` + filepath.ToSlash(binaryPath) +
		`","install_dir":"` + filepath.ToSlash(installDir) +
		`","expected_version":"0.74.0","worker_count":3,"timeout_secs":120,` +
		`"scan_interval_mins":9,"auto_update":{"enabled":true,"interval_hours":6}}`

	cfg := &config.Config{}
	cfg.Scanning.AllowDBOverride = true

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if !cfg.Scanning.Enabled {
		t.Fatal("a persisted+enabled scanning config naming a binary that exists was not applied; " +
			"the setup-wizard flow is broken")
	}
	if cfg.Scanning.BinaryPath != filepath.ToSlash(binaryPath) {
		t.Errorf("binary_path = %q, want %q", cfg.Scanning.BinaryPath, binaryPath)
	}
	if cfg.Scanning.ExpectedVersion != "0.74.0" || cfg.Scanning.WorkerCount != 3 {
		t.Errorf("expected_version/worker_count not applied: %q/%d",
			cfg.Scanning.ExpectedVersion, cfg.Scanning.WorkerCount)
	}
	if cfg.Scanning.ScanIntervalMins != 9 {
		t.Errorf("scan_interval_mins = %d, want 9", cfg.Scanning.ScanIntervalMins)
	}
	if !cfg.Scanning.AutoUpdate.Enabled || cfg.Scanning.AutoUpdate.IntervalHours != 6 {
		t.Errorf("auto_update not reloaded: %+v", cfg.Scanning.AutoUpdate)
	}
}

// The AKS -> Azure Container Apps case from #1072: the restored row is valid,
// it just describes a filesystem that does not exist here. The save path stats
// binary_path, but it does so on the machine that WROTE the row.
func TestReloadScanningConfigFromDB_RefusesWhenBinaryAbsentOnThisHost(t *testing.T) {
	emptyInstallDir := t.TempDir()
	missing := filepath.ToSlash(filepath.Join(emptyInstallDir, "trivy-0.74.0", "trivy"))

	blob := `{"enabled":true,"tool":"trivy","binary_path":"` + missing +
		`","install_dir":"` + filepath.ToSlash(emptyInstallDir) + `"}`

	cfg := &config.Config{}
	cfg.Scanning.AllowDBOverride = true

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if cfg.Scanning.Enabled {
		t.Fatal("scanning was enabled from a DB config whose binary does not exist on this host; " +
			"the failure is deferred to scanner.New(), which logs and continues, so the " +
			"deployment looks healthy while scanning is inoperative")
	}
	if cfg.Scanning.BinaryPath != "" {
		t.Errorf("binary_path = %q, want empty; a rejected config must not be partially applied",
			cfg.Scanning.BinaryPath)
	}
}

func TestReloadScanningConfigFromDB_RefusesBinaryPathOutsideInstallDir(t *testing.T) {
	installDir, _ := installedScanner(t, "trivy", "0.74.0")
	outside := t.TempDir()
	escape := filepath.Join(outside, "trivy")
	if err := os.WriteFile(escape, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	blob := `{"enabled":true,"tool":"trivy","binary_path":"` + filepath.ToSlash(escape) +
		`","install_dir":"` + filepath.ToSlash(installDir) + `"}`

	cfg := &config.Config{}
	cfg.Scanning.AllowDBOverride = true

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if cfg.Scanning.Enabled {
		t.Fatal("a DB config naming a binary outside the install directory was applied; " +
			"the save path rejects this shape but the read path let it through")
	}
}

func TestReloadScanningConfigFromDB_RefusesUnsupportedTool(t *testing.T) {
	installDir, binaryPath := installedScanner(t, "trivy", "0.74.0")

	blob := `{"enabled":true,"tool":"../../bin/sh","binary_path":"` + filepath.ToSlash(binaryPath) +
		`","install_dir":"` + filepath.ToSlash(installDir) + `"}`

	cfg := &config.Config{}
	cfg.Scanning.AllowDBOverride = true

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if cfg.Scanning.Enabled {
		t.Fatal("a DB config with a non-allowlisted tool was applied; the tool name flows into " +
			"filepath.Join(InstallDir, Tool)")
	}
}

// When the operator has said yes, the config wins and the DB is consulted only
// for auto-update. This is the half of the original behaviour that was correct.
func TestReloadScanningConfigFromDB_ConfigEnabledWinsOverDB(t *testing.T) {
	_, dbBinary := installedScanner(t, "trivy", "0.74.0")

	blob := `{"enabled":true,"tool":"checkov","binary_path":"` + filepath.ToSlash(dbBinary) +
		`","install_dir":"/db/scanners","auto_update":{"enabled":true,"interval_hours":12}}`

	cfg := &config.Config{}
	cfg.Scanning.Enabled = true
	cfg.Scanning.AllowDBOverride = true
	cfg.Scanning.Tool = "trivy"
	cfg.Scanning.BinaryPath = "/usr/local/bin/trivy"
	cfg.Scanning.InstallDir = "/app/scanners"

	reloadScanningConfigFromDB(cfg, scanningRepo(t, blob))

	if cfg.Scanning.Tool != "trivy" || cfg.Scanning.BinaryPath != "/usr/local/bin/trivy" {
		t.Errorf("config-supplied scanning settings were overwritten by the DB: tool=%q binary_path=%q",
			cfg.Scanning.Tool, cfg.Scanning.BinaryPath)
	}
	if cfg.Scanning.InstallDir != "/app/scanners" {
		t.Errorf("install_dir = %q, want /app/scanners", cfg.Scanning.InstallDir)
	}
	if !cfg.Scanning.AutoUpdate.Enabled || cfg.Scanning.AutoUpdate.IntervalHours != 12 {
		t.Errorf("auto_update must still reload when scanning is enabled via config: %+v",
			cfg.Scanning.AutoUpdate)
	}
}

// Load() must keep the setup-wizard flow working by default, and must let an
// operator turn the override off from env alone.
func TestConfigDefault_AllowDBOverride(t *testing.T) {
	t.Setenv("TFR_DATABASE_PASSWORD", "x")
	cfg, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil && !cfg.Scanning.AllowDBOverride {
		t.Error("scanning.allow_db_override defaulted to false; that would silently disable the " +
			"setup-wizard flow for every existing deployment")
	}
}

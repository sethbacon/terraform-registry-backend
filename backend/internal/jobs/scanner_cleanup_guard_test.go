// scanner_cleanup_guard_test.go covers issue #1076: cleanupSuperseded decides
// what to delete entirely from database rows. On a restored database those rows
// describe a previous deployment's filesystem, and acting on them deleted the
// only scanner binary actually present on the volume. The guard added here
// refuses to garbage-collect while there is no working scanner to fall back to.
package jobs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// newSupersededCleanupJob wires a ScannerUpdateJob with a sqlmock-backed version
// repository so the test can assert whether cleanupSuperseded reached the
// database at all.
func newSupersededCleanupJob(t *testing.T, scanCfg *config.ScanningConfig) (*ScannerUpdateJob, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	j := NewScannerUpdateJob(
		scanCfg,
		&config.NotificationsConfig{},
		&config.CVEConfig{},
		repositories.NewScannerBinaryVersionRepository(sqlx.NewDb(db, "sqlmock")),
		nil, // approvalRepo
		nil, // oidcCfgRepo
		nil, // scannerJob
		nil, // check
		nil, // download
	)
	return j, mock
}

func TestCleanupSuperseded_SkippedWhenNoBinaryPresent(t *testing.T) {
	installDir := t.TempDir()

	// A directory the database considers superseded. It is also, in the incident
	// this test guards against, the only copy of the scanner on the volume.
	staleDir := filepath.Join(installDir, "trivy-0.74.0")
	if err := os.MkdirAll(staleDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// The activated version's own binary is absent — the volume lost it, or the
	// database was restored from another environment.
	scanCfg := &config.ScanningConfig{
		Tool:       "trivy",
		InstallDir: installDir,
		BinaryPath: filepath.Join(installDir, "trivy-0.72.0", "trivy"),
	}
	j, mock := newSupersededCleanupJob(t, scanCfg)

	// Armed but must never fire: reaching the database means the guard did not hold.
	mock.ExpectQuery("SELECT").WithArgs("trivy").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tool", "version", "binary_path"}).
			AddRow(uuid.New(), "trivy", "0.74.0", filepath.Join(staleDir, "trivy")),
	)

	j.cleanupSuperseded(context.Background(), &models.ScannerBinaryVersion{
		ID: uuid.New(), Tool: "trivy", Version: "0.72.0",
	})

	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("cleanup queried for superseded versions despite no working scanner binary")
	}
	if _, err := os.Stat(staleDir); err != nil {
		t.Errorf("cleanup removed %s while no working scanner was present: %v", staleDir, err)
	}
}

// The guard must not become a blanket disable: with the activated binary in
// place, cleanup proceeds as before.
func TestCleanupSuperseded_ProceedsWhenBinaryPresent(t *testing.T) {
	installDir := t.TempDir()
	versionDir := filepath.Join(installDir, "trivy-0.74.0")
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	binaryPath := filepath.Join(versionDir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("stub"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// A stale directory from an earlier version that cleanup should remove.
	staleDir := filepath.Join(installDir, "trivy-0.71.0")
	if err := os.MkdirAll(staleDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	scanCfg := &config.ScanningConfig{
		Tool:       "trivy",
		InstallDir: installDir,
		BinaryPath: binaryPath,
	}
	j, mock := newSupersededCleanupJob(t, scanCfg)

	activeID := uuid.New()
	stalePath := filepath.Join(staleDir, "trivy")
	mock.ExpectQuery("SELECT").WithArgs("trivy").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tool", "version", "binary_path"}).
			AddRow(activeID, "trivy", "0.74.0", binaryPath).
			AddRow(uuid.New(), "trivy", "0.71.0", stalePath),
	)

	j.cleanupSuperseded(context.Background(), &models.ScannerBinaryVersion{
		ID: activeID, Tool: "trivy", Version: "0.74.0",
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("cleanup did not query for superseded versions: %v", err)
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Errorf("superseded dir %s was not removed: %v", staleDir, err)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Errorf("active binary was removed: %v", err)
	}
}

// scanner_binary_version_repository_test.go tests ScannerBinaryVersionRepository
// against sqlmock, mirroring the harness pattern used by
// version_approval_repository_test.go and oidc_config_repository_test.go — no
// live Postgres required.
package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newScannerBinaryVersionRepo(t *testing.T) (*ScannerBinaryVersionRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewScannerBinaryVersionRepository(sqlx.NewDb(db, "sqlmock")), mock
}

var scannerBinaryVersionCols = []string{
	"id", "tool", "version", "source_url", "sha256", "signature_verified", "signature_type",
	"sync_status", "approval_status", "is_active", "binary_path", "discovered_at", "created_at",
}

func TestNewScannerBinaryVersionRepository(t *testing.T) {
	repo, _ := newScannerBinaryVersionRepo(t)
	if repo == nil {
		t.Fatal("expected non-nil repository")
	}
}

func TestScannerBinaryVersionRepository_Upsert_Inserted(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	now := time.Now()
	rows := sqlmock.NewRows(scannerBinaryVersionCols).AddRow(
		uuid.New(), "trivy", "0.60.0", nil, nil, false, "",
		"downloaded", nil, false, nil, now, now,
	)
	mock.ExpectQuery(`INSERT INTO scanner_binary_versions`).WillReturnRows(rows)

	v := &models.ScannerBinaryVersion{Tool: "trivy", Version: "0.60.0", SyncStatus: "downloaded"}
	if err := repo.Upsert(context.Background(), v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID == uuid.Nil {
		t.Error("expected ID to be populated from the returned row")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestScannerBinaryVersionRepository_Upsert_ConflictReturnsExisting(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	// On a (tool, version) conflict the no-op UPDATE returns the EXISTING row, whose
	// id differs from the caller's throwaway id. Upsert must overwrite v with that
	// canonical row so callers reference the real id (a stale id previously caused
	// approval-event FK violations and made cleanup delete the active version).
	existingID := uuid.New()
	now := time.Now()
	rows := sqlmock.NewRows(scannerBinaryVersionCols).AddRow(
		existingID, "trivy", "0.60.0", nil, nil, false, "",
		"downloaded", nil, false, nil, now, now,
	)
	mock.ExpectQuery(`INSERT INTO scanner_binary_versions`).WillReturnRows(rows)

	v := &models.ScannerBinaryVersion{ID: uuid.New(), Tool: "trivy", Version: "0.60.0"}
	if err := repo.Upsert(context.Background(), v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != existingID {
		t.Errorf("expected canonical existing id %s, got %s", existingID, v.ID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestScannerBinaryVersionRepository_Upsert_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`INSERT INTO scanner_binary_versions`).WillReturnError(errors.New("db down"))

	v := &models.ScannerBinaryVersion{Tool: "trivy", Version: "0.60.0"}
	if err := repo.Upsert(context.Background(), v); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_GetByToolVersion_Found(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	now := time.Now()
	rows := sqlmock.NewRows(scannerBinaryVersionCols).AddRow(
		uuid.New(), "trivy", "0.60.0", nil, nil, false, "",
		"downloaded", nil, false, nil, now, now,
	)
	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND version = \$2`).
		WithArgs("trivy", "0.60.0").
		WillReturnRows(rows)

	v, err := repo.GetByToolVersion(context.Background(), "trivy", "0.60.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil || v.Version != "0.60.0" {
		t.Fatalf("unexpected result: %+v", v)
	}
}

func TestScannerBinaryVersionRepository_GetByToolVersion_NotFound(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND version = \$2`).
		WithArgs("trivy", "9.9.9").
		WillReturnRows(sqlmock.NewRows(scannerBinaryVersionCols))

	v, err := repo.GetByToolVersion(context.Background(), "trivy", "9.9.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil, got: %+v", v)
	}
}

func TestScannerBinaryVersionRepository_GetByToolVersion_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND version = \$2`).
		WillReturnError(errors.New("db down"))

	if _, err := repo.GetByToolVersion(context.Background(), "trivy", "0.60.0"); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_ListForTool(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	now := time.Now()
	rows := sqlmock.NewRows(scannerBinaryVersionCols).
		AddRow(uuid.New(), "trivy", "0.60.0", nil, nil, false, "", "downloaded", nil, false, nil, now, now).
		AddRow(uuid.New(), "trivy", "0.59.0", nil, nil, false, "", "downloaded", nil, true, nil, now, now)
	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1`).
		WithArgs("trivy").
		WillReturnRows(rows)

	got, err := repo.ListForTool(context.Background(), "trivy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(got))
	}
}

func TestScannerBinaryVersionRepository_ListForTool_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1`).
		WillReturnError(errors.New("db down"))

	if _, err := repo.ListForTool(context.Background(), "trivy"); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_ListApprovedInactive(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	now := time.Now()
	approved := "approved"
	rows := sqlmock.NewRows(scannerBinaryVersionCols).
		AddRow(uuid.New(), "trivy", "0.60.0", nil, nil, false, "", "downloaded", approved, false, nil, now, now)
	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE approval_status = 'approved' AND NOT is_active`).
		WillReturnRows(rows)

	got, err := repo.ListApprovedInactive(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
}

func TestScannerBinaryVersionRepository_ListApprovedInactive_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE approval_status = 'approved' AND NOT is_active`).
		WillReturnError(errors.New("db down"))

	if _, err := repo.ListApprovedInactive(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_MarkActive_Success(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = false`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = true WHERE id = \$1`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repo.MarkActive(context.Background(), id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestScannerBinaryVersionRepository_MarkActive_BeginError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectBegin().WillReturnError(errors.New("db down"))

	if err := repo.MarkActive(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_MarkActive_DemoteError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = false`).
		WillReturnError(errors.New("db down"))
	mock.ExpectRollback()

	if err := repo.MarkActive(context.Background(), id); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_MarkActive_PromoteError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	id := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = false`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE scanner_binary_versions SET is_active = true WHERE id = \$1`).
		WillReturnError(errors.New("db down"))
	mock.ExpectRollback()

	if err := repo.MarkActive(context.Background(), id); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_GetActive_Found(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	now := time.Now()
	rows := sqlmock.NewRows(scannerBinaryVersionCols).AddRow(
		uuid.New(), "trivy", "0.60.0", nil, nil, false, "", "downloaded", nil, true, nil, now, now,
	)
	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND is_active`).
		WithArgs("trivy").
		WillReturnRows(rows)

	v, err := repo.GetActive(context.Background(), "trivy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil || !v.IsActive {
		t.Fatalf("unexpected result: %+v", v)
	}
}

func TestScannerBinaryVersionRepository_GetActive_NotFound(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND is_active`).
		WithArgs("trivy").
		WillReturnRows(sqlmock.NewRows(scannerBinaryVersionCols))

	v, err := repo.GetActive(context.Background(), "trivy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil, got: %+v", v)
	}
}

func TestScannerBinaryVersionRepository_GetActive_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectQuery(`SELECT .* FROM scanner_binary_versions WHERE tool = \$1 AND is_active`).
		WillReturnError(errors.New("db down"))

	if _, err := repo.GetActive(context.Background(), "trivy"); err == nil {
		t.Fatal("expected error")
	}
}

func TestScannerBinaryVersionRepository_Delete_Success(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	id := uuid.New()
	mock.ExpectExec(`DELETE FROM scanner_binary_versions WHERE id = \$1`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Delete(context.Background(), id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScannerBinaryVersionRepository_Delete_DBError(t *testing.T) {
	repo, mock := newScannerBinaryVersionRepo(t)

	mock.ExpectExec(`DELETE FROM scanner_binary_versions WHERE id = \$1`).
		WillReturnError(errors.New("db down"))

	if err := repo.Delete(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected error")
	}
}

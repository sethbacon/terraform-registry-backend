package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newVersionApprovalRepo(t *testing.T) (*VersionApprovalRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewVersionApprovalRepository(sqlx.NewDb(db, "sqlmock")), mock
}

var versionApprovalCols = []string{
	"id", "type", "version", "approval_status",
	"provider_namespace", "provider_name",
	"mirror_config_name", "mirror_config_id",
	"gpg_verified", "shasum_verified", "synced_at",
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestVersionApprovalList_Success(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	id := uuid.New()
	cfgID := uuid.New()
	ns, name := "hashicorp", "aws"
	gpg, sha := true, true
	rows := sqlmock.NewRows(versionApprovalCols).AddRow(
		id, "provider", "5.0.0", "pending_approval",
		ns, name, "prod-mirror", cfgID, gpg, sha, time.Now(),
	)
	mock.ExpectQuery(`SELECT \* FROM`).WillReturnRows(rows)

	items, total, err := repo.List(context.Background(), VersionApprovalFilter{Status: "pending_approval"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected 1 item/total, got items=%d total=%d", len(items), total)
	}
	if items[0].Type != "provider" || items[0].Version != "5.0.0" {
		t.Fatalf("unexpected item: %+v", items[0])
	}
}

func TestVersionApprovalList_TypeFilters(t *testing.T) {
	// Each type filter narrows the inner query to a single branch; exercise both
	// plus the default UNION to cover innerQuery.
	for _, typ := range []string{"provider", "terraform", "scanner", ""} {
		t.Run("type="+typ, func(t *testing.T) {
			repo, mock := newVersionApprovalRepo(t)
			mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			mock.ExpectQuery(`SELECT \* FROM`).
				WillReturnRows(sqlmock.NewRows(versionApprovalCols))

			_, _, err := repo.List(context.Background(), VersionApprovalFilter{Type: typ, ConfigID: uuid.New().String()})
			if err != nil {
				t.Fatalf("unexpected error for type %q: %v", typ, err)
			}
		})
	}
}

func TestInnerQuery_Scanner(t *testing.T) {
	q := innerQuery(models.VersionApprovalTypeScanner)
	if !strings.Contains(q, "scanner_binary_versions") {
		t.Fatalf("expected innerQuery(scanner) to reference scanner_binary_versions, got: %s", q)
	}
}

func TestInnerQuery_Default_IncludesAllBranches(t *testing.T) {
	q := innerQuery("")
	for _, table := range []string{"mirrored_provider_versions", "terraform_versions", "scanner_binary_versions"} {
		if !strings.Contains(q, table) {
			t.Fatalf("expected default innerQuery to reference %s, got: %s", table, q)
		}
	}
}

func TestVersionApprovalList_Empty(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT \* FROM`).
		WillReturnRows(sqlmock.NewRows(versionApprovalCols))

	items, total, err := repo.List(context.Background(), VersionApprovalFilter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("expected empty, got items=%d total=%d", len(items), total)
	}
}

func TestVersionApprovalList_CountError(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM`).WillReturnError(fmt.Errorf("db error"))

	if _, _, err := repo.List(context.Background(), VersionApprovalFilter{}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PendingCount
// ---------------------------------------------------------------------------

func TestVersionApprovalPendingCount(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	mock.ExpectQuery(`SELECT`).
		WithArgs(models.VersionApprovalStatusPending).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	got, err := repo.PendingCount(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// SetStatus
// ---------------------------------------------------------------------------

func TestVersionApprovalSetStatus_Provider(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WithArgs(id, "approved").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := repo.SetStatus(context.Background(), id, "approved", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVersionApprovalSetStatus_Terraform(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	id := uuid.New()
	cfgID := uuid.New()

	mock.ExpectBegin()
	// Provider update affects no rows -> fall through to terraform.
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WithArgs(id, "rejected").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE terraform_versions SET approval_status`).
		WithArgs(id, "rejected").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT config_id FROM terraform_versions`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"config_id"}).AddRow(cfgID))
	mock.ExpectExec(`UPDATE terraform_versions SET is_latest = false`).
		WithArgs(cfgID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE terraform_versions SET is_latest = true`).
		WithArgs(cfgID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repo.SetStatus(context.Background(), id, "rejected", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVersionApprovalSetStatus_Scanner(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	id := uuid.New()

	mock.ExpectBegin()
	// Provider and terraform updates affect no rows -> fall through to scanner.
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WithArgs(id, "approved").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE terraform_versions SET approval_status`).
		WithArgs(id, "approved").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE scanner_binary_versions SET approval_status`).
		WithArgs(id, "approved").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := repo.SetStatus(context.Background(), id, "approved", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVersionApprovalSetStatus_NotFound(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE mirrored_provider_versions SET approval_status`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE terraform_versions SET approval_status`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE scanner_binary_versions SET approval_status`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := repo.SetStatus(context.Background(), id, "approved", nil, nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

func TestVersionApprovalEvents(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	id := uuid.New()
	name := "alice"

	cols := []string{
		"id", "mirrored_provider_version_id", "terraform_version_id",
		"action", "performed_by", "performed_by_name", "notes", "auto_approve_rule", "created_at",
	}
	rows := sqlmock.NewRows(cols).AddRow(
		uuid.New(), id, nil, "approved", uuid.New(), name, nil, nil, time.Now(),
	)
	mock.ExpectQuery(`FROM version_approval_events`).
		WithArgs(id).
		WillReturnRows(rows)

	events, err := repo.Events(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Action != "approved" {
		t.Fatalf("unexpected events: %+v", events)
	}
	if events[0].PerformedByName == nil || *events[0].PerformedByName != "alice" {
		t.Fatalf("expected performed_by_name alice, got %+v", events[0].PerformedByName)
	}
}

// ---------------------------------------------------------------------------
// RecordEvent
// ---------------------------------------------------------------------------

func TestVersionApprovalRecordEvent(t *testing.T) {
	repo, mock := newVersionApprovalRepo(t)
	mpvID := uuid.New()
	rule := "gpg_verified"

	mock.ExpectExec(`INSERT INTO version_approval_events`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.RecordEvent(context.Background(), &models.VersionApprovalEvent{
		MirroredProviderVersionID: &mpvID,
		Action:                    models.VersionApprovalActionAuto,
		AutoApproveRule:           &rule,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

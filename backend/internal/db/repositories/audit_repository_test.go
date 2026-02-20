package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var auditCols = []string{
	"id", "user_id", "organization_id", "action",
	"resource_type", "resource_id", "metadata", "ip_address", "created_at",
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newAuditRepo(t *testing.T) (*AuditRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAuditRepository(db), mock
}

func sampleAuditRow() *sqlmock.Rows {
	return sqlmock.NewRows(auditCols).
		AddRow("log-1", "user-1", "org-1", "CREATE",
			"module", "module-1", []byte(`{"key":"val"}`), "1.2.3.4", time.Now())
}

// ---------------------------------------------------------------------------
// CreateAuditLog
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

func TestCreateAuditLog_Success(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	log := &models.AuditLog{
		UserID:         strPtr("user-1"),
		OrganizationID: strPtr("org-1"),
		Action:         "CREATE",
		ResourceType:   strPtr("module"),
		ResourceID:     strPtr("module-1"),
		IPAddress:      strPtr("1.2.3.4"),
	}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAuditLog_WithMetadata(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	log := &models.AuditLog{
		UserID:       strPtr("user-1"),
		Action:       "UPDATE",
		ResourceType: strPtr("provider"),
		Metadata:     map[string]interface{}{"version": "1.0.0"},
	}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAuditLog_DBError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnError(errDB)

	log := &models.AuditLog{Action: "CREATE"}
	if err := repo.CreateAuditLog(context.Background(), log); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListAuditLogs
// ---------------------------------------------------------------------------

func TestListAuditLogs_NoFilters(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT id.*FROM audit_logs").
		WillReturnRows(sampleAuditRow())

	logs, total, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(logs) != 1 {
		t.Errorf("len(logs) = %d, want 1", len(logs))
	}
}

func TestListAuditLogs_WithFilters(t *testing.T) {
	repo, mock := newAuditRepo(t)
	userID := "user-1"
	orgID := "org-1"
	action := "CREATE"
	resourceType := "module"

	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT id.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows(auditCols))

	logs, total, err := repo.ListAuditLogs(context.Background(), AuditFilters{
		UserID:         &userID,
		OrganizationID: &orgID,
		Action:         &action,
		ResourceType:   &resourceType,
	}, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(logs) != 0 {
		t.Errorf("len(logs) = %d, want 0", len(logs))
	}
}

func TestListAuditLogs_CountError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnError(errDB)

	_, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListAuditLogs_QueryError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT id.*FROM audit_logs").
		WillReturnError(errDB)

	_, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAuditLog
// ---------------------------------------------------------------------------

func TestGetAuditLog_Found(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnRows(sampleAuditRow())

	log, err := repo.GetAuditLog(context.Background(), "log-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log == nil {
		t.Fatal("expected log, got nil")
	}
	if log.ID != "log-1" {
		t.Errorf("ID = %q, want %q", log.ID, "log-1")
	}
}

func TestGetAuditLog_NotFound(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnRows(sqlmock.NewRows(auditCols))

	log, err := repo.GetAuditLog(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log != nil {
		t.Errorf("expected nil, got %v", log)
	}
}

func TestGetAuditLog_Error(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetAuditLog(context.Background(), "log-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

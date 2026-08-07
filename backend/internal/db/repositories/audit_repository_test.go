// audit_repository_test.go adds a contract test for CreateAuditLog, the audit
// write path. AuditRepository is a pure alias to the shared identity store
// (audit_repository.go), so this path is otherwise invisible to this repo's
// test suite and coverage gate (issue #669).
package repositories

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newAuditRepo(t *testing.T) (*AuditRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAuditRepository(db), mock
}

// The insert is a QUERY, not an Exec, as of identity v0.25.0: it RETURNS the
// actor_email it resolved, so a caller that left the field nil gets back the
// address the trail was stamped with. That value survives the users row the
// COALESCE read it from (migration 000007) — which is the point of the column.
func TestAuditRepository_CreateAuditLog_Success(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"actor_email"}).AddRow("alice@example.com"))

	log := &models.AuditLog{Action: "module.upload"}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log.ActorEmail == nil || *log.ActorEmail != "alice@example.com" {
		t.Errorf("ActorEmail = %v, want the address the insert resolved", log.ActorEmail)
	}
}

func TestAuditRepository_CreateAuditLog_DBError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WillReturnError(errDB)

	log := &models.AuditLog{Action: "module.upload"}
	if err := repo.CreateAuditLog(context.Background(), log); err == nil {
		t.Error("expected error, got nil")
	}
}

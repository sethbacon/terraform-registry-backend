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

func TestAuditRepository_CreateAuditLog_Success(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	log := &models.AuditLog{Action: "module.upload"}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuditRepository_CreateAuditLog_DBError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnError(errDB)

	log := &models.AuditLog{Action: "module.upload"}
	if err := repo.CreateAuditLog(context.Background(), log); err == nil {
		t.Error("expected error, got nil")
	}
}

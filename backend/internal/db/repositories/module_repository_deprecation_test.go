package repositories

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// ---------------------------------------------------------------------------
// DeprecateModule
// ---------------------------------------------------------------------------

func TestDeprecateModule_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	msg := "use vpc-v2"
	err := repo.DeprecateModule(context.Background(), "mod-1", &msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeprecateModule_WithSuccessor(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	msg := "use vpc-v2"
	successor := "mod-2"
	err := repo.DeprecateModule(context.Background(), "mod-1", &msg, &successor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeprecateModule_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-999", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeprecateModule(context.Background(), "mod-999", nil, nil)
	if err == nil {
		t.Fatal("expected error for not found module")
	}
}

func TestDeprecateModule_DBError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("db error"))

	err := repo.DeprecateModule(context.Background(), "mod-1", nil, nil)
	if err == nil {
		t.Fatal("expected error on DB failure")
	}
}

// ---------------------------------------------------------------------------
// UndeprecateModule
// ---------------------------------------------------------------------------

func TestUndeprecateModule_Success(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.UndeprecateModule(context.Background(), "mod-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUndeprecateModule_NotFound(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-999").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.UndeprecateModule(context.Background(), "mod-999")
	if err == nil {
		t.Fatal("expected error for not found module")
	}
}

func TestUndeprecateModule_DBError(t *testing.T) {
	repo, mock := newModuleRepo(t)
	mock.ExpectExec("UPDATE modules").
		WithArgs("mod-1").
		WillReturnError(fmt.Errorf("db error"))

	err := repo.UndeprecateModule(context.Background(), "mod-1")
	if err == nil {
		t.Fatal("expected error on DB failure")
	}
}

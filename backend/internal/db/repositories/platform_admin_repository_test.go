package repositories

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func newTestPlatformAdminRepo(t *testing.T) (*PlatformAdminRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewPlatformAdminRepository(db), mock
}

func TestPlatformAdminRepository_IsPlatformAdmin_Granted(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	mock.ExpectQuery("SELECT EXISTS.*FROM platform_admins WHERE user_id").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	got, err := repo.IsPlatformAdmin(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("IsPlatformAdmin: %v", err)
	}
	if !got {
		t.Error("IsPlatformAdmin = false, want true for a user with a carrier row")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestPlatformAdminRepository_IsPlatformAdmin_NotGranted(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	mock.ExpectQuery("SELECT EXISTS.*FROM platform_admins WHERE user_id").
		WithArgs("user-2").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	got, err := repo.IsPlatformAdmin(context.Background(), "user-2")
	if err != nil {
		t.Fatalf("IsPlatformAdmin: %v", err)
	}
	if got {
		t.Error("IsPlatformAdmin = true, want false for a user with no carrier row")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// A lookup failure is REPORTED, never reported as "not an admin". The two are
// different answers and the callers treat them differently: AuthMiddleware
// turns the error into a 500 rather than silently serving a platform
// administrator a downgraded session.
func TestPlatformAdminRepository_IsPlatformAdmin_DBError(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	sentinel := errors.New("carrier lookup failed")
	mock.ExpectQuery("SELECT EXISTS.*FROM platform_admins WHERE user_id").
		WithArgs("user-3").
		WillReturnError(sentinel)

	got, err := repo.IsPlatformAdmin(context.Background(), "user-3")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if got {
		t.Error("IsPlatformAdmin = true on a failed lookup; a fault must never read as a grant")
	}
}

// An empty principal answers false without touching the database. The mock is
// primed with NO expectations, so a query would fail ExpectationsWereMet --
// this asserts the short-circuit, not just the return value.
func TestPlatformAdminRepository_IsPlatformAdmin_EmptyUserID_DoesNotQuery(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	got, err := repo.IsPlatformAdmin(context.Background(), "")
	if err != nil {
		t.Fatalf("IsPlatformAdmin(\"\"): %v", err)
	}
	if got {
		t.Error("IsPlatformAdmin(\"\") = true, want false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

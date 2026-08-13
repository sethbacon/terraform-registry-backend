package repositories

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// ---------------------------------------------------------------------------
// PR 2 (issue #766) — the write side
// ---------------------------------------------------------------------------

var grantCols = []string{"user_id", "granted_by", "granted_at", "note"}

const (
	adminA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	adminB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func TestPlatformAdminRepository_List(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	granted := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	note := "on-call rotation"
	mock.ExpectQuery("SELECT user_id, granted_by, granted_at, note FROM platform_admins ORDER BY").
		WillReturnRows(sqlmock.NewRows(grantCols).
			AddRow(adminA, nil, granted, nil).
			AddRow(adminB, adminA, granted.Add(time.Hour), note))

	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(List) = %d, want 2", len(got))
	}
	if got[0].UserID != adminA || got[0].GrantedBy != nil || got[0].Note != nil {
		t.Errorf("got[0] = %+v, want the backfilled shape (%s, nil grantor, nil note)", got[0], adminA)
	}
	if !got[0].GrantedAt.Equal(granted) {
		t.Errorf("got[0].GrantedAt = %v, want %v", got[0].GrantedAt, granted)
	}
	if got[1].GrantedBy == nil || *got[1].GrantedBy != adminA {
		t.Errorf("got[1].GrantedBy = %v, want %s", got[1].GrantedBy, adminA)
	}
	if got[1].Note == nil || *got[1].Note != note {
		t.Errorf("got[1].Note = %v, want %q", got[1].Note, note)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// An empty carrier lists as an empty slice, not nil: the handler renders it as
// `[]` rather than `null`.
func TestPlatformAdminRepository_List_Empty(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)
	mock.ExpectQuery("SELECT user_id, granted_by, granted_at, note FROM platform_admins").
		WillReturnRows(sqlmock.NewRows(grantCols))

	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil on an empty carrier; want an empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len(List) = %d, want 0", len(got))
	}
}

func TestPlatformAdminRepository_List_DBError(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)
	sentinel := errors.New("list failed")
	mock.ExpectQuery("SELECT user_id, granted_by, granted_at, note FROM platform_admins").
		WillReturnError(sentinel)

	got, err := repo.List(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if got != nil {
		t.Errorf("List = %v on a failed read, want nil", got)
	}
}

func TestPlatformAdminRepository_Grant(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	granted := time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC)
	note := "promoted by ops"
	mock.ExpectQuery("INSERT INTO platform_admins").
		WithArgs(adminB, adminA, note).
		WillReturnRows(sqlmock.NewRows(grantCols).AddRow(adminB, adminA, granted, note))

	grantor := adminA
	got, err := repo.Grant(context.Background(), adminB, &grantor, &note)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if got.UserID != adminB {
		t.Errorf("UserID = %q, want %q", got.UserID, adminB)
	}
	if got.GrantedBy == nil || *got.GrantedBy != adminA {
		t.Errorf("GrantedBy = %v, want %q — the provenance is the reason this is a table and not a boolean", got.GrantedBy, adminA)
	}
	if !got.GrantedAt.Equal(granted) {
		t.Errorf("GrantedAt = %v, want %v", got.GrantedAt, granted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ON CONFLICT DO NOTHING returns no row. That must surface as the sentinel, not
// as a nil grant with a nil error, and the EXISTING row must be left alone —
// overwriting it would erase who originally conferred the privilege.
func TestPlatformAdminRepository_Grant_AlreadyGranted(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	mock.ExpectQuery("INSERT INTO platform_admins").
		WithArgs(adminB, nil, nil).
		WillReturnRows(sqlmock.NewRows(grantCols)) // conflict: nothing returned

	got, err := repo.Grant(context.Background(), adminB, nil, nil)
	if !errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Fatalf("err = %v, want ErrAlreadyPlatformAdmin", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v on a conflict, want nil", got)
	}
}

func TestPlatformAdminRepository_Grant_DBError(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)
	sentinel := errors.New("insert failed")
	mock.ExpectQuery("INSERT INTO platform_admins").WillReturnError(sentinel)

	got, err := repo.Grant(context.Background(), adminB, nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Error("a driver failure was reported as ErrAlreadyPlatformAdmin")
	}
	if got != nil {
		t.Errorf("Grant = %+v on failure, want nil", got)
	}
}

// expectRevokeRead primes the locking read Revoke performs.
func expectRevokeRead(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT user_id, granted_by, granted_at, note FROM platform_admins .*FOR UPDATE").
		WillReturnRows(rows)
}

func TestPlatformAdminRepository_Revoke(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	granted := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	expectRevokeRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, granted, nil).
		AddRow(adminB, adminA, granted, nil))
	mock.ExpectExec("DELETE FROM platform_admins WHERE user_id").
		WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var sawRemaining []PlatformAdminGrant
	got, err := repo.Revoke(context.Background(), adminB, func(_ context.Context, remaining []PlatformAdminGrant) error {
		sawRemaining = remaining
		return nil
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.UserID != adminB {
		t.Errorf("Revoke returned %q, want the revoked grant %q", got.UserID, adminB)
	}
	// The predicate must be handed the set that would REMAIN — the target
	// excluded. Handing it the whole set would make "one admin left" read as
	// "two", which is the guard failing open.
	if len(sawRemaining) != 1 || sawRemaining[0].UserID != adminA {
		t.Errorf("predicate saw %+v, want exactly the non-target grant %q", sawRemaining, adminA)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The predicate's refusal aborts the transaction: no DELETE is issued at all.
// sqlmock is ordered and primed with no Exec, so an attempted delete fails the
// expectations rather than merely being rolled back.
func TestPlatformAdminRepository_Revoke_PredicateRefuses_DoesNotDelete(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	expectRevokeRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, time.Now(), nil))
	mock.ExpectRollback()

	refusal := errors.New("last one standing")
	got, err := repo.Revoke(context.Background(), adminA, func(_ context.Context, remaining []PlatformAdminGrant) error {
		if len(remaining) != 0 {
			t.Errorf("remaining = %+v, want empty for a sole administrator", remaining)
		}
		return refusal
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("err = %v, want the predicate's own error %v", err, refusal)
	}
	if got != nil {
		t.Errorf("Revoke = %+v after a refusal, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (a DELETE was issued despite the refusal?): %v", err)
	}
}

func TestPlatformAdminRepository_Revoke_NotAnAdmin(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	expectRevokeRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, time.Now(), nil))
	mock.ExpectRollback()

	called := false
	got, err := repo.Revoke(context.Background(), adminB, func(context.Context, []PlatformAdminGrant) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrNotPlatformAdmin) {
		t.Fatalf("err = %v, want ErrNotPlatformAdmin", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v for a non-admin, want nil", got)
	}
	if called {
		t.Error("the last-standing predicate ran for a user who holds no grant; there is nothing to protect")
	}
}

// A DELETE that matches nothing after the row was read under FOR UPDATE must
// not commit and must not report success.
func TestPlatformAdminRepository_Revoke_DeleteMatchedNothing(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	expectRevokeRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, time.Now(), nil).
		AddRow(adminB, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM platform_admins WHERE user_id").
		WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	got, err := repo.Revoke(context.Background(), adminB, nil)
	if err == nil {
		t.Fatal("Revoke reported success for a DELETE that removed no rows")
	}
	if !strings.Contains(err.Error(), "removed 0 rows") {
		t.Errorf("err = %v, want it to name the row count", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (did it commit?): %v", err)
	}
}

func TestPlatformAdminRepository_Revoke_ReadError(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	sentinel := errors.New("locking read failed")
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT user_id, granted_by, granted_at, note FROM platform_admins").
		WillReturnError(sentinel)
	mock.ExpectRollback()

	got, err := repo.Revoke(context.Background(), adminA, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if errors.Is(err, ErrNotPlatformAdmin) {
		t.Error("a failed read was reported as ErrNotPlatformAdmin — a fault must not read as an absent grant")
	}
	if got != nil {
		t.Errorf("Revoke = %+v on a failed read, want nil", got)
	}
}

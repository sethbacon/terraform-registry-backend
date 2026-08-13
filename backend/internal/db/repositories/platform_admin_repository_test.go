package repositories

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ---------------------------------------------------------------------------
// Audit intent test doubles (issue #766, migration 000052)
// ---------------------------------------------------------------------------

// intentSQL is what the test doubles below write. It stands in for the real
// outbox INSERT (internal/audit) and exists so the assertions can be about
// ORDER and TRANSACTION MEMBERSHIP — sqlmock matches in order, so a writer that
// ran outside the mutation's transaction, or after the commit, fails.
const intentSQL = "INSERT INTO audit_outbox"

// writingIntent returns an AuditIntentWriter that writes an intent on the
// transaction it is handed, and records that it ran.
func writingIntent(ran *bool) AuditIntentWriter {
	return func(ctx context.Context, tx *sql.Tx) error {
		*ran = true
		_, err := tx.ExecContext(ctx, intentSQL+" (event_id) VALUES ($1)", "event-1")
		return err
	}
}

// expectIntentWrite primes the intent write the mutation must perform.
func expectIntentWrite(mock sqlmock.Sqlmock) {
	mock.ExpectExec(intentSQL).WillReturnResult(sqlmock.NewResult(0, 1))
}

// refusingIntent returns an AuditIntentWriter that fails with cause, standing
// in for an outbox that cannot accept the record.
func refusingIntent(cause error) AuditIntentWriter {
	return func(context.Context, *sql.Tx) error { return cause }
}

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
	// ORDERED: begin, insert the grant, write the audit intent on the SAME
	// transaction, commit. sqlmock matches in sequence, so an intent written
	// after the commit — the shape this replaces — is an unexpected call.
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO platform_admins").
		WithArgs(adminB, adminA, note).
		WillReturnRows(sqlmock.NewRows(grantCols).AddRow(adminB, adminA, granted, note))
	expectIntentWrite(mock)
	mock.ExpectCommit()

	grantor := adminA
	var audited bool
	got, err := repo.Grant(context.Background(), adminB, &grantor, &note, writingIntent(&audited))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !audited {
		t.Error("the grant committed without the audit intent writer being run")
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

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO platform_admins").
		WithArgs(adminB, nil, nil).
		WillReturnRows(sqlmock.NewRows(grantCols)) // conflict: nothing returned
	mock.ExpectRollback()

	var audited bool
	got, err := repo.Grant(context.Background(), adminB, nil, nil, writingIntent(&audited))
	if !errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Fatalf("err = %v, want ErrAlreadyPlatformAdmin", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v on a conflict, want nil", got)
	}
	// Nothing changed hands, so there is nothing to audit. Writing an intent
	// here would put a "granted" record in the trail for a grant that did not
	// happen.
	if audited {
		t.Error("an audit intent was written for a grant that conflicted and changed nothing")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (did it commit?): %v", err)
	}
}

func TestPlatformAdminRepository_Grant_DBError(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)
	sentinel := errors.New("insert failed")
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO platform_admins").WillReturnError(sentinel)
	mock.ExpectRollback()

	var audited bool
	got, err := repo.Grant(context.Background(), adminB, nil, nil, writingIntent(&audited))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
	if errors.Is(err, ErrAlreadyPlatformAdmin) {
		t.Error("a driver failure was reported as ErrAlreadyPlatformAdmin")
	}
	if got != nil {
		t.Errorf("Grant = %+v on failure, want nil", got)
	}
	if audited {
		t.Error("an audit intent was written for a grant that failed")
	}
}

// GUARD durable-audit-mandatory-writer (Grant). A privileged mutation with
// nowhere to record itself does not happen — and does not even open a
// transaction. The mock is primed with NO expectations, so a BEGIN would fail
// ExpectationsWereMet: this asserts the refusal came before the database, not
// merely that an error came back.
func TestPlatformAdminRepository_Grant_NilIntentWriter_RefusesWithoutTouchingTheDatabase(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	got, err := repo.Grant(context.Background(), adminB, nil, nil, nil)
	if !errors.Is(err, ErrAuditIntentRequired) {
		t.Fatalf("err = %v, want ErrAuditIntentRequired", err)
	}
	if got != nil {
		t.Errorf("Grant = %+v with no audit writer, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unauditable grant reached the database): %v", err)
	}
}

// GUARD durable-audit-atomic (Grant). THE DEFECT THIS PR EXISTS FOR: the audit
// destination refuses, and the grant must not commit.
//
// Asserted on the writer's own sentinel and on ExpectationsWereMet, because a
// bare "err != nil" would also be satisfied by sqlmock's unexpected-call error
// — which is how a guard in this estate passed while protecting nothing.
func TestPlatformAdminRepository_Grant_AuditIntentFails_DoesNotCommit(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	granted := time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO platform_admins").
		WithArgs(adminB, nil, nil).
		WillReturnRows(sqlmock.NewRows(grantCols).AddRow(adminB, nil, granted, nil))
	// No ExpectCommit: a commit here is an unexpected call and fails the test.
	mock.ExpectRollback()

	outboxDown := errors.New("audit outbox unreachable")
	got, err := repo.Grant(context.Background(), adminB, nil, nil, refusingIntent(outboxDown))
	if !errors.Is(err, outboxDown) {
		t.Fatalf("err = %v, want the audit writer's own error %v", err, outboxDown)
	}
	if got != nil {
		t.Errorf("Grant = %+v when the audit record could not be written, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unaudited grant committed): %v", err)
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
	expectIntentWrite(mock)
	mock.ExpectCommit()

	var sawRemaining []PlatformAdminGrant
	var audited bool
	got, err := repo.Revoke(context.Background(), adminB, func(_ context.Context, remaining []PlatformAdminGrant) error {
		sawRemaining = remaining
		return nil
	}, writingIntent(&audited))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !audited {
		t.Error("the revocation committed without the audit intent writer being run")
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
	var audited bool
	got, err := repo.Revoke(context.Background(), adminA, func(_ context.Context, remaining []PlatformAdminGrant) error {
		if len(remaining) != 0 {
			t.Errorf("remaining = %+v, want empty for a sole administrator", remaining)
		}
		return refusal
	}, writingIntent(&audited))
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
	var audited bool
	got, err := repo.Revoke(context.Background(), adminB, func(context.Context, []PlatformAdminGrant) error {
		called = true
		return nil
	}, writingIntent(&audited))
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

	var audited bool
	got, err := repo.Revoke(context.Background(), adminB, nil, writingIntent(&audited))
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

	var audited bool
	got, err := repo.Revoke(context.Background(), adminA, nil, writingIntent(&audited))
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

// GUARD durable-audit-mandatory-writer (Revoke). Same rule as Grant, and the
// same proof: no writer, no transaction, ErrAuditIntentRequired. The mock has
// no expectations, so a BEGIN fails ExpectationsWereMet.
func TestPlatformAdminRepository_Revoke_NilIntentWriter_RefusesWithoutTouchingTheDatabase(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	got, err := repo.Revoke(context.Background(), adminA, nil, nil)
	if !errors.Is(err, ErrAuditIntentRequired) {
		t.Fatalf("err = %v, want ErrAuditIntentRequired", err)
	}
	if got != nil {
		t.Errorf("Revoke = %+v with no audit writer, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unauditable revocation reached the database): %v", err)
	}
}

// GUARD durable-audit-atomic (Revoke). The audit destination refuses AFTER the
// row has been deleted inside the transaction; the deletion must go with it.
//
// This is the direction that used to be impossible to get right: the delete was
// on the registry connection and the audit entry on the identity connection, so
// "roll the delete back" was not available and the handler reported success.
func TestPlatformAdminRepository_Revoke_AuditIntentFails_DoesNotCommit(t *testing.T) {
	repo, mock := newTestPlatformAdminRepo(t)

	expectRevokeRead(mock, sqlmock.NewRows(grantCols).
		AddRow(adminA, nil, time.Now(), nil).
		AddRow(adminB, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM platform_admins WHERE user_id").
		WithArgs(adminB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// No ExpectCommit: committing here is an unexpected call.
	mock.ExpectRollback()

	outboxDown := errors.New("audit outbox unreachable")
	got, err := repo.Revoke(context.Background(), adminB, nil, refusingIntent(outboxDown))
	if !errors.Is(err, outboxDown) {
		t.Fatalf("err = %v, want the audit writer's own error %v", err, outboxDown)
	}
	if got != nil {
		t.Errorf("Revoke = %+v when the audit record could not be written, want nil", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unaudited revocation committed): %v", err)
	}
}

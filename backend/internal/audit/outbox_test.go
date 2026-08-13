package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Issue #766 — the transactional audit outbox.
//
// Every assertion here is on a sentinel or an exact value. "err != nil" is not
// an assertion in this package: sqlmock's own unexpected-call error satisfies
// it, and a guard in this estate once passed for exactly that reason.

func newOutbox(t *testing.T) (*Outbox, *sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOutbox(db), db, mock
}

// capturedArg keeps a bound argument so a test can assert on a value the code
// under test generated.
type capturedArg struct{ value driver.Value }

func (c *capturedArg) Match(v driver.Value) bool { c.value = v; return true }

func TestOutbox_Enqueue_WritesTheIntentOnTheCallersTransaction(t *testing.T) {
	outbox, db, mock := newOutbox(t)

	actor := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	target := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	resource := "platform_admin"
	ip := "203.0.113.7"
	occurred := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)

	metadata := &capturedArg{}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_outbox").
		WithArgs(
			"11111111-2222-3333-4444-555555555555", // event_id, verbatim
			occurred,
			"platform_admin.granted",
			actor,
			"admin@example.com",
			nil, // organization_id
			resource,
			target,
			ip,
			metadata,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	email := "admin@example.com"
	intent := &Intent{
		EventID:      "11111111-2222-3333-4444-555555555555",
		OccurredAt:   occurred,
		Action:       "platform_admin.granted",
		ActorUserID:  &actor,
		ActorEmail:   &email,
		ResourceType: &resource,
		ResourceID:   &target,
		IPAddress:    &ip,
		Metadata:     map[string]interface{}{"note": "incident 42"},
	}
	if err := outbox.Enqueue(context.Background(), tx, intent); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	raw, ok := metadata.value.([]byte)
	if !ok {
		t.Fatalf("metadata was bound as %T, want JSON bytes", metadata.value)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("metadata is not JSON: %v (%s)", err, raw)
	}
	if decoded["note"] != "incident 42" {
		t.Errorf("metadata note = %v, want \"incident 42\"", decoded["note"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The caller's EventID survives untouched, because it is the audit_logs primary
// key the sink deduplicates on. An outbox that re-minted it would turn every
// redelivery into a second copy of the same event.
func TestOutbox_Enqueue_MintsAnEventIDWhenAbsent(t *testing.T) {
	outbox, db, mock := newOutbox(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_outbox").WillReturnResult(sqlmock.NewResult(0, 1))

	tx, _ := db.Begin()
	intent := &Intent{Action: "platform_admin.granted"}
	if err := outbox.Enqueue(context.Background(), tx, intent); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if intent.EventID == "" {
		t.Fatal("Enqueue left EventID empty; without a stable id redelivery duplicates the record")
	}
	if _, err := uuid.Parse(intent.EventID); err != nil {
		t.Errorf("EventID = %q, which is not a UUID and cannot key audit_logs.id: %v", intent.EventID, err)
	}
	if intent.OccurredAt.IsZero() {
		t.Error("Enqueue left OccurredAt zero; the audit trail would say the event happened at year 1")
	}
}

// GUARD durable-audit-fails-closed. Every way of having nowhere to write the
// record is an error, never a silent success — a no-op Enqueue would let the
// mutation commit alone, which is the whole defect.
func TestOutbox_Enqueue_FailsClosed(t *testing.T) {
	_, db, mock := newOutbox(t)
	mock.ExpectBegin()
	tx, _ := db.Begin()

	tests := []struct {
		name   string
		outbox *Outbox
		tx     *sql.Tx
		intent *Intent
		want   error
	}{
		{"nil outbox", nil, tx, &Intent{Action: "a"}, ErrNoOutbox},
		{"outbox with no connection", &Outbox{}, tx, &Intent{Action: "a"}, ErrNoOutbox},
		{"no transaction to enlist in", NewOutbox(db), nil, &Intent{Action: "a"}, ErrNoOutbox},
		{"nil intent", NewOutbox(db), tx, nil, ErrIntentIncomplete},
		{"empty action", NewOutbox(db), tx, &Intent{}, ErrIntentIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.outbox.Enqueue(context.Background(), tt.tx, tt.intent)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	// No ExpectExec was primed: a write in any of those cases would be an
	// unexpected call.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (something was written anyway): %v", err)
	}
}

// A driver failure is returned, not swallowed — that return value is what rolls
// the mutation back.
func TestOutbox_Enqueue_DriverErrorIsReturned(t *testing.T) {
	outbox, db, mock := newOutbox(t)

	sentinel := errors.New("outbox insert failed")
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO audit_outbox").WillReturnError(sentinel)

	tx, _ := db.Begin()
	err := outbox.Enqueue(context.Background(), tx, &Intent{Action: "platform_admin.granted"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
}

func TestOutbox_Backlog(t *testing.T) {
	outbox, _, mock := newOutbox(t)

	oldest := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)
	mock.ExpectQuery("(?s)FROM audit_outbox.*delivered_at IS NULL").
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(7, 2, oldest))

	got, err := outbox.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if got.Pending != 7 {
		t.Errorf("Pending = %d, want 7", got.Pending)
	}
	if got.Failed != 2 {
		t.Errorf("Failed = %d, want 2 — pending alone cannot tell \"just written\" from \"stuck\"", got.Failed)
	}
	if !got.OldestPending.Equal(oldest) {
		t.Errorf("OldestPending = %v, want %v", got.OldestPending, oldest)
	}
}

// An empty outbox reports a zero time rather than whatever min() returned,
// so the age gauge does not report an age for a backlog that does not exist.
func TestOutbox_Backlog_EmptyReportsNoOldest(t *testing.T) {
	outbox, _, mock := newOutbox(t)

	mock.ExpectQuery("FROM audit_outbox").
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(0, 0, nil))

	got, err := outbox.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if got.Pending != 0 || !got.OldestPending.IsZero() {
		t.Errorf("Backlog = %+v, want zero pending and no oldest", got)
	}
}

// GUARD durable-audit-prune-delivered-only. The pruner is the only thing that
// deletes from the outbox, and it must never reach an UNDELIVERED intent —
// that would destroy a record of a privileged mutation that never arrived.
//
// Asserted on the SQL itself, because the difference between the safe query and
// the catastrophic one is one predicate, and no row-count assertion would
// notice it going missing.
func TestOutbox_PruneDelivered_NeverTouchesUndeliveredIntents(t *testing.T) {
	outbox, _, mock := newOutbox(t)

	cutoff := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	mock.ExpectExec("(?s)DELETE FROM audit_outbox.*delivered_at IS NOT NULL AND delivered_at < \\$1").
		WithArgs(cutoff, 500).
		WillReturnResult(sqlmock.NewResult(0, 3))

	pruned, err := outbox.PruneDelivered(context.Background(), cutoff, 500)
	if err != nil {
		t.Fatalf("PruneDelivered: %v", err)
	}
	if pruned != 3 {
		t.Errorf("pruned = %d, want 3", pruned)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations — the prune did not carry the delivered-only predicate: %v", err)
	}
}

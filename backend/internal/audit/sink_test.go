package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// Issue #766 — the delivery end of the outbox.
//
// The property that matters here is IDEMPOTENCE, and it is a property of the
// SQL: audit_logs.id is the intent's own EventID and the insert carries
// ON CONFLICT (id) DO NOTHING. Both are asserted against the statement itself,
// because no row count can tell you the conflict clause went missing — the
// first delivery of every event succeeds either way, and the damage only shows
// up as duplicates after a crash. outbox_integration_test.go then proves the
// same thing behaviourally against a real primary key.

func newSink(t *testing.T, hasActorEmail bool) (*AuditLogSink, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mock.ExpectQuery("(?s)pg_attribute.*actor_email").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(hasActorEmail))
	return NewAuditLogSink(db), mock
}

func testIntent() Intent {
	actor := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	target := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	resource := "platform_admin"
	ip := "203.0.113.7"
	return Intent{
		EventID:      "11111111-2222-3333-4444-555555555555",
		OccurredAt:   time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC),
		Action:       "platform_admin.granted",
		ActorUserID:  &actor,
		ResourceType: &resource,
		ResourceID:   &target,
		IPAddress:    &ip,
	}
}

// GUARD durable-audit-idempotent-delivery. The intent's EventID IS
// audit_logs.id, and the insert absorbs a redelivery instead of appending a
// second copy.
func TestAuditLogSink_Deliver_IsKeyedOnTheEventIDAndAbsorbsRedelivery(t *testing.T) {
	sink, mock := newSink(t, false)

	intent := testIntent()
	mock.ExpectExec(`(?s)INSERT INTO audit_logs.*ON CONFLICT \(id\) DO NOTHING`).
		WithArgs(
			intent.EventID, // id — the stable key, NOT a fresh uuid
			*intent.ActorUserID,
			nil, // organization_id
			intent.Action,
			*intent.ResourceType,
			*intent.ResourceID,
			nil, // metadata
			*intent.IPAddress,
			intent.OccurredAt, // created_at is when it HAPPENED, not when it arrived
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := sink.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations — the insert is not keyed on the event id or lost its conflict clause: %v", err)
	}
}

// Where audit_logs carries actor_email (the identity schema), the address
// captured at intent time is written, falling back to resolving it exactly as
// the shared identity store's own insert does.
func TestAuditLogSink_Deliver_WritesActorEmailWhereTheColumnExists(t *testing.T) {
	sink, mock := newSink(t, true)

	intent := testIntent()
	email := "admin@example.com"
	intent.ActorEmail = &email

	mock.ExpectExec(`(?s)INSERT INTO audit_logs.*actor_email.*COALESCE\(\$10, \(SELECT email FROM users WHERE id = \$2\)\).*ON CONFLICT \(id\) DO NOTHING`).
		WithArgs(
			intent.EventID, *intent.ActorUserID, nil, intent.Action,
			*intent.ResourceType, *intent.ResourceID, nil, *intent.IPAddress,
			intent.OccurredAt, email,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := sink.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// An intent with no EventID has no idempotence key, so delivering it could only
// ever produce duplicates. Refused before the insert.
func TestAuditLogSink_Deliver_RefusesAnIntentWithNoEventID(t *testing.T) {
	sink, mock := newSink(t, false)
	// The probe is primed but nothing else: an insert would be unexpected.

	intent := testIntent()
	intent.EventID = ""
	err := sink.Deliver(context.Background(), intent)
	if !errors.Is(err, ErrIntentIncomplete) {
		t.Fatalf("err = %v, want ErrIntentIncomplete", err)
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("the column probe ran for an intent that was refused before any insert")
	}
}

// A sink with no connection is an error, not a silent success. A success here
// would mark the intent delivered and lose it.
func TestAuditLogSink_Deliver_NoConnection(t *testing.T) {
	var sink *AuditLogSink
	if err := sink.Deliver(context.Background(), testIntent()); err == nil {
		t.Fatal("a sink with no connection reported a successful delivery")
	}
	if err := (&AuditLogSink{}).Deliver(context.Background(), testIntent()); err == nil {
		t.Fatal("a sink with a nil connection reported a successful delivery")
	}
}

// The driver's failure reaches the relay, which is what keeps the intent in the
// backlog for a retry.
func TestAuditLogSink_Deliver_DriverErrorIsReturned(t *testing.T) {
	sink, mock := newSink(t, false)

	sentinel := errors.New("audit_logs unreachable")
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnError(sentinel)

	if err := sink.Deliver(context.Background(), testIntent()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the driver's error %v", err, sentinel)
	}
}

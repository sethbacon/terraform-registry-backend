package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// Issue #766 — the relay that carries the outbox to audit_logs.
//
// The properties under test are the ones the durability claim rests on:
// delivery marks and claims share one transaction (so a crash loses nothing),
// a failed delivery retains the intent instead of dropping it, and a relay with
// nowhere to deliver refuses to run rather than silently accumulating a
// backlog. Exactly-once-in-effect redelivery is proved against a real Postgres
// in outbox_integration_test.go, because it is a property of the destination's
// primary key and a mock cannot enforce one.

var outboxCols = []string{
	"event_id", "occurred_at", "action", "actor_user_id", "actor_email",
	"organization_id", "resource_type", "resource_id", "ip_address", "metadata", "attempts",
}

// pendingIntentRow is one claimable audit_outbox row.
type pendingIntentRow struct {
	eventID  string
	action   string
	attempts int
}

func rowsFrom(rows ...pendingIntentRow) *sqlmock.Rows {
	out := sqlmock.NewRows(outboxCols)
	for _, r := range rows {
		out.AddRow(r.eventID, time.Now().UTC(), r.action, nil, nil, nil,
			"platform_admin", "target", nil, nil, r.attempts)
	}
	return out
}

// recordingSink captures what it was asked to deliver and answers with a
// scripted result.
type recordingSink struct {
	mu  sync.Mutex
	got []Intent
	err error
}

func (s *recordingSink) Deliver(_ context.Context, intent Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, intent)
	return s.err
}

func (s *recordingSink) delivered() []Intent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Intent(nil), s.got...)
}

func newRelay(t *testing.T, sink Sink, shipper Shipper) (*Relay, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRelay(NewOutbox(db), sink, shipper, RelayConfig{BatchSize: 2}), mock
}

// The claim, the delivery and the mark are one transaction, in that order. The
// ordering IS the crash contract: a process that dies before the commit has
// marked nothing, so the intent is claimed again.
func TestRelay_DeliverBatch_ClaimsDeliversAndMarksInOneTransaction(t *testing.T) {
	sink := &recordingSink{}
	relay, mock := newRelay(t, sink, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)FROM audit_outbox.*delivered_at IS NULL.*FOR UPDATE SKIP LOCKED").
		WithArgs(2).
		WillReturnRows(rowsFrom(pendingIntentRow{"event-1", "platform_admin.granted", 0}))
	mock.ExpectExec("(?s)UPDATE audit_outbox.*SET delivered_at = now").
		WithArgs("event-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	claimed, delivered, err := relay.DeliverBatch(context.Background())
	if err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if claimed != 1 || delivered != 1 {
		t.Fatalf("claimed=%d delivered=%d, want 1 and 1", claimed, delivered)
	}
	got := sink.delivered()
	if len(got) != 1 || got[0].EventID != "event-1" {
		t.Fatalf("sink saw %+v, want exactly the claimed intent event-1", got)
	}
	if got[0].Action != "platform_admin.granted" {
		t.Errorf("delivered action = %q, want platform_admin.granted", got[0].Action)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD durable-audit-retained-on-failure. A delivery that fails does NOT mark
// the intent delivered and does NOT delete it: the record stays in the backlog
// and is retried. Losing it here would be the same defect the outbox exists to
// remove, moved one step later.
//
// The mock is primed with no delivered-marking UPDATE, so marking it anyway is
// an unexpected call rather than merely a wrong count.
func TestRelay_DeliverBatch_FailedDeliveryRetainsTheIntent(t *testing.T) {
	sink := &recordingSink{err: errors.New("audit_logs unreachable")}
	relay, mock := newRelay(t, sink, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM audit_outbox").
		WithArgs(2).
		WillReturnRows(rowsFrom(pendingIntentRow{"event-1", "platform_admin.granted", 0}))
	mock.ExpectExec("(?s)UPDATE audit_outbox.*SET attempts = attempts \\+ 1, last_error = \\$2").
		WithArgs("event-1", "audit_logs unreachable").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	claimed, delivered, err := relay.DeliverBatch(context.Background())
	if err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if claimed != 1 {
		t.Fatalf("claimed = %d, want 1", claimed)
	}
	if delivered != 0 {
		t.Fatalf("delivered = %d after the sink refused, want 0", delivered)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (was a failed delivery marked delivered?): %v", err)
	}
}

// One poisoned record must not block the ones behind it. The second intent is
// delivered and marked in the same batch as the first one's failure.
func TestRelay_DeliverBatch_OneFailureDoesNotBlockTheBatch(t *testing.T) {
	// The first delivery fails, the second succeeds.
	relay, mock := newRelay(t, &scriptedSink{errs: map[string]error{"event-1": errors.New("bad row")}}, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM audit_outbox").
		WithArgs(2).
		WillReturnRows(rowsFrom(
			pendingIntentRow{"event-1", "platform_admin.granted", 0},
			pendingIntentRow{"event-2", "platform_admin.revoked", 0},
		))
	mock.ExpectExec("UPDATE audit_outbox").WithArgs("event-1", "bad row").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE audit_outbox").WithArgs("event-2").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	claimed, delivered, err := relay.DeliverBatch(context.Background())
	if err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if claimed != 2 || delivered != 1 {
		t.Fatalf("claimed=%d delivered=%d, want 2 and 1", claimed, delivered)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// scriptedSink fails for named event ids and succeeds for everything else.
type scriptedSink struct{ errs map[string]error }

func (s *scriptedSink) Deliver(_ context.Context, intent Intent) error { return s.errs[intent.EventID] }

// A CRASH BETWEEN THE DESTINATION WRITE AND THE COMMIT, forced rather than
// raced: the sink delivers and then the process dies (a panic here; a real
// SIGKILL and a terminated backend are exercised against Postgres in
// outbox_integration_test.go).
//
// The assertion is that the outbox transaction ROLLS BACK — nothing was marked
// delivered — so the intent is redelivered on the next cycle. The mock is
// primed with no UPDATE and no COMMIT, so either one happening is an
// unexpected call.
func TestRelay_DeliverBatch_CrashAfterDeliveryLeavesTheIntentUndelivered(t *testing.T) {
	crash := &crashingSink{}
	relay, mock := newRelay(t, crash, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM audit_outbox").
		WithArgs(2).
		WillReturnRows(rowsFrom(pendingIntentRow{"event-1", "platform_admin.granted", 0}))
	mock.ExpectRollback()

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("the simulated crash did not propagate; the test proved nothing")
			}
		}()
		_, _, _ = relay.DeliverBatch(context.Background())
	}()

	if !crash.delivered {
		t.Fatal("the sink was never reached; the crash happened before the interesting moment")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the batch was marked delivered despite the crash): %v", err)
	}
}

type crashingSink struct{ delivered bool }

func (s *crashingSink) Deliver(context.Context, Intent) error {
	s.delivered = true
	panic("process died mid-flight")
}

// An empty outbox commits and reports nothing, rather than holding a
// transaction open across the idle interval.
func TestRelay_DeliverBatch_EmptyOutbox(t *testing.T) {
	relay, mock := newRelay(t, &recordingSink{}, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM audit_outbox").WithArgs(2).WillReturnRows(sqlmock.NewRows(outboxCols))
	mock.ExpectCommit()

	claimed, delivered, err := relay.DeliverBatch(context.Background())
	if err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if claimed != 0 || delivered != 0 {
		t.Errorf("claimed=%d delivered=%d, want 0 and 0", claimed, delivered)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD durable-audit-relay-refuses-to-idle. A relay with no destination would
// let intents pile up forever behind a process that looks healthy. It refuses
// to start instead, with a sentinel the caller can act on.
func TestRelay_Start_RefusesWithoutAnOutboxOrASink(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// An ALREADY-CANCELLED context, so a relay that wrongly proceeds returns
	// promptly with nil instead of blocking the test for its timeout. The
	// assertion is then about which answer came back, not about how long it
	// took.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := NewRelay(nil, &recordingSink{}, nil, RelayConfig{}).Start(ctx); !errors.Is(err, ErrNoOutbox) {
		t.Errorf("Start with no outbox = %v, want ErrNoOutbox", err)
	}
	err = NewRelay(NewOutbox(db), nil, nil, RelayConfig{}).Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "no sink") {
		t.Errorf("Start with no sink = %v, want a refusal naming the missing sink", err)
	}
}

// The backlog is published on every cycle. It cannot be bounded by discarding
// it, so these gauges are the only thing that stops it being SILENTLY
// unbounded — which makes their being set a property worth asserting.
func TestRelay_ObserveBacklog_PublishesTheDepth(t *testing.T) {
	relay, mock := newRelay(t, &recordingSink{}, nil)

	oldest := time.Now().Add(-30 * time.Minute)
	mock.ExpectQuery("FROM audit_outbox").
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(12, 4, oldest))

	relay.observeBacklog(context.Background())

	if got := testutil.ToFloat64(telemetry.AuditOutboxPending); got != 12 {
		t.Errorf("audit_outbox_pending = %v, want 12", got)
	}
	if got := testutil.ToFloat64(telemetry.AuditOutboxFailed); got != 4 {
		t.Errorf("audit_outbox_failed = %v, want 4", got)
	}
	if got := testutil.ToFloat64(telemetry.AuditOutboxOldestAgeSeconds); got < 1700 || got > 1900 {
		t.Errorf("audit_outbox_oldest_age_seconds = %v, want ~1800 (the oldest intent is 30 minutes old)", got)
	}
}

// An empty backlog reports age 0, not the age of the last thing that drained.
func TestRelay_ObserveBacklog_EmptyReportsZeroAge(t *testing.T) {
	relay, mock := newRelay(t, &recordingSink{}, nil)

	mock.ExpectQuery("FROM audit_outbox").
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(0, 0, nil))

	relay.observeBacklog(context.Background())

	if got := testutil.ToFloat64(telemetry.AuditOutboxOldestAgeSeconds); got != 0 {
		t.Errorf("audit_outbox_oldest_age_seconds = %v on an empty outbox, want 0", got)
	}
}

// A shipper failure does not hold the record back: audit_logs is the audit
// trail and already has it (shipper.go). The intent is still marked delivered.
func TestRelay_DeliverBatch_ShipperFailureDoesNotRetainTheIntent(t *testing.T) {
	relay, mock := newRelay(t, &recordingSink{}, failingShipper{})

	mock.ExpectBegin()
	mock.ExpectQuery("FROM audit_outbox").
		WithArgs(2).
		WillReturnRows(rowsFrom(pendingIntentRow{"event-1", "platform_admin.granted", 0}))
	mock.ExpectExec("(?s)UPDATE audit_outbox.*SET delivered_at = now").
		WithArgs("event-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	_, delivered, err := relay.DeliverBatch(context.Background())
	if err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1 — a broken SIEM must not grow the audit backlog", delivered)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The shipped entry carries the stable event id, so a SIEM receiving a
// redelivery can collapse it instead of counting the same grant twice.
func TestRelay_Ship_CarriesTheStableEventID(t *testing.T) {
	captured := &capturingShipper{}
	relay, _ := newRelay(t, &recordingSink{}, captured)

	relay.ship(context.Background(), Intent{EventID: "event-42", Action: "platform_admin.granted"})

	if captured.entry == nil {
		t.Fatal("nothing was shipped")
	}
	if got := captured.entry.Metadata["audit_event_id"]; got != "event-42" {
		t.Errorf("shipped metadata audit_event_id = %v, want event-42", got)
	}
}

type failingShipper struct{}

func (failingShipper) Ship(context.Context, *LogEntry) error { return errors.New("siem down") }
func (failingShipper) Close() error                          { return nil }

type capturingShipper struct{ entry *LogEntry }

func (c *capturingShipper) Ship(_ context.Context, e *LogEntry) error { c.entry = e; return nil }
func (c *capturingShipper) Close() error                              { return nil }

// Stop is idempotent: the registry may call it after a context cancellation
// already ended the loop.
func TestRelay_StopIsIdempotent(t *testing.T) {
	relay := NewRelay(nil, nil, nil, RelayConfig{})
	if err := relay.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := relay.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"

	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// The outbox mechanism itself is identity/auditoutbox's and is tested there.
// What is tested here is the registry-shaped wiring that is NOT the library's:
// the translation to this repository's LogEntry — the JSON a configured SIEM
// actually receives — and the publication of this repository's metrics.

// recordingShipper captures the LogEntry the bridge produces.
type recordingShipper struct {
	entries []*LogEntry
	err     error
}

func (r *recordingShipper) Ship(_ context.Context, entry *LogEntry) error {
	r.entries = append(r.entries, entry)
	return r.err
}

func (r *recordingShipper) Close() error { return nil }

func sampleEntry() *auditoutbox.Entry {
	return &auditoutbox.Entry{
		Timestamp:      time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		EventID:        "event-1",
		Action:         "platform_admin.granted",
		UserID:         "actor-1",
		ActorEmail:     "actor@example.com",
		OrganizationID: "org-1",
		ResourceType:   "platform_admin",
		ResourceID:     "target-1",
		IPAddress:      "203.0.113.7",
		Metadata:       map[string]interface{}{"note": "on call"},
	}
}

// TestShipperBridge_ShipsTheRegistrysOwnEntryShape asserts every field the
// external contract carries, by value. A SIEM parses this payload; a field
// dropped in translation is a field its rules stop matching on.
func TestShipperBridge_ShipsTheRegistrysOwnEntryShape(t *testing.T) {
	shipper := &recordingShipper{}
	if err := (shipperBridge{shipper: shipper}).Ship(context.Background(), sampleEntry()); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if len(shipper.entries) != 1 {
		t.Fatalf("shipped %d entries, want 1", len(shipper.entries))
	}
	got := shipper.entries[0]

	if !got.Timestamp.Equal(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("Timestamp = %v, want the event's own occurrence time", got.Timestamp)
	}
	for _, field := range []struct{ name, got, want string }{
		{"Action", got.Action, "platform_admin.granted"},
		{"UserID", got.UserID, "actor-1"},
		{"OrganizationID", got.OrganizationID, "org-1"},
		{"ResourceType", got.ResourceType, "platform_admin"},
		{"ResourceID", got.ResourceID, "target-1"},
		{"IPAddress", got.IPAddress, "203.0.113.7"},
	} {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}
	// The stable event id travels in the metadata, under the key it has always
	// used: that is how a receiver collapses a redelivery instead of counting
	// the same grant twice.
	if got.Metadata["audit_event_id"] != "event-1" {
		t.Errorf("metadata[audit_event_id] = %v, want %q", got.Metadata["audit_event_id"], "event-1")
	}
	if got.Metadata["note"] != "on call" {
		t.Errorf("metadata[note] = %v, want the intent's own detail preserved", got.Metadata["note"])
	}
}

// TestShipperBridge_DoesNotWriteThroughToTheRelaysIntent. The entry's metadata
// map belongs to the intent the relay is still holding; stamping the event id
// into it in place would mutate a value the relay is about to mark delivered.
func TestShipperBridge_DoesNotWriteThroughToTheRelaysIntent(t *testing.T) {
	entry := sampleEntry()
	source := entry.Metadata

	if err := (shipperBridge{shipper: &recordingShipper{}}).Ship(context.Background(), entry); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if _, stamped := source["audit_event_id"]; stamped {
		t.Error("the bridge wrote audit_event_id into the relay's own intent metadata")
	}
	if len(source) != 1 {
		t.Errorf("source metadata = %v, want it untouched", source)
	}
}

// TestShipperBridge_PropagatesTheShippersRefusal on the exact error, so the
// relay's ship-failure accounting is driven by the shipper and not swallowed
// here.
func TestShipperBridge_PropagatesTheShippersRefusal(t *testing.T) {
	sentinel := errors.New("siem down")
	err := (shipperBridge{shipper: &recordingShipper{err: sentinel}}).Ship(context.Background(), sampleEntry())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the shipper's own error", err)
	}
}

// TestNewOutboxRelay_NilShipperStaysNil. A bridge wrapping nothing would turn
// every delivery into a nil dereference inside the relay's best-effort shipping
// path; external shipping is optional, so "no shipper" has to reach the relay
// as no shipper.
func TestNewOutboxRelay_NilShipperStaysNil(t *testing.T) {
	relay := NewOutboxRelay(nil, nil, nil, auditoutbox.RelayConfig{})
	if relay == nil {
		t.Fatal("NewOutboxRelay returned nil")
	}
	// A relay with neither outbox nor sink must refuse to start rather than
	// idle: intents would accumulate with nothing to drain them.
	if err := relay.Start(context.Background()); !errors.Is(err, auditoutbox.ErrNoOutbox) {
		t.Fatalf("Start = %v, want auditoutbox.ErrNoOutbox", err)
	}
}

// TestRelayObserver_PublishesEveryMetric asserts EXACT values, and asserts them
// on a delta rather than on an absolute: these are process-wide collectors that
// another test in this package may already have moved.
func TestRelayObserver_PublishesEveryMetric(t *testing.T) {
	observer := relayObserver()

	deliveredBefore := testutil.ToFloat64(telemetry.AuditOutboxDeliveredTotal)
	failuresBefore := testutil.ToFloat64(telemetry.AuditOutboxDeliveryFailuresTotal)
	shipBefore := testutil.ToFloat64(telemetry.AuditOutboxShipFailuresTotal)
	prunedBefore := testutil.ToFloat64(telemetry.AuditOutboxPrunedTotal)

	observer.Delivered(3)
	observer.DeliveryFailures(2)
	observer.ShipFailures(1)
	observer.Pruned(7)
	observer.Backlog(auditoutbox.Backlog{
		Pending:       11,
		Failed:        4,
		OldestPending: time.Now().Add(-90 * time.Second),
	})

	for _, m := range []struct {
		name string
		got  float64
		want float64
	}{
		{"delivered", testutil.ToFloat64(telemetry.AuditOutboxDeliveredTotal) - deliveredBefore, 3},
		{"delivery failures", testutil.ToFloat64(telemetry.AuditOutboxDeliveryFailuresTotal) - failuresBefore, 2},
		{"ship failures", testutil.ToFloat64(telemetry.AuditOutboxShipFailuresTotal) - shipBefore, 1},
		{"pruned", testutil.ToFloat64(telemetry.AuditOutboxPrunedTotal) - prunedBefore, 7},
		{"pending", testutil.ToFloat64(telemetry.AuditOutboxPending), 11},
		{"failed", testutil.ToFloat64(telemetry.AuditOutboxFailed), 4},
	} {
		if m.got != m.want {
			t.Errorf("%s = %v, want %v", m.name, m.got, m.want)
		}
	}
	// The age is derived from a wall clock, so it is asserted as a band rather
	// than a value — but a band that excludes zero, which is what a gauge that
	// was never set reads as.
	if age := testutil.ToFloat64(telemetry.AuditOutboxOldestAgeSeconds); age < 89 || age > 120 {
		t.Errorf("oldest age = %v seconds, want ~90", age)
	}
}

// TestRelayObserver_ReportsNoAgeForAnEmptyBacklog. An age carried over from the
// last non-empty cycle is an alert that never clears.
func TestRelayObserver_ReportsNoAgeForAnEmptyBacklog(t *testing.T) {
	observer := relayObserver()
	observer.Backlog(auditoutbox.Backlog{Pending: 5, OldestPending: time.Now().Add(-time.Hour)})
	if age := testutil.ToFloat64(telemetry.AuditOutboxOldestAgeSeconds); age < 3000 {
		t.Fatalf("oldest age = %v, want the backlog's real age before the drain", age)
	}

	observer.Backlog(auditoutbox.Backlog{})
	if age := testutil.ToFloat64(telemetry.AuditOutboxOldestAgeSeconds); age != 0 {
		t.Errorf("oldest age = %v, want 0 once the backlog is empty", age)
	}
	if pending := testutil.ToFloat64(telemetry.AuditOutboxPending); pending != 0 {
		t.Errorf("pending = %v, want 0", pending)
	}
}

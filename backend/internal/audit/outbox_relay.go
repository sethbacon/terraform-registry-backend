// outbox_relay.go is all that remains here of the transactional audit outbox
// (issue #766, migration 000052): the mechanism itself now lives in the shared
// identity library as identity/auditoutbox, parameterised by the table names
// the app supplies, and this file is the registry-shaped wiring around it.
//
// WHY THE MECHANISM MOVED. The outbox was built here against two hardcoded
// names — `audit_outbox` and `audit_logs` — and under the identity model
// (sethbacon/terraform-suite-identity#206) audit_logs becomes per-app: two
// applications sharing one identity store keep two different destinations, so a
// shared implementation cannot name either. Extracting it also fixed two
// defects this copy had, which is why the copy is gone rather than kept in
// parallel:
//
//   - the destination probe was memoised with sync.Once, so a single transient
//     catalogue failure silently cost `actor_email` for the life of the
//     process. The library caches the probe only on SUCCESS.
//   - the delivered row filled actor_email with
//     `COALESCE($10, (SELECT email FROM users WHERE id = $2))`, a join from the
//     audit destination into identity — across a boundary that may be another
//     schema or another database, where the sub-select cannot resolve at all.
//     The address is captured at intent time, on the request path, which is the
//     only place it is reliably known.
//
// WHAT STAYS HERE is what the library must not own: this repository's
// Prometheus metrics, and this repository's external shippers (shipper.go),
// whose entry type is the registry's own LogEntry.
package audit

import (
	"context"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"

	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// OutboxTable and AuditLogTable are the two names this deployment's outbox
// mechanism addresses, in one place.
//
// SPELL THEM THE SAME WAY EVERYWHERE. Both are unqualified, so the connection's
// search_path places them — the same resolution the hand-written statements had
// before the swap, and the reason the swap needs no migration. Verify() reports
// which schema that turned out to be.
const (
	// OutboxTable holds audit intents on the REGISTRY's connection, beside the
	// privileged mutations whose transactions write them.
	OutboxTable = "audit_outbox"

	// AuditLogTable is the durable destination, on the IDENTITY connection —
	// the one that cannot join the mutation's transaction, which is why the
	// outbox exists.
	AuditLogTable = "audit_logs"
)

// relayObserver publishes one relay cycle's outcome to this repository's
// Prometheus metrics.
//
// The library ships no metrics registry and must not pick one for its two
// consuming applications, so the gauges and counters stay here and the relay
// calls into them. Every metric that existed before the swap is still fed, by
// the same arithmetic.
func relayObserver() auditoutbox.Observer {
	return auditoutbox.Observer{
		Backlog: func(b auditoutbox.Backlog) {
			telemetry.AuditOutboxPending.Set(float64(b.Pending))
			telemetry.AuditOutboxFailed.Set(float64(b.Failed))
			// Zero when nothing is pending: an age reported for an empty
			// backlog is a number that only ever grows and means nothing.
			var oldestAge float64
			if b.Pending > 0 && !b.OldestPending.IsZero() {
				oldestAge = time.Since(b.OldestPending).Seconds()
			}
			telemetry.AuditOutboxOldestAgeSeconds.Set(oldestAge)
		},
		Delivered:        func(n int) { telemetry.AuditOutboxDeliveredTotal.Add(float64(n)) },
		DeliveryFailures: func(n int) { telemetry.AuditOutboxDeliveryFailuresTotal.Add(float64(n)) },
		ShipFailures:     func(n int) { telemetry.AuditOutboxShipFailuresTotal.Add(float64(n)) },
		Pruned:           func(n int64) { telemetry.AuditOutboxPrunedTotal.Add(float64(n)) },
	}
}

// shipperBridge adapts this repository's Shipper — whose entry type is the
// registry's LogEntry, shared with the request-path audit middleware — to the
// library relay's own Shipper.
//
// A translation rather than a change of contract: the JSON a configured SIEM or
// webhook receives is byte-for-byte what it received before the swap, including
// `metadata.audit_event_id`, which is how a receiver collapses a redelivery
// instead of counting the same grant twice.
type shipperBridge struct {
	shipper Shipper
}

// Ship renders one delivered intent as a LogEntry and hands it to the wrapped
// shipper.
func (b shipperBridge) Ship(ctx context.Context, entry *auditoutbox.Entry) error {
	if entry == nil {
		return nil
	}
	// Copied, not written through: entry.Metadata is the relay's own claimed
	// intent map, and stamping the event id into it would mutate a value the
	// relay still holds.
	metadata := make(map[string]interface{}, len(entry.Metadata)+1)
	for k, v := range entry.Metadata {
		metadata[k] = v
	}
	metadata["audit_event_id"] = entry.EventID

	return b.shipper.Ship(ctx, &LogEntry{
		Timestamp:      entry.Timestamp,
		Action:         entry.Action,
		UserID:         entry.UserID,
		OrganizationID: entry.OrganizationID,
		ResourceType:   entry.ResourceType,
		ResourceID:     entry.ResourceID,
		IPAddress:      entry.IPAddress,
		Metadata:       metadata,
	})
}

// NewOutboxRelay constructs the library relay with this repository's metrics
// and shippers attached.
//
// shipper may be nil — external shipping is optional — and a nil one is passed
// through as a nil library Shipper rather than as a bridge wrapping nothing,
// which would turn every delivery into a nil-pointer dereference inside the
// relay's best-effort path.
func NewOutboxRelay(outbox *auditoutbox.Outbox, sink auditoutbox.Sink, shipper Shipper, cfg auditoutbox.RelayConfig) *auditoutbox.Relay {
	var bridged auditoutbox.Shipper
	if shipper != nil {
		bridged = shipperBridge{shipper: shipper}
	}
	cfg.Observer = relayObserver()
	return auditoutbox.NewRelay(outbox, sink, bridged, cfg)
}

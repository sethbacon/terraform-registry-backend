// relay.go delivers the transactional outbox (outbox.go) to audit_logs and to
// any configured shippers.
//
// THE CRASH CONTRACT.
//
// One cycle is: claim a batch inside a transaction on the registry connection,
// deliver each intent, mark it delivered, commit. The mark and the claim share
// that transaction, so a process that dies at any point before the commit
// leaves every intent in the cycle still undelivered — and the next relay (this
// process after a restart, or another replica) claims them again. Nothing is
// lost by a crash; the cost of one is a redelivery, which the sink absorbs by
// keying audit_logs on the intent's own EventID (sink.go).
//
// Delivery is therefore at-least-once in transport and exactly-once in effect.
package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// Relay defaults. Deliberately unexcitable: these are privileged-mutation
// records, a handful an hour in a busy deployment, and a tight poll would spend
// far more on empty scans than the latency is worth.
const (
	defaultRelayInterval        = 10 * time.Second
	defaultRelayBatchSize       = 100
	defaultRelayMaxBatches      = 10
	defaultRelayBacklogWarn     = 100
	defaultRelayDeliveredRetain = 7 * 24 * time.Hour
)

// RelayConfig tunes the relay. The zero value is valid and means the defaults
// above.
type RelayConfig struct {
	// PollInterval is how often the relay looks for undelivered intents.
	PollInterval time.Duration
	// BatchSize is how many intents one claim takes.
	BatchSize int
	// BacklogWarn is the undelivered depth at which the relay starts logging at
	// ERROR. Zero means the default; negative disables the alarm.
	BacklogWarn int64
	// RetainDelivered is how long a delivered intent is kept before pruning.
	// The outbox is a delivery queue, not a second copy of the audit trail —
	// audit_logs is the record, and its own retention is configured separately
	// (audit_retention.*). Negative disables pruning, which is how an operator
	// keeps the outbox as a delivery ledger for reconciliation.
	RetainDelivered time.Duration
}

func (c RelayConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return defaultRelayInterval
	}
	return c.PollInterval
}

func (c RelayConfig) batchSize() int {
	if c.BatchSize <= 0 {
		return defaultRelayBatchSize
	}
	return c.BatchSize
}

func (c RelayConfig) backlogWarn() int64 {
	if c.BacklogWarn == 0 {
		return defaultRelayBacklogWarn
	}
	return c.BacklogWarn
}

func (c RelayConfig) retainDelivered() time.Duration {
	if c.RetainDelivered == 0 {
		return defaultRelayDeliveredRetain
	}
	return c.RetainDelivered
}

// Relay drains the audit outbox. It satisfies the jobs.Job interface so the
// registry starts and stops it with everything else.
type Relay struct {
	outbox  *Outbox
	sink    Sink
	shipper Shipper
	cfg     RelayConfig

	stopChan chan struct{}
}

// NewRelay constructs a Relay. shipper may be nil when no external shipping is
// configured; sink may not be, since it is the durable destination.
func NewRelay(outbox *Outbox, sink Sink, shipper Shipper, cfg RelayConfig) *Relay {
	return &Relay{
		outbox:   outbox,
		sink:     sink,
		shipper:  shipper,
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}
}

// Name returns the job name used in logs.
func (r *Relay) Name() string { return "audit-outbox-relay" }

// Start runs one cycle immediately, then on a ticker, until Stop or ctx.
//
// A misconfigured relay REFUSES TO START rather than idling: with no outbox or
// no sink, every intent written by the mutation paths would accumulate forever
// with nothing to drain it, and the deployment would look healthy while its
// audit trail sat undelivered.
func (r *Relay) Start(ctx context.Context) error {
	if r.outbox == nil || r.outbox.db == nil {
		return ErrNoOutbox
	}
	if r.sink == nil {
		return errors.New("audit relay: no sink configured; audit intents would never reach audit_logs")
	}

	slog.Info("audit outbox relay: started",
		"poll_interval", r.cfg.pollInterval(), "batch_size", r.cfg.batchSize())

	r.RunCycle(ctx)

	ticker := time.NewTicker(r.cfg.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.RunCycle(ctx)
		case <-r.stopChan:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop signals the relay to exit. Safe to call more than once.
func (r *Relay) Stop() error {
	select {
	case <-r.stopChan:
	default:
		close(r.stopChan)
	}
	return nil
}

// RunCycle drains up to defaultRelayMaxBatches batches, then reports the
// backlog and prunes delivered history.
//
// The batch cap bounds one cycle's work so a large backlog cannot starve
// shutdown or hold a transaction open indefinitely; what it does not drain is
// picked up on the next tick.
//
// Exported so a test — and an operator, through a one-shot invocation — can
// drive delivery deterministically instead of racing the ticker.
func (r *Relay) RunCycle(ctx context.Context) {
	for i := 0; i < defaultRelayMaxBatches; i++ {
		claimed, delivered, err := r.DeliverBatch(ctx)
		if err != nil {
			slog.Error("audit outbox relay: delivery cycle failed", "error", err)
			break
		}
		if delivered > 0 {
			telemetry.AuditOutboxDeliveredTotal.Add(float64(delivered))
		}
		// A short batch means the queue is drained (or the rest is locked by
		// another replica); either way there is nothing more to do this cycle.
		if claimed < r.cfg.batchSize() {
			break
		}
	}

	r.observeBacklog(ctx)
	r.prune(ctx)
}

// DeliverBatch runs exactly one claim/deliver/commit cycle and reports how many
// intents were claimed and how many of those were delivered.
//
// A single intent that fails to deliver does not abort the batch: its failure
// is recorded on its own row, it stays undelivered, and the rest of the batch
// proceeds. Aborting instead would let one poisoned record block every audit
// entry behind it.
func (r *Relay) DeliverBatch(ctx context.Context) (claimed, delivered int, err error) {
	if r.outbox == nil || r.outbox.db == nil {
		return 0, 0, ErrNoOutbox
	}
	if r.sink == nil {
		return 0, 0, errors.New("audit relay: no sink configured")
	}

	tx, err := r.outbox.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	// Rolled back unconditionally; after a successful Commit this is a no-op
	// returning sql.ErrTxDone. A panic or a process death between here and the
	// Commit therefore leaves every claimed intent undelivered, which is the
	// crash contract this design rests on.
	defer func() { _ = tx.Rollback() }()

	intents, err := r.outbox.claim(ctx, tx, r.cfg.batchSize())
	if err != nil {
		return 0, 0, err
	}
	if len(intents) == 0 {
		// Nothing claimed: commit (releasing the snapshot) and report an empty
		// batch rather than holding the transaction open.
		return 0, 0, tx.Commit()
	}

	var failures int
	for _, intent := range intents {
		if derr := r.sink.Deliver(ctx, intent.Intent); derr != nil {
			failures++
			slog.Error("audit outbox relay: delivery failed; intent retained for retry",
				"event_id", intent.EventID, "action", intent.Action,
				"attempts", intent.Attempts+1, "error", derr)
			if rerr := r.outbox.recordFailure(ctx, tx, intent.EventID, derr); rerr != nil {
				return len(intents), 0, rerr
			}
			continue
		}

		// Shipping is best-effort BY DESIGN and deliberately after the durable
		// write. audit_logs is the audit trail; a shipper is external
		// visibility (see shipper.go). Holding the intent for a broken SIEM
		// would grow the backlog without protecting the record, so a shipping
		// failure is counted and logged, not retried here.
		r.ship(ctx, intent.Intent)

		if merr := r.outbox.markDelivered(ctx, tx, intent.EventID); merr != nil {
			return len(intents), 0, merr
		}
		delivered++
	}

	if failures > 0 {
		telemetry.AuditOutboxDeliveryFailuresTotal.Add(float64(failures))
	}
	if err := tx.Commit(); err != nil {
		// Nothing was marked. Every intent in this batch is still pending and
		// will be claimed again.
		return len(intents), 0, err
	}
	return len(intents), delivered, nil
}

// ship forwards a delivered intent to the configured external shippers.
func (r *Relay) ship(ctx context.Context, intent Intent) {
	if r.shipper == nil {
		return
	}
	entry := &LogEntry{
		Timestamp:    intent.OccurredAt,
		Action:       intent.Action,
		ResourceType: derefString(intent.ResourceType),
		ResourceID:   derefString(intent.ResourceID),
		IPAddress:    derefString(intent.IPAddress),
		Metadata:     intent.Metadata,
	}
	entry.UserID = derefString(intent.ActorUserID)
	entry.OrganizationID = derefString(intent.OrganizationID)
	if entry.Metadata == nil {
		entry.Metadata = map[string]interface{}{}
	}
	// The stable event id travels with the entry so a SIEM can collapse a
	// redelivery instead of counting the same grant twice.
	entry.Metadata["audit_event_id"] = intent.EventID

	if err := r.shipper.Ship(ctx, entry); err != nil {
		slog.Error("audit outbox relay: external shipping failed (the audit_logs record is unaffected)",
			"event_id", intent.EventID, "error", err)
		telemetry.AuditOutboxShipFailuresTotal.Inc()
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// observeBacklog publishes the undelivered depth and shouts when it grows.
//
// The backlog cannot be bounded by discarding it — that would throw away the
// records the outbox exists to keep — so it is bounded by being LOUD instead:
// two gauges an operator can alert on, and an ERROR line naming the depth and
// the age of the oldest intent once it crosses the threshold.
func (r *Relay) observeBacklog(ctx context.Context) {
	backlog, err := r.outbox.Backlog(ctx)
	if err != nil {
		slog.Error("audit outbox relay: failed to read backlog", "error", err)
		return
	}

	telemetry.AuditOutboxPending.Set(float64(backlog.Pending))
	telemetry.AuditOutboxFailed.Set(float64(backlog.Failed))
	var oldestAge float64
	if backlog.Pending > 0 && !backlog.OldestPending.IsZero() {
		oldestAge = time.Since(backlog.OldestPending).Seconds()
	}
	telemetry.AuditOutboxOldestAgeSeconds.Set(oldestAge)

	warnAt := r.cfg.backlogWarn()
	if warnAt > 0 && backlog.Pending >= warnAt {
		slog.Error("audit outbox backlog is not draining: privileged mutations are recorded but not yet in audit_logs",
			"pending", backlog.Pending, "failed_at_least_once", backlog.Failed,
			"oldest_age_seconds", int64(oldestAge), "threshold", warnAt)
	}
}

// prune removes delivered intents past their retention.
func (r *Relay) prune(ctx context.Context) {
	retain := r.cfg.retainDelivered()
	if retain < 0 {
		return
	}
	pruned, err := r.outbox.PruneDelivered(ctx, time.Now().Add(-retain), r.cfg.batchSize()*defaultRelayMaxBatches)
	if err != nil {
		slog.Error("audit outbox relay: prune failed", "error", err)
		return
	}
	if pruned > 0 {
		telemetry.AuditOutboxPrunedTotal.Add(float64(pruned))
		slog.Info("audit outbox relay: pruned delivered intents", "pruned", pruned, "retain", retain)
	}
}

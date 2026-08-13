// outbox.go implements the transactional audit outbox (issue #766, migration
// 000052).
//
// WHY AN OUTBOX AND NOT A SECOND WRITE.
//
// The platform-admin carrier lives on the REGISTRY connection; audit_logs lives
// on the IDENTITY connection, which may be another schema or another database
// entirely. They cannot share a transaction, so the carrier's management API
// used to write the grant, then write the audit entry, and — when the second
// write failed — log at error level and report success anyway. The highest
// privilege in the product could therefore change hands with no audit record.
//
// The outbox removes the divergence by removing the second write from the
// request path. The audit INTENT is inserted into `audit_outbox`, on the same
// connection and in the same transaction as the mutation, so the two commit
// together or not at all. A relay (relay.go) delivers intents to audit_logs and
// to any configured shippers afterwards, at least once.
//
// EventID is chosen here, before the mutation commits, and is reused verbatim
// as audit_logs.id — which is what makes redelivery idempotent rather than
// merely retried: the second attempt collides on the destination's primary key
// (sink.go).
//
// The property is enforced BELOW this package as well. Migration 000052 puts a
// deferred constraint trigger on platform_admins that re-checks, at COMMIT,
// that the transaction wrote a matching intent. Code that forgets to call
// Enqueue does not fail silently; its transaction does not commit.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrNoOutbox is returned by the mutation paths when no outbox is wired.
//
// A privileged mutation with nowhere to record its audit intent must not
// proceed. This is the fail-closed answer at the Go layer; migration 000052's
// trigger is the one that holds even when this check is bypassed.
var ErrNoOutbox = errors.New("audit outbox not configured")

// ErrIntentIncomplete marks an Intent that cannot be audited meaningfully.
// Rejected before the mutation rather than stored and puzzled over later.
var ErrIntentIncomplete = errors.New("audit intent is incomplete")

// Intent is one audit record, captured in the same transaction as the mutation
// it describes and delivered afterwards.
//
// The field set is audit_logs' own, so delivery is a copy rather than a
// translation. ActorEmail is denormalised for the same reason identity's
// audit_logs.actor_email is: the entry must stay attributable after the user
// row is gone.
type Intent struct {
	// EventID is the stable identity of this event. It becomes audit_logs.id,
	// so it is what makes redelivery idempotent. Left empty, Enqueue mints one.
	EventID string
	// OccurredAt is when the audited event happened, NOT when it was delivered.
	// Defaulted to now() by Enqueue.
	OccurredAt time.Time
	// Action is the dotted event name ("platform_admin.granted"). Required.
	Action string
	// ActorUserID is the acting principal, nil for an unattributable event.
	ActorUserID *string
	// ActorEmail is the actor's address as it stood at the time.
	ActorEmail *string
	// OrganizationID is the owning organization, nil for platform-wide events.
	OrganizationID *string
	// ResourceType and ResourceID name the thing acted upon.
	ResourceType *string
	ResourceID   *string
	// IPAddress is the client address the request arrived from.
	IPAddress *string
	// Metadata is the free-form detail, stored as JSONB.
	Metadata map[string]interface{}
}

// pendingIntent is an outbox row the relay has claimed for delivery.
type pendingIntent struct {
	Intent
	Attempts int
}

// Outbox is the audit outbox table on the registry's own connection.
type Outbox struct {
	db *sql.DB
}

// NewOutbox constructs an Outbox over the registry's domain connection — the
// SAME connection the privileged mutations run on. Handing it the identity
// connection instead would reintroduce exactly the cross-connection split this
// exists to remove, so callers must pass the connection the mutation uses.
func NewOutbox(db *sql.DB) *Outbox {
	return &Outbox{db: db}
}

// DB exposes the connection the outbox lives on, so a caller can assert it is
// the same one its mutations use.
func (o *Outbox) DB() *sql.DB {
	if o == nil {
		return nil
	}
	return o.db
}

const outboxInsert = `
	INSERT INTO audit_outbox (
		event_id, occurred_at, action, actor_user_id, actor_email,
		organization_id, resource_type, resource_id, ip_address, metadata
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

// Enqueue writes intent into the outbox INSIDE tx — the caller's transaction,
// the one carrying the mutation being audited. It does not commit; that is the
// caller's, so the record and the mutation land together or neither does.
//
// A nil Outbox or a nil tx is an error rather than a no-op. Both mean the
// intent would be lost, and a lost audit intent must fail the mutation, not
// accompany it silently.
//
// EventID is filled in when empty, and written back into intent so the caller
// can log or return it.
func (o *Outbox) Enqueue(ctx context.Context, tx *sql.Tx, intent *Intent) error {
	if o == nil || o.db == nil {
		return ErrNoOutbox
	}
	if tx == nil {
		return fmt.Errorf("%w: no transaction to enlist in", ErrNoOutbox)
	}
	if intent == nil {
		return fmt.Errorf("%w: nil intent", ErrIntentIncomplete)
	}
	if intent.Action == "" {
		return fmt.Errorf("%w: action is empty", ErrIntentIncomplete)
	}
	if intent.EventID == "" {
		intent.EventID = uuid.New().String()
	}
	if intent.OccurredAt.IsZero() {
		intent.OccurredAt = time.Now().UTC()
	}

	metadataArg, err := marshalMetadata(intent.Metadata)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, outboxInsert,
		intent.EventID,
		intent.OccurredAt,
		intent.Action,
		intent.ActorUserID,
		intent.ActorEmail,
		intent.OrganizationID,
		intent.ResourceType,
		intent.ResourceID,
		intent.IPAddress,
		metadataArg,
	)
	if err != nil {
		return fmt.Errorf("failed to enqueue audit intent: %w", err)
	}
	return nil
}

// marshalMetadata renders Metadata for a JSONB column. A nil map is sent as SQL
// NULL (a nil interface{}, the same convention the identity store uses) rather
// than the string "null".
func marshalMetadata(m map[string]interface{}) (interface{}, error) {
	if m == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit intent metadata: %w", err)
	}
	return encoded, nil
}

// outboxColumns is the projection the claim scan reads, in one place so the
// query and the scan cannot drift.
const outboxColumns = `event_id, occurred_at, action, actor_user_id, actor_email,
	organization_id, resource_type, resource_id, ip_address, metadata, attempts`

// claim locks up to limit undelivered intents inside tx.
//
// FOR UPDATE SKIP LOCKED, not a plain FOR UPDATE: several replicas run the
// relay, and a replica that blocks behind another's batch delivers nothing
// while it waits. SKIP LOCKED lets each take a disjoint set, and the rows one
// replica skips are picked up on the next cycle.
//
// Oldest first, so a backlog drains in the order events happened.
func (o *Outbox) claim(ctx context.Context, tx *sql.Tx, limit int) ([]pendingIntent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+outboxColumns+`
		  FROM audit_outbox
		 WHERE delivered_at IS NULL
		 ORDER BY occurred_at ASC, event_id ASC
		 LIMIT $1
		   FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to claim audit intents: %w", err)
	}
	defer rows.Close()

	var claimed []pendingIntent
	for rows.Next() {
		var p pendingIntent
		var metadata []byte
		if err := rows.Scan(&p.EventID, &p.OccurredAt, &p.Action, &p.ActorUserID, &p.ActorEmail,
			&p.OrganizationID, &p.ResourceType, &p.ResourceID, &p.IPAddress, &metadata, &p.Attempts); err != nil {
			return nil, fmt.Errorf("failed to scan audit intent: %w", err)
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &p.Metadata); err != nil {
				// The record still delivers; only the detail is unreadable.
				// Dropping the whole entry over a bad metadata blob would lose
				// the who/what/when, which is the part that matters.
				p.Metadata = map[string]interface{}{"metadata_unreadable": err.Error()}
			}
		}
		claimed = append(claimed, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read claimed audit intents: %w", err)
	}
	return claimed, nil
}

// markDelivered records a successful delivery inside tx.
func (o *Outbox) markDelivered(ctx context.Context, tx *sql.Tx, eventID string) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE audit_outbox
		    SET delivered_at = now(), attempts = attempts + 1, last_error = NULL
		  WHERE event_id = $1`, eventID)
	if err != nil {
		return fmt.Errorf("failed to mark audit intent %s delivered: %w", eventID, err)
	}
	return nil
}

// recordFailure counts an attempt and keeps the reason, leaving delivered_at
// NULL so the intent is retried. The row stays in the backlog on purpose: an
// audit intent is never dropped for failing to deliver.
func (o *Outbox) recordFailure(ctx context.Context, tx *sql.Tx, eventID string, cause error) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE audit_outbox
		    SET attempts = attempts + 1, last_error = $2
		  WHERE event_id = $1`, eventID, cause.Error())
	if err != nil {
		return fmt.Errorf("failed to record audit intent %s failure: %w", eventID, err)
	}
	return nil
}

// Backlog is what an operator needs to see: how many audit records exist but
// have not reached audit_logs, how long the oldest has been waiting, and how
// many have already failed at least once.
type Backlog struct {
	// Pending is the number of undelivered intents.
	Pending int64
	// Failed is the subset of Pending that has failed at least one attempt.
	// Pending alone cannot distinguish "written a moment ago" from "stuck".
	Failed int64
	// OldestPending is when the oldest undelivered event occurred. Zero when
	// Pending is 0.
	OldestPending time.Time
}

// Backlog reads the current undelivered depth.
func (o *Outbox) Backlog(ctx context.Context) (Backlog, error) {
	if o == nil || o.db == nil {
		return Backlog{}, ErrNoOutbox
	}
	var b Backlog
	var oldest sql.NullTime
	err := o.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE attempts > 0),
		       min(occurred_at)
		  FROM audit_outbox
		 WHERE delivered_at IS NULL`).Scan(&b.Pending, &b.Failed, &oldest)
	if err != nil {
		return Backlog{}, fmt.Errorf("failed to read audit outbox backlog: %w", err)
	}
	if oldest.Valid {
		b.OldestPending = oldest.Time
	}
	return b, nil
}

// PruneDelivered removes delivered intents older than before, in batches of at
// most limit, and returns how many rows went.
//
// ONLY DELIVERED ROWS. The undelivered backlog is never pruned — deleting an
// intent that never reached audit_logs would destroy the record this whole
// design exists to keep. That is why the backlog is reported and alarmed on
// instead: it can only be drained by delivering it.
func (o *Outbox) PruneDelivered(ctx context.Context, before time.Time, limit int) (int64, error) {
	if o == nil || o.db == nil {
		return 0, ErrNoOutbox
	}
	if limit <= 0 {
		limit = 1000
	}
	res, err := o.db.ExecContext(ctx, `
		DELETE FROM audit_outbox
		 WHERE event_id IN (
		       SELECT event_id FROM audit_outbox
		        WHERE delivered_at IS NOT NULL AND delivered_at < $1
		        ORDER BY delivered_at ASC
		        LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to prune delivered audit intents: %w", err)
	}
	pruned, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to count pruned audit intents: %w", err)
	}
	return pruned, nil
}

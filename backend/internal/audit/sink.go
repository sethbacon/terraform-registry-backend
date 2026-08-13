// sink.go is the delivery end of the outbox: it writes a claimed Intent into
// `audit_logs` on the IDENTITY connection, idempotently.
//
// WHY THIS WRITES audit_logs DIRECTLY INSTEAD OF CALLING
// AuditRepository.CreateAuditLog.
//
// Delivery is at-least-once — that is what makes it survive a crash — so the
// destination has to be able to recognise a record it already holds. The only
// thing that can enforce that is the destination's own primary key, which means
// the id must come from the intent. The shared identity store's CreateAuditLog
// mints `uuid.New()` on every call and overwrites whatever the caller set, so
// redelivering through it would append a second copy of the same event rather
// than collide with the first.
//
// So the sink owns one INSERT with the intent's EventID as audit_logs.id and
// ON CONFLICT (id) DO NOTHING. Redelivery is then a no-op at the database, and
// "at-least-once transport" becomes "exactly once in effect".
//
// This is a delivery-path duplicate of one INSERT, not a fork of the identity
// store: the audit WRITE API every handler calls is untouched
// (AuditRepository.CreateAuditLog), and the delivered rows carry the same
// column set, so a reader cannot tell which writer produced them.
//
// AND IT IS WHY THIS PATH STILL WORKS UNDER ISSUE #864. CreateAuditLog writes
// `actor_email` unconditionally, but that column exists only on
// identity.audit_logs (identity migration 000007) — never on the registry's own
// public.audit_logs (migration 000001), which is what `audit_logs` resolves to
// in the DEFAULT topology. Every call through the shared writer therefore fails
// with 42703 out of the box. The sink asks the connection which columns the
// table it is about to write actually has, so the outbox delivers the
// platform-admin trail on a default deployment today, and would deliver a
// backlog accumulated before #864 is fixed rather than retrying into a wall.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// Sink is the durable destination for a delivered intent.
//
// Deliver MUST be idempotent: the relay may call it more than once for the same
// EventID, and must be able to do so without producing a second record.
type Sink interface {
	Deliver(ctx context.Context, intent Intent) error
}

// AuditLogSink writes intents into `audit_logs` on the identity connection.
type AuditLogSink struct {
	db *sql.DB

	// actor_email exists on identity.audit_logs (identity migration 000007) but
	// not on the registry's own public.audit_logs (migration 000001), and which
	// one `audit_logs` resolves to depends on the connection's search_path. The
	// column set is therefore probed once, on the connection actually in use,
	// rather than assumed from configuration.
	probeOnce     sync.Once
	hasActorEmail bool
}

// NewAuditLogSink constructs a sink over the identity connection — the same one
// AuditRepository uses, so the delivered rows land where every audit reader
// looks.
func NewAuditLogSink(db *sql.DB) *AuditLogSink {
	return &AuditLogSink{db: db}
}

// Deliver inserts the intent as an audit_logs row keyed by its EventID.
//
// ON CONFLICT (id) DO NOTHING is the idempotence. A redelivery after a crash,
// or a duplicate claim by a second replica, updates nothing and reports
// success — which is correct: the record the caller is asking for is already
// there.
func (s *AuditLogSink) Deliver(ctx context.Context, intent Intent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit sink: no identity connection configured")
	}
	if intent.EventID == "" {
		// Without a stable id there is no idempotence, only duplicates.
		return fmt.Errorf("%w: event id is empty", ErrIntentIncomplete)
	}

	metadataArg, err := marshalMetadata(intent.Metadata)
	if err != nil {
		return err
	}

	s.probeOnce.Do(func() { s.hasActorEmail = s.probeActorEmail(ctx) })

	args := []interface{}{
		intent.EventID,
		intent.ActorUserID,
		intent.OrganizationID,
		intent.Action,
		intent.ResourceType,
		intent.ResourceID,
		metadataArg,
		intent.IPAddress,
		intent.OccurredAt,
	}
	query := `INSERT INTO audit_logs
		(id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`
	if s.hasActorEmail {
		// COALESCE, exactly as the identity store's own insert does: the
		// address captured at intent time wins, and a caller that had none
		// falls back to resolving it now.
		args = append(args, intent.ActorEmail)
		query = `INSERT INTO audit_logs
		(id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, (SELECT email FROM users WHERE id = $2)))
		ON CONFLICT (id) DO NOTHING`
	}

	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to deliver audit intent %s: %w", intent.EventID, err)
	}
	return nil
}

// probeActorEmail reports whether the audit_logs this connection resolves to
// carries actor_email.
//
// to_regclass respects the connection's search_path, so the answer is about the
// table that will actually be written, not about a schema name guessed from
// config. A failed probe answers false: the narrower insert is valid against
// both schemas, so an unreadable catalogue costs the denormalised address, not
// the audit record.
func (s *AuditLogSink) probeActorEmail(ctx context.Context) bool {
	var present bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_attribute
			 WHERE attrelid = to_regclass('audit_logs')
			   AND attname = 'actor_email'
			   AND NOT attisdropped)`).Scan(&present)
	if err != nil {
		return false
	}
	return present
}

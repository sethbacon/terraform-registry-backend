-- 000052_audit_outbox
--
-- A transactional outbox for audit records, and a database-level refusal to
-- change platform-admin authority without one (issue #766).
--
-- THE DEFECT THIS CLOSES.
--
-- The platform-admin carrier (`platform_admins`, migration 000051) lives on the
-- REGISTRY connection. `audit_logs` lives on the IDENTITY connection, which may
-- be another schema or another database entirely. They cannot share a
-- transaction, so PR 2 wrote the grant, then wrote the audit entry, and — when
-- the second write failed — logged at error level and reported the mutation as
-- a success anyway. Returning 500 was rejected because it invites a retry that
-- then 409s. The result: the highest-privilege operation in the product could
-- succeed with no audit record, and nothing detected it.
--
-- THE FIX, IN TWO HALVES.
--
--   1. `audit_outbox` is on the registry connection, beside the carrier, so the
--      audit INTENT commits in the SAME transaction as the mutation or neither
--      does. A relay (internal/audit) delivers intents to `audit_logs` and to
--      any configured shippers afterwards, at least once. event_id is chosen at
--      intent time and becomes `audit_logs.id`, so redelivery collides on the
--      primary key instead of duplicating the record.
--
--   2. A DEFERRABLE INITIALLY DEFERRED constraint trigger on `platform_admins`
--      re-checks, at COMMIT, that this transaction wrote a matching intent. A
--      mutation without one does not commit. That is the difference between a
--      property the code intends and a property the database enforces: it holds
--      for a future handler that forgets, for a migration, and for the
--      hand-written SQL that the management API was built to replace.
--
-- WHY txid AND NOT A FOREIGN KEY. "Same transaction" is the property being
-- enforced, and no constraint can express it — an FK would be satisfied by an
-- intent written days earlier. pg_current_xact_id() is the top-level
-- transaction id, recorded on the intent as it is written and compared at
-- commit; it requires PostgreSQL 13+, and this product requires 14+ (README).

CREATE TABLE IF NOT EXISTS audit_outbox (
    -- Chosen by the writer BEFORE the mutation commits, and reused verbatim as
    -- audit_logs.id. That is what makes redelivery idempotent: the second
    -- attempt conflicts on the destination's primary key.
    event_id        UUID        PRIMARY KEY,
    -- The transaction that wrote this intent. Read only by the trigger below.
    txid            xid8        NOT NULL DEFAULT pg_current_xact_id(),
    -- When the audited event happened, not when it was delivered. Delivery may
    -- be minutes later; the audit trail must say the former.
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    action          VARCHAR(500) NOT NULL,
    actor_user_id   UUID,
    -- The actor's address as it stood at the time, denormalised for the same
    -- reason identity's audit_logs.actor_email is: the entry must stay
    -- attributable after the user row is gone.
    actor_email     VARCHAR(255),
    organization_id UUID,
    resource_type   VARCHAR(100),
    resource_id     VARCHAR(255),
    ip_address      VARCHAR(45),
    metadata        JSONB,
    -- Delivery bookkeeping. delivered_at IS NULL is the backlog.
    delivered_at    TIMESTAMPTZ,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The relay's claim scan. Partial, on the undelivered rows only, so it stays
-- small no matter how much delivered history has yet to be pruned.
CREATE INDEX IF NOT EXISTS idx_audit_outbox_pending
    ON audit_outbox (occurred_at, event_id) WHERE delivered_at IS NULL;

-- The pruner's scan over delivered history.
CREATE INDEX IF NOT EXISTS idx_audit_outbox_delivered
    ON audit_outbox (delivered_at) WHERE delivered_at IS NOT NULL;

-- The trigger's same-transaction lookup. Every commit that touches
-- platform_admins runs it, so it is not optional.
CREATE INDEX IF NOT EXISTS idx_audit_outbox_txid
    ON audit_outbox (txid, resource_type, resource_id);

-- audit_outbox_assert_intent raises unless the CURRENT transaction has already
-- written an intent naming this subject with this action.
--
-- resource_id is compared case-insensitively: uuid::text is canonical
-- lowercase, but an operator writing the intent by hand may not be.
CREATE OR REPLACE FUNCTION audit_outbox_assert_intent(
    subject UUID, resource VARCHAR, expected_action VARCHAR
) RETURNS void AS $$
BEGIN
    IF subject IS NULL THEN
        RAISE EXCEPTION 'audit outbox: refusing a % mutation with no subject to audit', resource
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_outbox o
         WHERE o.txid = pg_current_xact_id()
           AND o.resource_type = resource
           AND lower(o.resource_id) = subject::text
           AND o.action = expected_action
    ) THEN
        RAISE EXCEPTION 'audit outbox: % on % has no audit intent in this transaction (expected an audit_outbox row with action=%, resource_type=%, resource_id=%)',
            expected_action, subject, expected_action, resource, subject
            USING ERRCODE = '23514',
                  HINT = 'Write the audit_outbox intent in the same transaction as the mutation. See internal/audit/outbox.go and migrations/README.md.';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- platform_admins_require_audit_intent is the enforcement point.
--
-- The action names are the audit vocabulary in
-- internal/api/admin/platform_admins.go. They are pinned HERE on purpose:
-- an intent that merely mentions the subject would let a revocation be
-- committed under a grant's record. Renaming an action without editing this
-- function makes the mutation fail loudly at commit rather than pass
-- unaudited.
CREATE OR REPLACE FUNCTION platform_admins_require_audit_intent() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM audit_outbox_assert_intent(NEW.user_id, 'platform_admin', 'platform_admin.granted');
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM audit_outbox_assert_intent(OLD.user_id, 'platform_admin', 'platform_admin.revoked');
    ELSE
        -- UPDATE. Nothing in the product updates a carrier row today; if
        -- something starts, it is audited like everything else. A repointed
        -- user_id is two subjects and needs an intent for each, otherwise the
        -- grant could be moved to a different principal under one record.
        PERFORM audit_outbox_assert_intent(OLD.user_id, 'platform_admin', 'platform_admin.updated');
        IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
            PERFORM audit_outbox_assert_intent(NEW.user_id, 'platform_admin', 'platform_admin.updated');
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- DEFERRABLE INITIALLY DEFERRED: the check runs at COMMIT, so the mutation and
-- its intent may be written in either order within the transaction, and the
-- failure aborts the commit rather than one statement.
DROP TRIGGER IF EXISTS platform_admins_require_audit_intent ON platform_admins;
CREATE CONSTRAINT TRIGGER platform_admins_require_audit_intent
    AFTER INSERT OR UPDATE OR DELETE ON platform_admins
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION platform_admins_require_audit_intent();

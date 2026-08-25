-- 000058_audit_logs_actor_email
--
-- Give this repository's audit_logs the actor_email column the shared identity
-- store has written and read since v0.25.0. Issue #864.
--
-- THE DEFECT, AS IT REACHED PRODUCTION
--
-- identity/store/audit_repository.go names actor_email in both directions:
--
--   INSERT INTO audit_logs (..., actor_email) VALUES (..., ...)
--   SELECT ..., al.actor_email FROM audit_logs al
--
-- unqualified, so the connection's search_path decides which table that is.
-- TFR_IDENTITY_SCHEMA_ENABLED is what puts the identity schema on that path and
-- it is OFF BY DEFAULT, so identityDB is the plain app pool and both statements
-- resolve to public.audit_logs — created by this chain's 000001, which never had
-- the column. Every audited request and every read of /api/v1/admin/audit-logs
-- died on 42703, silently: the write path logged nothing and the read handler
-- discarded the error.
--
-- TWO FLAGS, NOT ONE, and this is the part worth keeping. Enabling
-- TFR_IDENTITY_MIGRATIONS_ENABLED does NOT fix it: identity's 000007 is
-- schema-qualified (ALTER TABLE identity.audit_logs), so running that chain adds
-- the column to a table the default configuration never touches. The 42703 is
-- identical before and after.
--
-- WHY THIS REMEDY
--
-- schemaguard's knownGaps entry for #864 lists three ways out: this migration,
-- making the cutover the default, or a probed write in the library
-- (terraform-suite-identity#203). This is the one that fixes the DEFAULT
-- deployment without asking every operator to change configuration, and it is
-- additive — a deployment that later completes the cutover reads
-- identity.audit_logs, where the column already exists, and this one becomes
-- inert rather than wrong.
--
-- The shape mirrors identity's 000007 exactly, including the backfill, so the
-- two tables cannot answer the same question differently.

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_email VARCHAR(255);

-- Backfill every row whose actor still exists. Rows whose actor was already
-- deleted stay NULL — that attribution is gone and this migration will not
-- invent it. Mirrors identity 000007's backfill.
UPDATE audit_logs al
   SET actor_email = u.email
  FROM users u
 WHERE al.user_id = u.id
   AND al.actor_email IS NULL;

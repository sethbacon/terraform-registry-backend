-- 000058_audit_logs_actor_email (down)
--
-- Dropping actor_email discards the retained attribution for every audit row
-- whose user has since been deleted — the exact case the column exists for,
-- and the one no backfill can rebuild, because the users row it would read is
-- gone. Rolling this back is lossy in a way the up migration is not.
--
-- It is still a real DROP rather than a no-op: leaving the column behind on a
-- rollback to a version whose queries do not name it is harmless, but leaving
-- it behind while the schema chain says it is absent is the drift this whole
-- issue was about.
--
-- Preserve it first if any row is attributed to a deleted user:
--   COPY (SELECT id, actor_email FROM audit_logs WHERE actor_email IS NOT NULL)
--     TO '/tmp/audit_actor_email.csv' CSV HEADER;

ALTER TABLE audit_logs DROP COLUMN IF EXISTS actor_email;

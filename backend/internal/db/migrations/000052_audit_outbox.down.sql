-- 000052_audit_outbox (down)
--
-- The trigger goes first: dropping audit_outbox while the trigger still reads
-- it would leave every platform-admin mutation failing at commit with a missing
-- relation instead of a clean refusal.
--
-- ROLLING BACK REOPENS THE HOLE. After this runs, a platform-admin grant or
-- revoke can once again commit with no audit record — the failure mode issue
-- #766 was raised for. Undelivered intents are destroyed with the table, so
-- drain the backlog first if any of it still matters:
--
--   SELECT count(*), min(occurred_at) FROM audit_outbox WHERE delivered_at IS NULL;
--
-- Delivered intents are safe to lose: their audit_logs rows are the record.
DROP TRIGGER IF EXISTS platform_admins_require_audit_intent ON platform_admins;
DROP FUNCTION IF EXISTS platform_admins_require_audit_intent();
DROP FUNCTION IF EXISTS audit_outbox_assert_intent(UUID, VARCHAR, VARCHAR);
DROP TABLE IF EXISTS audit_outbox;

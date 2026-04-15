DROP INDEX IF EXISTS idx_audit_logs_created_at;

ALTER TABLE system_settings
  DROP COLUMN IF EXISTS audit_retention_days;

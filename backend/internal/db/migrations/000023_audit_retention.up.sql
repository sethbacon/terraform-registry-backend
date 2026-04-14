ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS audit_retention_days INTEGER NOT NULL DEFAULT 90;

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

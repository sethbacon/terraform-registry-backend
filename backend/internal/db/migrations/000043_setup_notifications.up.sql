-- 000043_setup_notifications.up.sql
-- Adds DB-persisted notification/SMTP configuration to system_settings, mirroring
-- the scanning_config columns added in 000021_setup_scanning. This lets the
-- notifications configuration be saved/reloaded at runtime instead of only via
-- YAML/env. The SMTP password inside notifications_config MUST be encrypted by
-- the caller before it is stored here.
ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS notifications_configured    BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS notifications_configured_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS notifications_config        JSONB;

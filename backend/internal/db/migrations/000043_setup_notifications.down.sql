ALTER TABLE system_settings
  DROP COLUMN IF EXISTS notifications_config,
  DROP COLUMN IF EXISTS notifications_configured_at,
  DROP COLUMN IF EXISTS notifications_configured;

ALTER TABLE system_settings
  DROP COLUMN IF EXISTS scanning_configured,
  DROP COLUMN IF EXISTS scanning_configured_at,
  DROP COLUMN IF EXISTS scanning_config;

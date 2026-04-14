ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS scanning_configured    BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS scanning_configured_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS scanning_config        JSONB;

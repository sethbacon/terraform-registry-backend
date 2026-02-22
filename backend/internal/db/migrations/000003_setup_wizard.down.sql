-- Reverse the setup wizard migration.

DROP TABLE IF EXISTS oidc_config;

ALTER TABLE system_settings
    DROP COLUMN IF EXISTS setup_completed,
    DROP COLUMN IF EXISTS setup_token_hash,
    DROP COLUMN IF EXISTS oidc_configured,
    DROP COLUMN IF EXISTS pending_admin_email;

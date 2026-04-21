-- 000027_setup_ldap.up.sql
-- Add LDAP configuration columns to system_settings for setup wizard support.
-- LDAP and OIDC are mutually exclusive; auth_method tracks which is active.

ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'oidc',
    ADD COLUMN IF NOT EXISTS ldap_configured BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ldap_configured_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ldap_config JSONB;

-- Existing registries that already completed setup used OIDC, so mark them.
UPDATE system_settings SET auth_method = 'oidc' WHERE oidc_configured = true;

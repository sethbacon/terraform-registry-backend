-- ============================================================================
-- SETUP WIZARD: One-time first-run setup flow
-- Adds setup token, OIDC configuration stored in DB, and setup state tracking
-- ============================================================================

-- Extend system_settings with setup wizard state columns.
-- For existing deployments: if storage is already configured, mark setup as
-- completed so the setup wizard does not appear on upgrade.
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS setup_completed     BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS setup_token_hash     TEXT,
    ADD COLUMN IF NOT EXISTS oidc_configured      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS pending_admin_email   TEXT;

-- Auto-complete setup for existing deployments that already have storage configured.
UPDATE system_settings
SET setup_completed = true
WHERE id = 1 AND storage_configured = true;

-- OIDC provider configuration stored in the database, encrypted at rest.
-- Follows the same pattern as storage_config: sensitive fields have _encrypted suffix,
-- encryption/decryption happens in the handler layer using the TokenCipher.
CREATE TABLE oidc_config (
    id                       UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     VARCHAR(255)  NOT NULL DEFAULT 'default',
    provider_type            VARCHAR(50)   NOT NULL DEFAULT 'generic_oidc',
    issuer_url               TEXT          NOT NULL,
    client_id                TEXT          NOT NULL,
    client_secret_encrypted  TEXT          NOT NULL,
    redirect_url             TEXT          NOT NULL,
    scopes                   JSONB         NOT NULL DEFAULT '["openid", "email", "profile"]'::jsonb,
    is_active                BOOLEAN       NOT NULL DEFAULT true,
    -- Extra configuration for provider-specific settings (Azure AD tenant, group mapping, etc.)
    extra_config             JSONB         DEFAULT '{}'::jsonb,
    -- Metadata
    created_at               TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMP     NOT NULL DEFAULT NOW(),
    created_by               UUID          REFERENCES users(id),
    updated_by               UUID          REFERENCES users(id),
    CONSTRAINT valid_provider_type CHECK (provider_type IN ('generic_oidc', 'azuread'))
);

COMMENT ON TABLE oidc_config IS 'OIDC provider configuration stored encrypted in the database. Supports runtime reconfiguration without server restart.';

-- Only one OIDC config can be active at a time.
CREATE UNIQUE INDEX idx_oidc_config_active ON oidc_config(is_active) WHERE is_active = true;

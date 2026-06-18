-- Migration 000041: Shared, admin-managed app credentials for SCM providers.
--
-- Today SCM auth is per-user OAuth (scm_oauth_tokens, one row per user+provider)
-- and a module's syncs depend on the *creator's* personal token. This migration
-- adds a provider-level, app-owned auth mode — a Microsoft Entra app registration
-- for Azure DevOps and a GitHub App for GitHub — so a single admin-configured
-- credential serves every user's linking and all background syncs.
--
-- Additive and backwards-compatible: every existing provider defaults to
-- auth_mode='oauth_user' and keeps working unchanged. An admin opts a provider
-- into app mode by supplying app credentials.

-- How a provider authenticates for shared, headless access.
ALTER TABLE scm_providers
    ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'oauth_user'
        CHECK (auth_mode IN ('oauth_user', 'entra_app', 'github_app'));

-- GitHub App fields (used when auth_mode = 'github_app'). Entra app mode reuses
-- the existing client_id + tenant_id + client_secret_encrypted columns and needs
-- no new columns.
ALTER TABLE scm_providers ADD COLUMN github_app_id             VARCHAR(255);
ALTER TABLE scm_providers ADD COLUMN github_installation_id    VARCHAR(255);
ALTER TABLE scm_providers ADD COLUMN encrypted_app_private_key TEXT; -- base64 AES-256-GCM

-- Shape guard: a github_app provider must carry all three GitHub App fields.
-- entra_app reuses client_id/tenant_id (already present) and is validated at the
-- API layer; oauth_user imposes no extra requirement.
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_app_shape CHECK (
        auth_mode <> 'github_app'
        OR (github_app_id IS NOT NULL
            AND github_installation_id IS NOT NULL
            AND encrypted_app_private_key IS NOT NULL)
    );

-- Cached shared token so process restarts don't immediately re-mint. The token
-- is re-mintable from the stored app secrets, so losing this cache is non-fatal.
CREATE TABLE scm_provider_tokens (
    scm_provider_id        UUID         PRIMARY KEY REFERENCES scm_providers(id) ON DELETE CASCADE,
    access_token_encrypted TEXT         NOT NULL,
    token_type             VARCHAR(50)  NOT NULL DEFAULT 'Bearer',
    expires_at             TIMESTAMP,
    updated_at             TIMESTAMP    NOT NULL DEFAULT NOW()
);

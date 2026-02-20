-- ============================================================================
-- Consolidated initial schema – represents the full current database state.
--
-- This single migration replaces all prior incremental migrations (001–028).
-- Fresh deployments apply this one file. Existing deployments that already
-- have all previous migrations applied should reset schema_migrations:
--
--   TRUNCATE schema_migrations;
--   INSERT INTO schema_migrations (version, dirty) VALUES (1, false);
--
-- gen_random_uuid() is used throughout (built-in since PostgreSQL 13).
-- No external extensions required.
-- ============================================================================

-- ============================================================================
-- CORE: Organizations, Users, Role Templates
-- ============================================================================

CREATE TABLE organizations (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) UNIQUE NOT NULL,
    name       VARCHAR(255) NOT NULL,
    oidc_sub   VARCHAR(255) UNIQUE,
    created_at TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email    ON users(email);
CREATE INDEX idx_users_oidc_sub ON users(oidc_sub);

-- Role templates: predefined scope bundles for common use cases.
-- System templates (is_system = true) cannot be deleted through the UI.
CREATE TABLE role_templates (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description  TEXT,
    scopes       JSONB        NOT NULL DEFAULT '[]',
    is_system    BOOLEAN      DEFAULT false,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_role_templates_name ON role_templates(name);

-- ============================================================================
-- AUTH: API Keys, Organization Membership
-- ============================================================================

CREATE TABLE api_keys (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         REFERENCES users(id) ON DELETE CASCADE,
    organization_id  UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    key_hash         VARCHAR(255) UNIQUE NOT NULL,
    key_prefix       VARCHAR(10)  NOT NULL,
    scopes           JSONB        NOT NULL DEFAULT '[]'::jsonb,
    description      TEXT,
    role_template_id UUID         REFERENCES role_templates(id) ON DELETE SET NULL,
    expires_at       TIMESTAMP,
    last_used_at     TIMESTAMP,
    created_at       TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_key_hash        ON api_keys(key_hash);
CREATE INDEX idx_api_keys_user_id         ON api_keys(user_id);
CREATE INDEX idx_api_keys_organization_id ON api_keys(organization_id);
CREATE INDEX idx_api_keys_role_template   ON api_keys(role_template_id);

-- Organization membership.
-- NOTE: The legacy `role VARCHAR` column (from the original schema) was
-- replaced by role_template_id in migration 022 and is not present here.
CREATE TABLE organization_members (
    organization_id  UUID      REFERENCES organizations(id) ON DELETE CASCADE,
    user_id          UUID      REFERENCES users(id) ON DELETE CASCADE,
    role_template_id UUID      REFERENCES role_templates(id) ON DELETE SET NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX idx_organization_members_user_id  ON organization_members(user_id);
CREATE INDEX idx_org_members_role_template     ON organization_members(role_template_id);

-- ============================================================================
-- REGISTRY: Modules and Providers (core resource tables)
-- ============================================================================

CREATE TABLE modules (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    namespace       VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    system          VARCHAR(255) NOT NULL,
    description     TEXT,
    source          VARCHAR(255),
    created_by      UUID         REFERENCES users(id),
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, namespace, name, system)
);

CREATE INDEX idx_modules_org        ON modules(organization_id);
CREATE INDEX idx_modules_namespace  ON modules(namespace, name, system);
CREATE INDEX idx_modules_created_by ON modules(created_by);

CREATE TABLE providers (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    namespace       VARCHAR(255) NOT NULL,
    type            VARCHAR(255) NOT NULL,
    description     TEXT,
    source          VARCHAR(255),
    created_by      UUID         REFERENCES users(id),
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, namespace, type)
);

CREATE INDEX idx_providers_org        ON providers(organization_id);
CREATE INDEX idx_providers_namespace  ON providers(namespace, type);
CREATE INDEX idx_providers_created_by ON providers(created_by);

-- ============================================================================
-- SCM: Source Control Management Integration
-- ============================================================================

CREATE TABLE scm_providers (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    provider_type           VARCHAR(50)  NOT NULL
                              CHECK (provider_type IN ('github', 'azuredevops', 'gitlab', 'bitbucket_dc')),
    name                    VARCHAR(255) NOT NULL,
    base_url                VARCHAR(512),
    client_id               VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT         NOT NULL,
    webhook_secret          VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255),
    is_active               BOOLEAN      DEFAULT true,
    created_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, provider_type, name)
);

CREATE INDEX idx_scm_providers_org  ON scm_providers(organization_id);
CREATE INDEX idx_scm_providers_type ON scm_providers(provider_type);

-- User OAuth tokens – one per user per SCM provider.
CREATE TABLE scm_oauth_tokens (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID         REFERENCES users(id) ON DELETE CASCADE,
    scm_provider_id         UUID         REFERENCES scm_providers(id) ON DELETE CASCADE,
    access_token_encrypted  TEXT         NOT NULL,
    refresh_token_encrypted TEXT,
    token_type              VARCHAR(50)  NOT NULL DEFAULT 'Bearer',
    expires_at              TIMESTAMP,
    scopes                  TEXT,
    created_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, scm_provider_id)
);

CREATE INDEX idx_scm_oauth_tokens_user     ON scm_oauth_tokens(user_id);
CREATE INDEX idx_scm_oauth_tokens_provider ON scm_oauth_tokens(scm_provider_id);

-- Links a module to a specific SCM repository (one module : one repo).
-- Created before module_versions because module_versions has an FK here.
CREATE TABLE module_scm_repos (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id        UUID         REFERENCES modules(id) ON DELETE CASCADE,
    scm_provider_id  UUID         REFERENCES scm_providers(id) ON DELETE CASCADE,
    repository_owner VARCHAR(255) NOT NULL,
    repository_name  VARCHAR(255) NOT NULL,
    repository_url   VARCHAR(512),
    default_branch   VARCHAR(255) DEFAULT 'main',
    module_path      VARCHAR(512) DEFAULT '/',
    tag_pattern      VARCHAR(255) DEFAULT 'v*',
    auto_publish     BOOLEAN      DEFAULT true,
    webhook_id       VARCHAR(255),
    webhook_url      VARCHAR(512),
    webhook_enabled  BOOLEAN      DEFAULT false,
    last_sync_at     TIMESTAMP,
    last_sync_commit VARCHAR(40),
    created_at       TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (module_id)
);

CREATE INDEX idx_module_scm_repos_module   ON module_scm_repos(module_id);
CREATE INDEX idx_module_scm_repos_provider ON module_scm_repos(scm_provider_id);

-- ============================================================================
-- REGISTRY: Module and Provider Versions
-- ============================================================================

CREATE TABLE module_versions (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id           UUID          REFERENCES modules(id) ON DELETE CASCADE,
    version             VARCHAR(50)   NOT NULL,
    storage_path        VARCHAR(1024) NOT NULL,
    storage_backend     VARCHAR(50)   NOT NULL,
    size_bytes          BIGINT        NOT NULL,
    checksum            VARCHAR(64)   NOT NULL,
    published_by        UUID          REFERENCES users(id),
    download_count      BIGINT        DEFAULT 0,
    readme              TEXT,
    commit_sha          VARCHAR(40),
    scm_source          VARCHAR(512),
    tag_name            VARCHAR(255),
    scm_repo_id         UUID          REFERENCES module_scm_repos(id),
    deprecated          BOOLEAN       NOT NULL DEFAULT FALSE,
    deprecated_at       TIMESTAMP,
    deprecation_message TEXT,
    created_at          TIMESTAMP     NOT NULL DEFAULT NOW(),
    UNIQUE (module_id, version)
);

COMMENT ON COLUMN module_versions.readme IS 'README content extracted from module tarball';

CREATE INDEX idx_module_versions_module     ON module_versions(module_id);
CREATE INDEX idx_module_versions_version    ON module_versions(version);
CREATE INDEX idx_module_versions_commit_sha ON module_versions(commit_sha);
CREATE INDEX idx_module_versions_tag_name   ON module_versions(tag_name);
CREATE INDEX idx_module_versions_scm_repo   ON module_versions(scm_repo_id);
CREATE INDEX idx_module_versions_deprecated ON module_versions(deprecated);

CREATE TABLE provider_versions (
    id                    UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id           UUID          REFERENCES providers(id) ON DELETE CASCADE,
    version               VARCHAR(50)   NOT NULL,
    protocols             JSONB         NOT NULL DEFAULT '[]'::jsonb,
    gpg_public_key        TEXT          NOT NULL,
    shasums_url           VARCHAR(1024) NOT NULL,
    shasums_signature_url VARCHAR(1024) NOT NULL,
    published_by          UUID          REFERENCES users(id),
    deprecated            BOOLEAN       NOT NULL DEFAULT FALSE,
    deprecated_at         TIMESTAMP,
    deprecation_message   TEXT,
    created_at            TIMESTAMP     NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, version)
);

CREATE INDEX idx_provider_versions_provider   ON provider_versions(provider_id);
CREATE INDEX idx_provider_versions_version    ON provider_versions(version);
CREATE INDEX idx_provider_versions_deprecated ON provider_versions(deprecated);

CREATE TABLE provider_platforms (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_version_id UUID          REFERENCES provider_versions(id) ON DELETE CASCADE,
    os                  VARCHAR(50)   NOT NULL,
    arch                VARCHAR(50)   NOT NULL,
    filename            VARCHAR(255)  NOT NULL,
    storage_path        VARCHAR(1024) NOT NULL,
    storage_backend     VARCHAR(50)   NOT NULL,
    size_bytes          BIGINT        NOT NULL,
    shasum              VARCHAR(64)   NOT NULL,
    download_count      BIGINT        DEFAULT 0,
    UNIQUE (provider_version_id, os, arch)
);

CREATE INDEX idx_provider_platforms_version ON provider_platforms(provider_version_id);
CREATE INDEX idx_provider_platforms_os_arch ON provider_platforms(os, arch);

-- ============================================================================
-- SCM: Webhook Events and Immutability Violation Tracking
-- ============================================================================

CREATE TABLE scm_webhook_events (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_scm_repo_id    UUID        REFERENCES module_scm_repos(id) ON DELETE CASCADE,
    event_id              VARCHAR(255),
    event_type            VARCHAR(50) NOT NULL,
    ref                   VARCHAR(255),
    commit_sha            VARCHAR(40),
    tag_name              VARCHAR(255),
    payload               JSONB       NOT NULL,
    headers               JSONB,
    signature             VARCHAR(255),
    signature_valid       BOOLEAN,
    processed             BOOLEAN     DEFAULT false,
    processing_started_at TIMESTAMP,
    processed_at          TIMESTAMP,
    result_version_id     UUID        REFERENCES module_versions(id),
    error                 TEXT,
    created_at            TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scm_webhook_events_repo      ON scm_webhook_events(module_scm_repo_id);
CREATE INDEX idx_scm_webhook_events_processed ON scm_webhook_events(processed);
CREATE INDEX idx_scm_webhook_events_created   ON scm_webhook_events(created_at DESC);
CREATE INDEX idx_scm_webhook_events_event_id  ON scm_webhook_events(event_id);

-- Tracks tag movements that violate version immutability guarantees.
CREATE TABLE version_immutability_violations (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    module_version_id   UUID         REFERENCES module_versions(id) ON DELETE CASCADE,
    tag_name            VARCHAR(255) NOT NULL,
    original_commit_sha VARCHAR(40)  NOT NULL,
    detected_commit_sha VARCHAR(40)  NOT NULL,
    detected_at         TIMESTAMP    NOT NULL DEFAULT NOW(),
    alert_sent          BOOLEAN      DEFAULT false,
    alert_sent_at       TIMESTAMP,
    resolved            BOOLEAN      DEFAULT false,
    resolved_at         TIMESTAMP,
    resolved_by         UUID         REFERENCES users(id),
    notes               TEXT
);

CREATE INDEX idx_immutability_violations_version    ON version_immutability_violations(module_version_id);
CREATE INDEX idx_immutability_violations_unresolved ON version_immutability_violations(resolved)
    WHERE resolved = false;

-- ============================================================================
-- ANALYTICS: Download Events and Audit Logs
-- ============================================================================

CREATE TABLE download_events (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type VARCHAR(50) NOT NULL,
    resource_id   UUID        NOT NULL,
    version_id    UUID        NOT NULL,
    user_id       UUID        REFERENCES users(id),
    ip_address    INET,
    user_agent    TEXT,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_download_events_resource ON download_events(resource_type, resource_id);
CREATE INDEX idx_download_events_created  ON download_events(created_at);

CREATE TABLE audit_logs (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         REFERENCES users(id),
    organization_id UUID         REFERENCES organizations(id),
    action          VARCHAR(255) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     UUID,
    metadata        JSONB,
    ip_address      INET,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user         ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_organization ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_created      ON audit_logs(created_at);

-- ============================================================================
-- MIRRORING: Mirror Configurations and Sync Tracking
-- ============================================================================

CREATE TABLE mirror_configurations (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  VARCHAR(255) NOT NULL UNIQUE,
    description           TEXT,
    upstream_registry_url VARCHAR(512) NOT NULL,
    namespace_filter      TEXT,
    provider_filter       TEXT,
    version_filter        TEXT,
    platform_filter       TEXT,
    organization_id       UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    enabled               BOOLEAN      NOT NULL DEFAULT true,
    sync_interval_hours   INTEGER      NOT NULL DEFAULT 24,
    last_sync_at          TIMESTAMPTZ,
    last_sync_status      VARCHAR(50),
    last_sync_error       TEXT,
    requires_approval     BOOLEAN      DEFAULT false,
    approval_status       VARCHAR(50)  DEFAULT 'not_required'
                            CHECK (approval_status IN ('not_required', 'pending', 'approved', 'rejected')),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by            UUID         REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT valid_sync_interval CHECK (sync_interval_hours > 0),
    CONSTRAINT valid_registry_url  CHECK (upstream_registry_url LIKE 'http%')
);

COMMENT ON TABLE mirror_configurations IS 'Configuration for provider mirroring from upstream registries';

CREATE INDEX idx_mirror_enabled_last_sync ON mirror_configurations(enabled, last_sync_at)
    WHERE enabled = true;
CREATE INDEX idx_mirror_upstream_registry ON mirror_configurations(upstream_registry_url);
CREATE INDEX idx_mirror_organization      ON mirror_configurations(organization_id);

CREATE TABLE mirror_sync_history (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    mirror_config_id UUID        NOT NULL REFERENCES mirror_configurations(id) ON DELETE CASCADE,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    status           VARCHAR(50) NOT NULL,
    providers_synced INTEGER     DEFAULT 0,
    providers_failed INTEGER     DEFAULT 0,
    error_message    TEXT,
    sync_details     JSONB,
    CONSTRAINT valid_status CHECK (status IN ('running', 'success', 'failed', 'cancelled'))
);

COMMENT ON TABLE mirror_sync_history IS 'Historical record of mirror synchronization operations';

CREATE INDEX idx_sync_history_mirror_config ON mirror_sync_history(mirror_config_id, started_at DESC);
CREATE INDEX idx_sync_history_status        ON mirror_sync_history(status, started_at)
    WHERE status = 'running';

-- Tracks which providers were mirrored from which mirror configuration.
CREATE TABLE mirrored_providers (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    mirror_config_id   UUID         NOT NULL REFERENCES mirror_configurations(id) ON DELETE CASCADE,
    provider_id        UUID         NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    upstream_namespace VARCHAR(255) NOT NULL,
    upstream_type      VARCHAR(255) NOT NULL,
    last_synced_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_sync_version  VARCHAR(50),
    sync_enabled       BOOLEAN      NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id),
    CONSTRAINT unique_mirror_provider UNIQUE (mirror_config_id, upstream_namespace, upstream_type)
);

COMMENT ON TABLE mirrored_providers IS 'Tracks which providers were mirrored from which mirror configuration';

CREATE INDEX idx_mirrored_providers_mirror   ON mirrored_providers(mirror_config_id);
CREATE INDEX idx_mirrored_providers_provider ON mirrored_providers(provider_id);

-- Tracks individual version sync status for mirrored providers.
CREATE TABLE mirrored_provider_versions (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    mirrored_provider_id UUID        NOT NULL REFERENCES mirrored_providers(id) ON DELETE CASCADE,
    provider_version_id  UUID        NOT NULL REFERENCES provider_versions(id) ON DELETE CASCADE,
    upstream_version     VARCHAR(50) NOT NULL,
    synced_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shasum_verified      BOOLEAN     DEFAULT false,
    gpg_verified         BOOLEAN     DEFAULT false,
    UNIQUE (mirrored_provider_id, upstream_version)
);

COMMENT ON TABLE mirrored_provider_versions IS 'Tracks individual version sync status for mirrored providers';

CREATE INDEX idx_mirrored_versions_provider ON mirrored_provider_versions(mirrored_provider_id);

-- ============================================================================
-- RBAC: Mirror Approval Workflows and Mirror Policies
-- ============================================================================

CREATE TABLE mirror_approval_requests (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    mirror_config_id   UUID         REFERENCES mirror_configurations(id) ON DELETE CASCADE,
    organization_id    UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    requested_by       UUID         REFERENCES users(id) ON DELETE SET NULL,
    provider_namespace VARCHAR(255) NOT NULL,
    provider_name      VARCHAR(255),
    reason             TEXT,
    status             VARCHAR(50)  NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by        UUID         REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at        TIMESTAMP,
    review_notes       TEXT,
    auto_approved      BOOLEAN      DEFAULT false,
    expires_at         TIMESTAMP,
    created_at         TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mirror_approval_requests_status   ON mirror_approval_requests(status);
CREATE INDEX idx_mirror_approval_requests_org      ON mirror_approval_requests(organization_id);
CREATE INDEX idx_mirror_approval_requests_mirror   ON mirror_approval_requests(mirror_config_id);
CREATE INDEX idx_mirror_approval_requests_provider ON mirror_approval_requests(provider_namespace, provider_name);

-- Define allowed/denied upstream registries and namespaces.
-- NULL organization_id = global default policy (applies to all orgs).
CREATE TABLE mirror_policies (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID         REFERENCES organizations(id) ON DELETE CASCADE,
    name              VARCHAR(255) NOT NULL,
    description       TEXT,
    policy_type       VARCHAR(10)  NOT NULL CHECK (policy_type IN ('allow', 'deny')),
    upstream_registry VARCHAR(512),
    namespace_pattern VARCHAR(255),
    provider_pattern  VARCHAR(255),
    priority          INT          DEFAULT 0,
    is_active         BOOLEAN      DEFAULT true,
    requires_approval BOOLEAN      DEFAULT false,
    created_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
    created_by        UUID         REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (organization_id, name)
);

CREATE INDEX idx_mirror_policies_org      ON mirror_policies(organization_id);
CREATE INDEX idx_mirror_policies_type     ON mirror_policies(policy_type);
CREATE INDEX idx_mirror_policies_active   ON mirror_policies(is_active) WHERE is_active = true;
CREATE INDEX idx_mirror_policies_priority ON mirror_policies(priority DESC);

-- ============================================================================
-- STORAGE: Configuration and System Settings
-- ============================================================================

-- Singleton table for global system state (first-run detection, etc.).
CREATE TABLE system_settings (
    id                    INTEGER   PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    storage_configured    BOOLEAN   NOT NULL DEFAULT false,
    storage_configured_at TIMESTAMP,
    storage_configured_by UUID      REFERENCES users(id),
    created_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE system_settings IS 'Global system settings (singleton). Controls first-run setup state.';

-- Storage backend configuration. Sensitive fields are encrypted at rest.
CREATE TABLE storage_config (
    id                             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    backend_type                   VARCHAR(20)   NOT NULL,
    is_active                      BOOLEAN       NOT NULL DEFAULT true,
    -- Local filesystem
    local_base_path                VARCHAR(1024),
    local_serve_directly           BOOLEAN       DEFAULT true,
    -- Azure Blob Storage
    azure_account_name             VARCHAR(255),
    azure_account_key_encrypted    TEXT,
    azure_container_name           VARCHAR(255),
    azure_cdn_url                  VARCHAR(1024),
    -- Amazon S3 / S3-compatible
    s3_endpoint                    VARCHAR(1024),
    s3_region                      VARCHAR(100),
    s3_bucket                      VARCHAR(255),
    s3_auth_method                 VARCHAR(50),
    s3_access_key_id_encrypted     TEXT,
    s3_secret_access_key_encrypted TEXT,
    s3_role_arn                    VARCHAR(255),
    s3_role_session_name           VARCHAR(100),
    s3_external_id                 VARCHAR(255),
    s3_web_identity_token_file     VARCHAR(1024),
    -- Google Cloud Storage
    gcs_bucket                     VARCHAR(255),
    gcs_project_id                 VARCHAR(255),
    gcs_auth_method                VARCHAR(50),
    gcs_credentials_file           VARCHAR(1024),
    gcs_credentials_json_encrypted TEXT,
    gcs_endpoint                   VARCHAR(1024),
    -- Metadata
    created_at                     TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at                     TIMESTAMP     NOT NULL DEFAULT NOW(),
    created_by                     UUID          REFERENCES users(id),
    updated_by                     UUID          REFERENCES users(id),
    CONSTRAINT valid_backend_type CHECK (backend_type IN ('local', 'azure', 's3', 'gcs'))
);

COMMENT ON TABLE storage_config IS 'Stores storage backend configuration. Sensitive fields are encrypted.';

CREATE INDEX idx_storage_config_active ON storage_config(is_active) WHERE is_active = true;

-- ============================================================================
-- DEFAULT SEED DATA
-- System-level data only. No user accounts or environment-specific records.
-- ============================================================================

-- Default organization for single-tenant deployments.
INSERT INTO organizations (name, display_name)
VALUES ('default', 'Default Organization');

-- System role templates (final scope set as of schema consolidation).
INSERT INTO role_templates (name, display_name, description, scopes, is_system) VALUES
('viewer',
 'Viewer',
 'Read-only access to modules, providers, mirrors, organizations, and SCM configurations',
 '["modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read"]'::jsonb,
 true),
('publisher',
 'Publisher',
 'Can upload and manage modules and providers',
 '["modules:read", "modules:write", "providers:read", "providers:write", "organizations:read", "scm:read"]'::jsonb,
 true),
('devops',
 'DevOps',
 'Can manage SCM integrations and provider mirroring for CI/CD pipelines',
 '["modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "organizations:read", "scm:read", "scm:manage"]'::jsonb,
 true),
('admin',
 'Administrator',
 'Full access to all registry features',
 '["admin"]'::jsonb,
 true),
('user_manager',
 'User Manager',
 'Can manage user accounts and memberships',
 '["users:read", "users:write", "organizations:read", "organizations:write", "api_keys:manage", "modules:read", "providers:read"]'::jsonb,
 true),
('auditor',
 'Auditor',
 'Read-only access with audit log visibility for security and compliance review',
 '["modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read", "audit:read"]'::jsonb,
 true);

-- Global mirror policies (NULL organization_id = applies when no org-specific policy matches).
INSERT INTO mirror_policies
    (organization_id, name, description, policy_type, upstream_registry,
     namespace_pattern, provider_pattern, priority, is_active, requires_approval)
VALUES
(NULL,
 'default-allow-hashicorp',
 'Allow mirroring HashiCorp official providers without approval',
 'allow', 'https://registry.terraform.io',
 'hashicorp', '*', 100, true, false),
(NULL,
 'default-require-approval-other',
 'Require approval for non-HashiCorp providers from the public registry',
 'allow', 'https://registry.terraform.io',
 '*', '*', 0, true, true);

-- Initialize the system settings singleton.
INSERT INTO system_settings (id, storage_configured) VALUES (1, false);

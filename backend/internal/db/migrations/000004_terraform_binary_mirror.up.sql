-- ============================================================================
-- TERRAFORM BINARY MIRROR (multi-config)
-- Tables for mirroring official Terraform/OpenTofu release binaries from
-- a configurable upstream (default: releases.hashicorp.com) for supply-chain
-- security and air-gapped deployment scenarios.
--
-- Multiple mirror configs can coexist so that, for example, HashiCorp Terraform
-- and OpenTofu can each have their own independent mirror.
-- ============================================================================

-- Named configurations for Terraform binary mirrors.
-- Multiple rows are supported (one per upstream tool/endpoint).
CREATE TABLE terraform_mirror_configs (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255)  NOT NULL,
    description         TEXT          DEFAULT NULL,
    -- tool distinguishes the release source: terraform | opentofu | custom
    tool                VARCHAR(50)   NOT NULL DEFAULT 'terraform',
    enabled             BOOLEAN       NOT NULL DEFAULT false,
    upstream_url        TEXT          NOT NULL DEFAULT 'https://releases.hashicorp.com',
    -- JSON array of "os/arch" strings, e.g. ["linux/amd64","darwin/arm64"].
    -- NULL means all platforms.
    platform_filter     JSONB         DEFAULT NULL,
    gpg_verify          BOOLEAN       NOT NULL DEFAULT true,
    sync_interval_hours INTEGER       NOT NULL DEFAULT 24,
    last_sync_at        TIMESTAMP     DEFAULT NULL,
    last_sync_status    VARCHAR(20)   DEFAULT NULL,  -- success | failed | in_progress
    last_sync_error     TEXT          DEFAULT NULL,
    created_at          TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP     NOT NULL DEFAULT NOW(),
    CONSTRAINT terraform_mirror_configs_name_unique UNIQUE (name),
    CONSTRAINT terraform_mirror_configs_tool_check CHECK (
        tool IN ('terraform', 'opentofu', 'custom')
    )
);

COMMENT ON TABLE terraform_mirror_configs IS 'Named configurations for Terraform binary mirrors. Supports multiple configs (e.g. one for HashiCorp Terraform and one for OpenTofu).';

-- Terraform versions discovered / mirrored from the upstream.
CREATE TABLE terraform_versions (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id       UUID          NOT NULL REFERENCES terraform_mirror_configs(id) ON DELETE CASCADE,
    version         VARCHAR(50)   NOT NULL,
    is_latest       BOOLEAN       NOT NULL DEFAULT false,
    is_deprecated   BOOLEAN       NOT NULL DEFAULT false,
    -- Upstream release metadata (populated during sync)
    release_date    TIMESTAMP     DEFAULT NULL,
    -- Overall sync state for this version
    sync_status     VARCHAR(20)   NOT NULL DEFAULT 'pending',  -- pending | syncing | synced | failed | partial
    sync_error      TEXT          DEFAULT NULL,
    synced_at       TIMESTAMP     DEFAULT NULL,
    created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    CONSTRAINT terraform_versions_unique UNIQUE (config_id, version),
    CONSTRAINT terraform_versions_sync_status_check CHECK (
        sync_status IN ('pending', 'syncing', 'synced', 'failed', 'partial')
    )
);

COMMENT ON TABLE terraform_versions IS 'Catalog of Terraform/OpenTofu versions scoped to a mirror config.';

-- At most one version per config can be marked latest.
CREATE UNIQUE INDEX idx_terraform_versions_latest
    ON terraform_versions (config_id)
    WHERE is_latest = true;

CREATE INDEX idx_terraform_versions_sync_status ON terraform_versions (config_id, sync_status);

-- Individual binary packages: one row per (version, os, arch) combination.
CREATE TABLE terraform_version_platforms (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id      UUID          NOT NULL REFERENCES terraform_versions(id) ON DELETE CASCADE,
    os              VARCHAR(50)   NOT NULL,   -- linux | darwin | windows | freebsd
    arch            VARCHAR(50)   NOT NULL,   -- amd64 | arm64 | 386 | arm
    -- Upstream download information
    upstream_url    TEXT          NOT NULL,
    filename        TEXT          NOT NULL,   -- e.g. terraform_1.7.0_linux_amd64.zip
    sha256          VARCHAR(64)   NOT NULL,
    -- Storage information (populated after successful download)
    storage_key     TEXT          DEFAULT NULL,   -- path inside storage backend
    storage_backend VARCHAR(50)   DEFAULT NULL,   -- local | s3 | azure | gcs
    -- Verification results
    sha256_verified BOOLEAN       NOT NULL DEFAULT false,
    gpg_verified    BOOLEAN       NOT NULL DEFAULT false,
    -- Sync state for this individual platform
    sync_status     VARCHAR(20)   NOT NULL DEFAULT 'pending',  -- pending | syncing | synced | failed
    sync_error      TEXT          DEFAULT NULL,
    synced_at       TIMESTAMP     DEFAULT NULL,
    created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    CONSTRAINT terraform_version_platforms_unique UNIQUE (version_id, os, arch),
    CONSTRAINT terraform_version_platforms_sync_status_check CHECK (
        sync_status IN ('pending', 'syncing', 'synced', 'failed')
    )
);

COMMENT ON TABLE terraform_version_platforms IS 'Individual Terraform/OpenTofu binary packages keyed by version + os + arch. Tracks download, verification, and storage state.';

CREATE INDEX idx_terraform_version_platforms_version_id ON terraform_version_platforms (version_id);
CREATE INDEX idx_terraform_version_platforms_sync_status ON terraform_version_platforms (sync_status);
CREATE INDEX idx_terraform_version_platforms_os_arch ON terraform_version_platforms (os, arch);

-- Audit log for every sync run (manual or scheduled), scoped to a mirror config.
CREATE TABLE terraform_sync_history (
    id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id         UUID          NOT NULL REFERENCES terraform_mirror_configs(id) ON DELETE CASCADE,
    triggered_by      VARCHAR(20)   NOT NULL DEFAULT 'scheduler',  -- scheduler | manual
    started_at        TIMESTAMP     NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMP     DEFAULT NULL,
    status            VARCHAR(20)   NOT NULL DEFAULT 'running',  -- running | success | failed | cancelled
    versions_synced   INTEGER       NOT NULL DEFAULT 0,
    platforms_synced  INTEGER       NOT NULL DEFAULT 0,
    versions_failed   INTEGER       NOT NULL DEFAULT 0,
    error_message     TEXT          DEFAULT NULL,
    -- JSONB detail payload (per-version results, etc.)
    sync_details      JSONB         DEFAULT NULL,
    CONSTRAINT terraform_sync_history_status_check CHECK (
        status IN ('running', 'success', 'failed', 'cancelled')
    )
);

COMMENT ON TABLE terraform_sync_history IS 'Audit trail of every Terraform binary mirror sync operation (scheduled or manually triggered), scoped to a mirror config.';

CREATE INDEX idx_terraform_sync_history_config_started ON terraform_sync_history (config_id, started_at DESC);
CREATE INDEX idx_terraform_sync_history_status ON terraform_sync_history (status);

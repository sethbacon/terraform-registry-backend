-- 000032_cve_advisories.up.sql
-- Creates the tables used by the CVE polling subsystem.
--
-- cve_advisories   – one row per unique advisory (deduped by source + source_id).
-- cve_affected_targets – one row per (advisory × affected artifact) with a
--   target_kind discriminator and a jsonb target_ref that holds kind-specific
--   identifiers.

CREATE TABLE IF NOT EXISTS cve_advisories (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source        TEXT NOT NULL,                 -- "osv"
    source_id     TEXT NOT NULL,                 -- e.g. "GHSA-xxxx-yyyy-zzzz" or "CVE-2025-12345"
    severity      TEXT NOT NULL DEFAULT 'unknown', -- critical|high|medium|low|unknown
    summary       TEXT NOT NULL DEFAULT '',
    details       TEXT NOT NULL DEFAULT '',
    references    JSONB NOT NULL DEFAULT '[]',   -- array of URL strings
    published_at  TIMESTAMPTZ,
    modified_at   TIMESTAMPTZ,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    withdrawn_at  TIMESTAMPTZ,                   -- non-null once OSV marks it withdrawn
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cve_advisories_source UNIQUE (source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_advisories_source_id ON cve_advisories (source_id);
CREATE INDEX IF NOT EXISTS idx_cve_advisories_severity  ON cve_advisories (severity);

-- -----------------------------------------------------------------------------
-- cve_affected_targets
-- A single advisory can affect many artifacts across all three target kinds.
-- The fingerprint column is a stable, deterministic string that uniquely
-- identifies the (advisory × artifact) pair within a target_kind, allowing
-- safe upserts via ON CONFLICT.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_affected_targets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id   UUID NOT NULL REFERENCES cve_advisories(id) ON DELETE CASCADE,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('binary', 'provider', 'scanner')),
    -- Fingerprint: deterministic string derived from target_ref so ON CONFLICT works
    -- without storing the full JSONB in a unique index.
    fingerprint   TEXT NOT NULL,
    target_ref    JSONB NOT NULL,               -- kind-specific; see below
    -- Resolved FK columns (nullable — scanner targets have no FK)
    terraform_version_id  UUID REFERENCES terraform_versions(id) ON DELETE SET NULL,
    provider_version_id   UUID REFERENCES provider_versions(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cve_affected_targets UNIQUE (advisory_id, target_kind, fingerprint)
);

-- target_ref shapes (informational, enforced by application):
--   binary:   {"mirror_config_id":"<uuid>","terraform_version_id":"<uuid>","tool":"terraform","version":"1.9.0"}
--   provider: {"provider_id":"<uuid>","provider_version_id":"<uuid>","namespace":"hashicorp","type":"aws","version":"5.0.0"}
--   scanner:  {"tool":"trivy","version":"0.50.0"}

CREATE INDEX IF NOT EXISTS idx_cve_affected_targets_advisory  ON cve_affected_targets (advisory_id);
CREATE INDEX IF NOT EXISTS idx_cve_affected_targets_kind      ON cve_affected_targets (target_kind);
CREATE INDEX IF NOT EXISTS idx_cve_affected_targets_tfver     ON cve_affected_targets (terraform_version_id) WHERE terraform_version_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cve_affected_targets_provver   ON cve_affected_targets (provider_version_id) WHERE provider_version_id IS NOT NULL;

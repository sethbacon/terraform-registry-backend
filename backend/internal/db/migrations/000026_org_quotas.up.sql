-- Per-organization quota management
-- Tracks storage limits, publish rate limits, and download rate limits per org.

CREATE TABLE IF NOT EXISTS org_quotas (
    id                    BIGSERIAL PRIMARY KEY,
    organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    storage_bytes_limit   BIGINT NOT NULL DEFAULT 0,        -- 0 = unlimited
    publishes_per_day     INT NOT NULL DEFAULT 0,            -- 0 = unlimited
    downloads_per_day     INT NOT NULL DEFAULT 0,            -- 0 = unlimited
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id)
);

-- Track daily usage for quota enforcement
CREATE TABLE IF NOT EXISTS org_quota_usage (
    id                    BIGSERIAL PRIMARY KEY,
    organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    date                  DATE NOT NULL DEFAULT CURRENT_DATE,
    storage_bytes_used    BIGINT NOT NULL DEFAULT 0,
    publishes_today       INT NOT NULL DEFAULT 0,
    downloads_today       INT NOT NULL DEFAULT 0,
    UNIQUE(organization_id, date)
);

CREATE INDEX IF NOT EXISTS idx_org_quotas_org_id ON org_quotas(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_quota_usage_org_date ON org_quota_usage(organization_id, date);

-- Scanner binary versions discovered by the scheduled update-check job. Participates
-- in the version-approval workflow (type="scanner"): pending rows are gated until an
-- admin approves, then a reconciler activates the binary. approval_status semantics
-- match provider/terraform mirror versions.
CREATE TABLE IF NOT EXISTS scanner_binary_versions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool               VARCHAR(50)  NOT NULL,
    version            VARCHAR(100) NOT NULL,
    source_url         TEXT,
    sha256             VARCHAR(128),
    signature_verified BOOLEAN      NOT NULL DEFAULT false,
    signature_type     VARCHAR(20)  NOT NULL DEFAULT 'none',
    sync_status        VARCHAR(20)  NOT NULL DEFAULT 'downloaded',
    approval_status    VARCHAR(20)  DEFAULT NULL
        CHECK (approval_status IN ('pending_approval','approved','rejected')),
    is_active          BOOLEAN      NOT NULL DEFAULT false,
    binary_path        TEXT,
    discovered_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tool, version)
);
CREATE INDEX IF NOT EXISTS idx_sbv_approval_status ON scanner_binary_versions (approval_status) WHERE approval_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sbv_active ON scanner_binary_versions (tool) WHERE is_active;

-- Extend the approval-events audit table with the scanner FK and widen the
-- exactly-one-target constraint to three targets.
ALTER TABLE version_approval_events
    ADD COLUMN IF NOT EXISTS scanner_binary_version_id UUID REFERENCES scanner_binary_versions(id) ON DELETE CASCADE;
ALTER TABLE version_approval_events DROP CONSTRAINT IF EXISTS exactly_one_target;
ALTER TABLE version_approval_events ADD  CONSTRAINT exactly_one_target CHECK (
    (mirrored_provider_version_id IS NOT NULL)::int +
    (terraform_version_id         IS NOT NULL)::int +
    (scanner_binary_version_id    IS NOT NULL)::int = 1
);
CREATE INDEX IF NOT EXISTS idx_vae_sbv ON version_approval_events (scanner_binary_version_id) WHERE scanner_binary_version_id IS NOT NULL;

-- Version Approval for Mirrors
--
-- Adds a version-level approval gate to provider mirrors and terraform binary
-- mirrors. When a mirror config has requires_approval = true, newly synced
-- versions enter 'pending_approval' state and are hidden from Terraform clients
-- until an administrator (or an auto-approve rule) approves them.
--
-- approval_status semantics (per version row):
--   NULL              -> not subject to approval; always visible (default)
--   'pending_approval'-> awaiting review; hidden from protocol endpoints
--   'approved'        -> visible to clients
--   'rejected'        -> permanently hidden
--
-- Mirrors without requires_approval behave exactly as before: their versions
-- keep approval_status = NULL and incur zero filtering cost.

-- Provider mirror: gate flag + optional auto-approve rules (JSON).
ALTER TABLE mirror_configurations
    ADD COLUMN IF NOT EXISTS requires_approval  BOOLEAN DEFAULT FALSE NOT NULL,
    ADD COLUMN IF NOT EXISTS auto_approve_rules JSONB   DEFAULT NULL;

-- Terraform binary mirror: same two fields.
ALTER TABLE terraform_mirror_configs
    ADD COLUMN IF NOT EXISTS requires_approval  BOOLEAN DEFAULT FALSE NOT NULL,
    ADD COLUMN IF NOT EXISTS auto_approve_rules JSONB   DEFAULT NULL;

-- Per-version approval state.
ALTER TABLE mirrored_provider_versions
    ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT NULL
        CHECK (approval_status IN ('pending_approval', 'approved', 'rejected'));

ALTER TABLE terraform_versions
    ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT NULL
        CHECK (approval_status IN ('pending_approval', 'approved', 'rejected'));

-- Partial indexes keep the "pending count" badge and protocol filtering fast
-- without penalising the common case (approval_status IS NULL).
CREATE INDEX IF NOT EXISTS idx_mpv_approval_status
    ON mirrored_provider_versions (approval_status)
    WHERE approval_status IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tfv_approval_status
    ON terraform_versions (approval_status)
    WHERE approval_status IS NOT NULL;

-- Audit trail of every approval decision (auto or manual).
CREATE TABLE IF NOT EXISTS version_approval_events (
    id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mirrored_provider_version_id UUID REFERENCES mirrored_provider_versions(id) ON DELETE CASCADE,
    terraform_version_id         UUID REFERENCES terraform_versions(id)         ON DELETE CASCADE,
    action                       VARCHAR(20) NOT NULL CHECK (action IN ('auto_approved', 'approved', 'rejected')),
    performed_by                 UUID REFERENCES users(id) ON DELETE SET NULL,
    notes                        TEXT,
    auto_approve_rule            VARCHAR(50),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT exactly_one_target CHECK (
        (mirrored_provider_version_id IS NOT NULL)::int +
        (terraform_version_id         IS NOT NULL)::int = 1
    )
);

CREATE INDEX IF NOT EXISTS idx_vae_mpv ON version_approval_events (mirrored_provider_version_id) WHERE mirrored_provider_version_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vae_tfv ON version_approval_events (terraform_version_id)         WHERE terraform_version_id IS NOT NULL;

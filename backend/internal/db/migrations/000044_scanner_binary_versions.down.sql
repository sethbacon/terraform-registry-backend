DROP INDEX IF EXISTS idx_vae_sbv;

ALTER TABLE version_approval_events DROP CONSTRAINT IF EXISTS exactly_one_target;
ALTER TABLE version_approval_events ADD  CONSTRAINT exactly_one_target CHECK (
    (mirrored_provider_version_id IS NOT NULL)::int +
    (terraform_version_id         IS NOT NULL)::int = 1
);
ALTER TABLE version_approval_events DROP COLUMN IF EXISTS scanner_binary_version_id;

DROP TABLE IF EXISTS scanner_binary_versions;

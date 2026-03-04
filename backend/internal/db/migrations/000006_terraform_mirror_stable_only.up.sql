-- Migration 000006: Add stable_only flag to terraform_mirror_configs.
-- When true, the sync job filters out pre-release versions (alpha/beta/rc)
-- identified by a "-" or "+" in the version string (standard semver pre-release
-- and build-metadata suffixes).

ALTER TABLE terraform_mirror_configs
    ADD COLUMN IF NOT EXISTS stable_only BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN terraform_mirror_configs.stable_only IS
    'When true, only stable releases (no alpha/beta/rc pre-releases) are synced. '
    'Versions whose string contains "-" or "+" are skipped.';

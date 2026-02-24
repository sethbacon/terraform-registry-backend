-- ============================================================================
-- Add version_filter column to terraform_mirror_configs
-- Allows operators to restrict which Terraform/OpenTofu versions are synced
-- using prefix, latest:N, semver constraint, or exact-version filters.
-- ============================================================================

ALTER TABLE terraform_mirror_configs
    ADD COLUMN IF NOT EXISTS version_filter TEXT DEFAULT NULL;

COMMENT ON COLUMN terraform_mirror_configs.version_filter IS
    'Optional version filter expression. Supported formats: '
    '"1.9" or "1.9." (prefix), "latest:5" (N most-recent), '
    '">=1.5.0" (semver constraint), comma-separated exact versions, '
    'or a single exact version string. NULL means all versions.';

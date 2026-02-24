-- Revert: remove version_filter column from terraform_mirror_configs
ALTER TABLE terraform_mirror_configs
    DROP COLUMN IF EXISTS version_filter;

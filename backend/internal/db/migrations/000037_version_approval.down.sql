DROP TABLE IF EXISTS version_approval_events;

DROP INDEX IF EXISTS idx_tfv_approval_status;
DROP INDEX IF EXISTS idx_mpv_approval_status;

ALTER TABLE terraform_versions          DROP COLUMN IF EXISTS approval_status;
ALTER TABLE mirrored_provider_versions  DROP COLUMN IF EXISTS approval_status;

ALTER TABLE terraform_mirror_configs
    DROP COLUMN IF EXISTS auto_approve_rules,
    DROP COLUMN IF EXISTS requires_approval;

ALTER TABLE mirror_configurations
    DROP COLUMN IF EXISTS auto_approve_rules,
    DROP COLUMN IF EXISTS requires_approval;

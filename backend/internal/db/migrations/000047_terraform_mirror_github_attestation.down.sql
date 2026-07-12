ALTER TABLE terraform_mirror_configs
    DROP COLUMN IF EXISTS verify_github_attestation;

ALTER TABLE terraform_version_platforms
    DROP COLUMN IF EXISTS attestation_verified;

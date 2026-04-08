ALTER TABLE terraform_mirror_configs
    DROP COLUMN IF EXISTS custom_gpg_key,
    DROP COLUMN IF EXISTS skip_gpg_verify;

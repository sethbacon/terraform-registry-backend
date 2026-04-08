ALTER TABLE terraform_mirror_configs
    ADD COLUMN IF NOT EXISTS custom_gpg_key TEXT,
    ADD COLUMN IF NOT EXISTS skip_gpg_verify BOOLEAN NOT NULL DEFAULT FALSE;

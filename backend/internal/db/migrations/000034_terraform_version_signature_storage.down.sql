ALTER TABLE terraform_versions
    DROP COLUMN IF EXISTS sums_storage_key,
    DROP COLUMN IF EXISTS sig_storage_key;

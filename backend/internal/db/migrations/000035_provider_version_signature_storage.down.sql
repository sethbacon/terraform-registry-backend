ALTER TABLE provider_versions
    DROP COLUMN IF EXISTS shasum_storage_key,
    DROP COLUMN IF EXISTS shasum_signature_storage_key;

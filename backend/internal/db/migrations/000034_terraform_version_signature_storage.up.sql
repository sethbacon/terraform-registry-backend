-- Persist the GPG signature and SHA256SUMS files alongside the binaries so
-- the public download endpoint can hand them back to clients for offline
-- verification. Prior to this migration the sync job fetched both files
-- only to verify GPG and then discarded them, leaving no way to serve a
-- .sig file at download time.
ALTER TABLE terraform_versions
    ADD COLUMN IF NOT EXISTS sums_storage_key TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS sig_storage_key  TEXT DEFAULT NULL;

COMMENT ON COLUMN terraform_versions.sums_storage_key IS
    'Storage backend key for the GPG-verified SHA256SUMS file. NULL until sync has stored it.';
COMMENT ON COLUMN terraform_versions.sig_storage_key IS
    'Storage backend key for the GPG signature (.sig) of SHA256SUMS. NULL until sync has stored it.';

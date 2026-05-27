-- Provider versions can now have their SHA256SUMS file and detached GPG
-- signature stored in the registry's own storage backend (in addition to
-- the existing ShasumURL/ShasumSignatureURL columns which hold external
-- URLs populated by the mirror-sync job pointing at HashiCorp's CDN).
--
-- When a user uploads a provider directly (rather than mirroring), we
-- store the files locally and the download handler generates pre-signed
-- URLs on demand. The Terraform Provider Registry Protocol places no
-- restriction on whether shasums_url and shasums_signature_url are
-- external or pre-signed (see provider-registry-protocol docs).
ALTER TABLE provider_versions
    ADD COLUMN IF NOT EXISTS shasum_storage_key           TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS shasum_signature_storage_key TEXT DEFAULT NULL;

COMMENT ON COLUMN provider_versions.shasum_storage_key IS
    'Storage backend key for the SHA256SUMS file uploaded with this version. NULL when not stored locally (e.g. mirrored providers use shasum_url instead).';
COMMENT ON COLUMN provider_versions.shasum_signature_storage_key IS
    'Storage backend key for the GPG-verified detached signature of SHA256SUMS. NULL when not stored locally.';

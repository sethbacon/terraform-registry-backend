ALTER TABLE provider_platforms
    ADD COLUMN h1_hash TEXT DEFAULT NULL;

COMMENT ON COLUMN provider_platforms.h1_hash IS 'Terraform h1: dirhash of the provider zip archive (sorted-file SHA-256 manifest). NULL for platforms synced before this migration.';

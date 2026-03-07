-- Stores the full SHA256SUMS entry set for a provider version as fetched and
-- GPG-verified during mirror sync.  Persisting all entries (including
-- platforms that are not mirrored locally) lets the Network Mirror Protocol
-- endpoint serve zh: hashes for every platform in the upstream release, so
-- clients can build a complete cross-platform lock file from this mirror alone.
CREATE TABLE provider_version_shasums (
    provider_version_id UUID    NOT NULL REFERENCES provider_versions(id) ON DELETE CASCADE,
    filename            TEXT    NOT NULL,
    sha256_hex          TEXT    NOT NULL,
    PRIMARY KEY (provider_version_id, filename)
);

COMMENT ON TABLE provider_version_shasums IS
    'Per-file SHA256 checksums from the upstream HashiCorp SHA256SUMS file, stored verbatim after GPG verification during mirror sync.';

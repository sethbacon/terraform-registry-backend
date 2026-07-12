-- GitHub Artifact Attestation verification for unsigned-upstream tools.
-- Recent OPA releases (v1.18.0+) carry an out-of-band Sigstore-signed in-toto
-- release attestation (predicate https://in-toto.io/attestation/release/v0.2)
-- served from GitHub's attestation API by artifact digest — the only
-- signature-based authenticity such upstreams have (no GPG key exists).
-- verify_github_attestation opts a mirror config into verifying it during
-- sync; attestation_verified records, per platform binary, that the
-- downloaded file's SHA-256 digest was bound to an attestation whose Fulcio
-- signer identity was pinned to the upstream repository. The column is named
-- generically ("attestation", not "github_attestation") so it can also carry
-- future SLSA-provenance / cosign verification results. Independent of
-- gpg_verified and sha256_verified.
ALTER TABLE terraform_mirror_configs
    ADD COLUMN IF NOT EXISTS verify_github_attestation BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE terraform_version_platforms
    ADD COLUMN IF NOT EXISTS attestation_verified BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN terraform_mirror_configs.verify_github_attestation IS
    'When true, mirror sync verifies GitHub Artifact Attestations (Sigstore, pinned signer identity) for binaries of GitHub-hosted upstreams. Only meaningful for unsigned-upstream tools such as OPA.';
COMMENT ON COLUMN terraform_version_platforms.attestation_verified IS
    'True when the binary''s SHA-256 digest was bound to a release attestation verified against a pinned signer identity (issuer + source repository). Independent of gpg_verified/sha256_verified.';

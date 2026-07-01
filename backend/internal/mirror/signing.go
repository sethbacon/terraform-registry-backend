package mirror

import "strings"

// unsignedUpstreamTools lists tools whose upstream publishes release binaries
// WITHOUT any cryptographic signature — only SHA-256 checksums (per-file
// .sha256 sidecars). For these, mirror sync verifies integrity via those
// checksums but cannot verify authenticity: there is simply no signature to
// check. This is an intentional, documented state — distinct from a tool that
// SHOULD be signed but has no key configured, which is a likely misconfiguration.
//
// OPA (open-policy-agent/opa) is the canonical case: its GitHub releases ship
// opa_<os>_<arch> binaries each with a sibling opa_<os>_<arch>.sha256, and no
// .sig / SHA256SUMS / cosign signature artifacts attached to the release.
//
// Nuance (verified 2026-06-28): recent OPA releases (v1.18.0+) do carry an
// out-of-band GitHub Artifact Attestation — a Sigstore-signed in-toto statement
// (predicate https://in-toto.io/attestation/release/v0.2) served from GitHub's
// attestation API, not as a release asset. It is NOT GPG and NOT SLSA build
// provenance (the default `gh attestation verify` provenance lookup 404s), so it
// does not change the checksum-only handling here; attestation-based authenticity
// would be a separate future enhancement, not a GPG key to embed.
//
// terraform-docs (terraform-docs/terraform-docs) is a second case (verified
// 2026-06-30): its GitHub releases ship terraform-docs-v<ver>-<os>-<arch>.tar.gz
// (and .zip for windows) archives plus a single combined
// terraform-docs-v<ver>.sha256sum checksum file, with no .sig / cosign / SLSA
// provenance artifacts. Integrity is verified against that checksum file;
// authenticity cannot be, exactly as with OPA.
var unsignedUpstreamTools = map[string]bool{
	"opa":            true,
	"terraform-docs": true,
}

// IsUnsignedUpstreamTool reports whether the given tool's upstream publishes no
// release signatures (checksum-only verification is the best available). Used so
// the mirror sync and the admin signing-keys view can present OPA honestly as
// "unsigned upstream" rather than as a missing-key error or a silent skip.
func IsUnsignedUpstreamTool(tool string) bool {
	return unsignedUpstreamTools[strings.ToLower(strings.TrimSpace(tool))]
}

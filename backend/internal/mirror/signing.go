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
// .sig / SHA256SUMS / cosign artifacts.
var unsignedUpstreamTools = map[string]bool{
	"opa": true,
}

// IsUnsignedUpstreamTool reports whether the given tool's upstream publishes no
// release signatures (checksum-only verification is the best available). Used so
// the mirror sync and the admin signing-keys view can present OPA honestly as
// "unsigned upstream" rather than as a missing-key error or a silent skip.
func IsUnsignedUpstreamTool(tool string) bool {
	return unsignedUpstreamTools[strings.ToLower(strings.TrimSpace(tool))]
}

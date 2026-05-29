package mirror

import "errors"

const hashiCorpFingerprint = "C874011F0AB405110D02105534365D9472D7468F"

// HasUsableGPGKey reports whether the armored key contains at least one
// non-expired signing subkey or primary key.
func HasUsableGPGKey(armored string) bool {
	info, err := ParseReleasesKey(armored)
	if err != nil {
		return false
	}
	return info.HasUsableSigningKey
}

// ResolveExpiredGPGKey checks if an armored GPG key is expired and, if its
// primary fingerprint matches a known releases key, returns the refreshed
// embedded snapshot. If the key is valid, unparseable, or has an unknown
// fingerprint, it is returned unchanged.
//
// This handles the case where the upstream Terraform provider registry
// serves an expired signing key that gets stored in provider_versions at
// sync time. Substitution only occurs for fingerprint-pinned keys.
func ResolveExpiredGPGKey(armored string) string {
	info, err := ParseReleasesKey(armored)
	if err != nil && !errors.Is(err, ErrNoUsableSigningKey) {
		return armored
	}
	if info.HasUsableSigningKey {
		return armored
	}
	switch info.PrimaryFingerprint {
	case hashiCorpFingerprint:
		return HashiCorpReleasesGPGKey
	default:
		return armored
	}
}

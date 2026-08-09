package storage

import (
	"fmt"
	"path"
	"strings"
)

// maxKeyBytes caps an object key. S3 rejects keys over 1024 bytes, so a longer
// key is a guaranteed backend error later; refusing it here turns an opaque
// provider-specific failure into a clear one. The longest key this application
// produces is around 110 bytes.
const maxKeyBytes = 1024

// ValidateKey rejects object keys that are malformed or path-traversing.
//
// The local backend has always had safeJoin, documented as defence in depth
// "so the storage layer cannot be exploited even if a future code path skips
// that check". The cloud backends had no equivalent: S3, Azure and GCS pass the
// caller's string through as the object key verbatim (issue #752). This makes
// the guarantee uniform rather than local-only.
//
// Object stores treat keys as opaque, so ".." has no traversal meaning there
// and no per-tenant key prefix currently exists to escape — this is a hardening
// gap, not a live exploit, and the issue says as much. What makes it worth
// closing is that the gap is structural: /v1/files/*filepath already feeds a
// URL-derived string into these backends, and adding a bucket prefix, a
// per-organization key namespace, or a shared-bucket deployment later would
// silently have no enforcement.
//
// # What is deliberately NOT rejected
//
// No character-set restriction. Real keys in this registry contain uppercase
// (namespaces are not lowercased on the storage path), '+' and '~' from version
// strings — hashicorp/go-version is looser than strict semver and accepts build
// metadata like 1.0.0+build.5 — and '.' throughout. A charset allowlist derived
// from what "should" be there would reject artifacts that already exist.
//
// No prefix allowlist. It is tempting to require modules/, providers/ or
// terraform-binaries/, but .readiness-probe and .connectivity-test are
// root-level sentinel keys with no prefix at all, and rejecting them would
// break the readiness endpoint and both storage connectivity tests.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("storage key is empty")
	}
	if len(key) > maxKeyBytes {
		return fmt.Errorf("storage key is %d bytes, over the %d-byte limit", len(key), maxKeyBytes)
	}
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("storage key %q is absolute", key)
	}
	// Backslash: a Windows separator smuggled past a '/'-oriented check, and
	// never legitimate in a key this application builds.
	if strings.Contains(key, `\`) {
		return fmt.Errorf("storage key %q contains a backslash", key)
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("storage key %q contains a control character", key)
		}
	}
	// Empty segments. "modules//x" and "modules/x" are DIFFERENT keys to an
	// object store, so this is also a confusable-duplicate guard, not only a
	// traversal one.
	if strings.Contains(key, "//") {
		return fmt.Errorf("storage key %q contains an empty path segment", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("storage key %q contains a %q segment", key, "..")
		}
	}
	// Canonical form. Catches the remaining non-traversing oddities in one
	// rule: a leading "./", a trailing "/", an interior "/./". Each names a
	// distinct object-store key that resolves to the same file on a filesystem,
	// which is how the same artifact ends up stored twice and deleted once.
	if cleaned := path.Clean(key); cleaned != key {
		return fmt.Errorf("storage key %q is not canonical (want %q)", key, cleaned)
	}
	// path.Clean(".") is "." — canonical, but not an object.
	if key == "." {
		return fmt.Errorf("storage key %q names no object", key)
	}
	return nil
}

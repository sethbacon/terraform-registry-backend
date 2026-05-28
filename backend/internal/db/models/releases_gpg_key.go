// Package models - releases_gpg_key.go defines the cached upstream release-signing
// GPG key model populated by the ReleasesKeyRefreshJob from each tool's
// .well-known/pgp-key.txt endpoint.
package models

import "time"

// ReleasesGPGKey is a cached ASCII-armored release-signing key for a single
// tool ("terraform" | "opentofu"). PrimaryFingerprint is the hex-encoded,
// uppercase 40-character SHA-1 fingerprint of the OpenPGP primary key; the
// refresh job pins this against a hardcoded allow-list before writing so a
// compromised TLS path cannot substitute a different key.
type ReleasesGPGKey struct {
	Tool               string     `db:"tool"`
	ArmoredKey         string     `db:"armored_key"`
	PrimaryFingerprint string     `db:"primary_fpr"`
	KeyExpiresAt       *time.Time `db:"key_expires_at"`
	SourceURL          string     `db:"source_url"`
	FetchedAt          time.Time  `db:"fetched_at"`
}

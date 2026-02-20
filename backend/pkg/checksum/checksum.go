// Package checksum provides SHA-256 checksum utilities for file integrity
// verification. It is used during provider binary uploads to compute checksums
// and verify them against the upstream SHA256SUMS file published alongside each
// provider release. Keeping this logic in a dedicated package makes it easy to
// apply consistent hashing behaviour across the upload, mirror, and storage
// layers without duplicating crypto/sha256 wiring throughout the codebase.
package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// CalculateSHA256 calculates the SHA256 checksum of data from a reader
func CalculateSHA256(reader io.Reader) (string, error) {
	hasher := sha256.New()

	if _, err := io.Copy(hasher, reader); err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifySHA256 verifies that the checksum of data matches the expected checksum
func VerifySHA256(reader io.Reader, expectedChecksum string) (bool, error) {
	actualChecksum, err := CalculateSHA256(reader)
	if err != nil {
		return false, err
	}

	return actualChecksum == expectedChecksum, nil
}

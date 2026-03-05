// Package checksum provides SHA-256 checksum utilities for file integrity
// verification. It is used during provider binary uploads to compute checksums
// and verify them against the upstream SHA256SUMS file published alongside each
// provider release. Keeping this logic in a dedicated package makes it easy to
// apply consistent hashing behaviour across the upload, mirror, and storage
// layers without duplicating crypto/sha256 wiring throughout the codebase.
package checksum

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
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

// HashZip computes the Terraform h1: dirhash of a zip archive. It is the same
// algorithm used by Terraform when verifying provider packages downloaded from a
// network mirror: for each file inside the zip (sorted by name) the SHA-256 of
// its raw content is computed, a manifest line of the form
//
//	"<sha256hex>  <filename>\n"
//
// is written to an outer SHA-256 hasher, and the final digest is returned as
// "h1:<base64>". This matches Go's golang.org/x/mod/dirhash.HashZip behaviour.
func HashZip(zipContent []byte) (string, error) {
	r, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
	if err != nil {
		return "", fmt.Errorf("failed to read zip archive: %w", err)
	}

	// Collect and sort entry names for deterministic ordering.
	names := make([]string, 0, len(r.File))
	files := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
		files[f.Name] = f
	}
	sort.Strings(names)

	// Build the manifest hash.
	outer := sha256.New()
	for _, name := range names {
		inner := sha256.New()
		rc, err := files[name].Open()
		if err != nil {
			return "", fmt.Errorf("failed to open zip entry %q: %w", name, err)
		}
		if _, err := io.Copy(inner, rc); err != nil {
			rc.Close() // #nosec G104 -- best-effort close; the copy error takes precedence
			return "", fmt.Errorf("failed to hash zip entry %q: %w", name, err)
		}
		if err := rc.Close(); err != nil {
			return "", fmt.Errorf("failed to close zip entry %q: %w", name, err)
		}
		fmt.Fprintf(outer, "%x  %s\n", inner.Sum(nil), name)
	}

	return "h1:" + base64.StdEncoding.EncodeToString(outer.Sum(nil)), nil
}

// Package archiver provides helpers for extracting module archives.
// ExtractTarGz is shared between the module scanner job (Feature 2) and the
// terraform-docs analyzer (Feature 3).
package archiver

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxExtractBytes is the cumulative decompressed-bytes limit across all entries;
// matches the 100 MB cap enforced by validation.ValidateArchive at upload time.
const maxExtractBytes = 100 << 20 // 100 MB total

// maxExtractEntries bounds the number of tar entries extracted. Without this, an
// archive of millions of zero-byte file entries writes 0 body bytes (never tripping
// maxExtractBytes) while still exhausting inodes/metadata on the extraction worker.
// A ~1MB gzip can encode ~2M such entries, so this must be checked independently of
// the byte cap. Matches the cap enforced by validation.ValidateArchive at upload time.
const maxExtractEntries = 100000

// maxCompressedInputBytes bounds the compressed (gzip) input stream itself, mirroring
// validation.ValidateArchive's io.LimitReader wrap. Without this, ExtractTarGz would
// read an unbounded compressed stream even though the decompressed output is capped.
const maxCompressedInputBytes = 100 << 20 // 100 MB

// ExtractTarGz extracts a gzipped tar archive from reader into destDir.
// Enforces path traversal protection, a 100 MB cumulative extraction limit, a
// maximum entry count, and a compressed-input size cap. Returns an error on
// invalid archives.
func ExtractTarGz(reader io.Reader, destDir string) error {
	if !filepath.IsAbs(destDir) {
		return fmt.Errorf("destDir must be an absolute path, got: %s", destDir)
	}
	gzr, err := gzip.NewReader(io.LimitReader(reader, maxCompressedInputBytes+1))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var totalWritten int64
	var entryCount int
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		entryCount++
		if entryCount > maxExtractEntries {
			return fmt.Errorf("archive exceeds maximum entry count of %d", maxExtractEntries)
		}

		// Prevent path traversal: resolve against destDir and verify containment
		// using filepath.Rel. A relative path that starts with ".." (or equals it)
		// escapes destDir; we also reject absolute results defensively.
		cleanDest := filepath.Clean(destDir)
		target := filepath.Join(cleanDest, header.Name) // #nosec G305 -- containment verified below
		rel, err := filepath.Rel(cleanDest, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("invalid file path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return fmt.Errorf("mkdir parent: %w", err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode&0777)) // #nosec G304,G115 -- target validated by prefix check above; mode & 0777 fits in uint32
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			remaining := maxExtractBytes - totalWritten
			n, copyErr := io.Copy(f, io.LimitReader(tr, remaining+1))
			_ = f.Close()
			if copyErr != nil {
				return fmt.Errorf("write file %s: %w", target, copyErr)
			}
			totalWritten += n
			if totalWritten > maxExtractBytes {
				return fmt.Errorf("archive exceeds extraction size limit of %d bytes", maxExtractBytes)
			}
		}
	}
	return nil
}

// FindModuleRoot returns the actual Terraform module root within an extracted directory.
// GitHub/GitLab archives often wrap contents in a single top-level directory.
// If the extracted directory contains exactly one subdirectory and that subdirectory
// contains .tf files, it is returned as the module root; otherwise extractedDir itself.
func FindModuleRoot(extractedDir string) string {
	entries, err := os.ReadDir(extractedDir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return extractedDir
	}
	sub := filepath.Join(extractedDir, entries[0].Name())
	tfs, _ := filepath.Glob(filepath.Join(sub, "*.tf"))
	if len(tfs) > 0 {
		return sub
	}
	return extractedDir
}

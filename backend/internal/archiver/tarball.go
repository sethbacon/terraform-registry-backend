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
)

// maxExtractBytes is the cumulative decompressed-bytes limit across all entries;
// matches the 100 MB cap enforced by validation.ValidateArchive at upload time.
const maxExtractBytes = 100 << 20 // 100 MB total

// ExtractTarGz extracts a gzipped tar archive from reader into destDir.
// Enforces path traversal protection and a 100 MB cumulative extraction limit.
// Returns an error on invalid archives.
func ExtractTarGz(reader io.Reader, destDir string) error {
	if !filepath.IsAbs(destDir) {
		return fmt.Errorf("destDir must be an absolute path, got: %s", destDir)
	}
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var totalWritten int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Prevent path traversal: filepath.Join calls Clean internally; the prefix
		// check below is the actual guard (destDir is always absolute).
		target := filepath.Join(destDir, header.Name) // #nosec G305
		cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
		if len(target) < len(cleanDest) || target[:len(cleanDest)] != cleanDest {
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

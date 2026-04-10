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

const maxExtractBytes = 500 << 20 // 500 MB — matches scm_publisher constant

// ExtractTarGz extracts a gzipped tar archive from reader into destDir.
// Enforces path traversal protection. Returns an error on invalid archives.
func ExtractTarGz(reader io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Prevent path traversal
		target := filepath.Join(destDir, header.Name) // #nosec G305
		if !filepath.IsAbs(target) {
			target = filepath.Clean(target)
		}
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
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode&0777)) // G304: target validated above; G115: mode & 0777 fits in uint32
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxExtractBytes)); err != nil {
				_ = f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			_ = f.Close()
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

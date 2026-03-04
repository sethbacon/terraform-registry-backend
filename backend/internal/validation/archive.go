// Package validation provides input validation for module and provider uploads. Each validator
// checks a specific aspect of the upload: archive structure (path traversal, symlinks, size
// limits), GPG signature verification, platform compatibility, README presence, and semantic
// version format. Validators run before any data is persisted so invalid uploads are rejected
// early without consuming storage.
package validation

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	// MaxArchiveSize is the maximum size for a module archive (100MB)
	MaxArchiveSize = 100 * 1024 * 1024
)

// ValidateArchive validates a tar.gz archive
func ValidateArchive(reader io.Reader, maxSize int64) error {
	if maxSize <= 0 {
		maxSize = MaxArchiveSize
	}

	// Wrap reader to track size
	limitedReader := io.LimitReader(reader, maxSize+1)

	// Check gzip format
	gzReader, err := gzip.NewReader(limitedReader)
	if err != nil {
		return fmt.Errorf("invalid gzip format: %w", err)
	}
	defer gzReader.Close()

	// Check tar format
	tarReader := tar.NewReader(gzReader)

	var totalSize int64
	fileCount := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid tar format: %w", err)
		}

		fileCount++
		totalSize += header.Size

		// Check for path traversal attacks
		if err := validatePath(header.Name); err != nil {
			return fmt.Errorf("invalid file path in archive: %w", err)
		}

		// Check size limit
		if totalSize > maxSize {
			return fmt.Errorf("archive size exceeds maximum allowed size of %d bytes", maxSize)
		}
	}

	if fileCount == 0 {
		return fmt.Errorf("archive is empty")
	}

	return nil
}

// validatePath checks for path traversal attacks
func validatePath(path string) error {
	// Normalize path
	path = filepath.Clean(path)

	// Check for absolute paths (Unix-style)
	if filepath.IsAbs(path) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Check for Windows-style absolute paths (e.g. C:\...) even on non-Windows hosts.
	// Archives extracted from Windows machines may contain these paths.
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Check for path traversal (..)
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	// Check for dangerous filenames
	if strings.HasPrefix(path, ".") && path != "." {
		// Allow hidden files but check for specific dangerous ones
		if strings.HasPrefix(path, ".git") {
			return fmt.Errorf("git directories not allowed in archives")
		}
	}

	return nil
}

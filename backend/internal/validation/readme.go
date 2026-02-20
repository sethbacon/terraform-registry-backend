// readme.go validates the presence of a README file within module archive tarballs,
// extracting its contents for storage and display in the registry.
package validation

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// ExtractReadme extracts README content from a tarball.
// Looks for README.md, README.txt, README, or readme.md files in the root.
// When multiple candidates are present, the one with the highest priority in
// the readmeNames list is returned (README.md wins over README, etc.).
func ExtractReadme(archiveReader io.Reader) (string, error) {
	// Create gzip reader
	gzReader, err := gzip.NewReader(archiveReader)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Priority-ordered list: index 0 = highest priority.
	readmeNames := []string{"README.md", "readme.md", "README.MD", "README", "readme", "README.txt", "readme.txt"}

	// Collect all README candidates keyed by their priority index so we can
	// return the highest-priority one after scanning the full archive.
	const maxReadmeSize = 1024 * 1024
	candidates := make(map[int]string) // priority → content

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar entry: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Get the file name (basename)
		fileName := header.Name
		// Remove leading ./ if present
		fileName = strings.TrimPrefix(fileName, "./")

		// Check if it's in the root (no subdirectories)
		if strings.Contains(fileName, "/") {
			continue
		}

		// Check if this is a README file and record it with its priority
		for priority, readmeName := range readmeNames {
			if strings.EqualFold(fileName, readmeName) {
				if _, already := candidates[priority]; !already {
					limited := io.LimitReader(tarReader, maxReadmeSize)
					content, err := io.ReadAll(limited)
					if err != nil {
						return "", fmt.Errorf("failed to read README content: %w", err)
					}
					candidates[priority] = string(content)
				}
				break
			}
		}
	}

	// Return the highest-priority candidate (lowest index in readmeNames).
	for priority := range readmeNames {
		if content, ok := candidates[priority]; ok {
			return content, nil
		}
	}

	return "", nil
}

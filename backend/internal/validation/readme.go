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

// ExtractReadme extracts README content from a tarball
// Looks for README.md, README.txt, README, or readme.md files in the root
func ExtractReadme(archiveReader io.Reader) (string, error) {
	// Create gzip reader
	gzReader, err := gzip.NewReader(archiveReader)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Look for README file in root directory
	readmeNames := []string{"README.md", "readme.md", "README.MD", "README", "readme", "README.txt", "readme.txt"}

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

		// Check if this is a README file
		for _, readmeName := range readmeNames {
			if strings.EqualFold(fileName, readmeName) {
				// Found README, read its contents
				// Limit README size to 1MB
				const maxReadmeSize = 1024 * 1024
				limited := io.LimitReader(tarReader, maxReadmeSize)
				content, err := io.ReadAll(limited)
				if err != nil {
					return "", fmt.Errorf("failed to read README content: %w", err)
				}
				return string(content), nil
			}
		}
	}

	// No README found
	return "", nil
}

// semver.go provides semantic version format validation and comparison helpers used when
// publishing or resolving module and provider version strings.
package validation

import (
	"fmt"

	"github.com/hashicorp/go-version"
)

// ValidateSemver validates that a version string is valid semantic versioning
func ValidateSemver(versionStr string) error {
	_, err := version.NewVersion(versionStr)
	if err != nil {
		return fmt.Errorf("invalid semantic version: %w", err)
	}
	return nil
}

// CompareSemver compares two semantic versions
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareSemver(v1Str, v2Str string) (int, error) {
	v1, err := version.NewVersion(v1Str)
	if err != nil {
		return 0, fmt.Errorf("invalid version v1: %w", err)
	}

	v2, err := version.NewVersion(v2Str)
	if err != nil {
		return 0, fmt.Errorf("invalid version v2: %w", err)
	}

	return v1.Compare(v2), nil
}

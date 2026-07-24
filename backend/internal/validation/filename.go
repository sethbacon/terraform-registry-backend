// filename.go validates upstream-supplied filenames before they are used as a
// storage-key path component, rejecting path separators and traversal
// sequences so an untrusted filename cannot inject extra path segments into
// an object-storage key.
package validation

import (
	"fmt"
	"strings"
)

// ValidateStorageFilename returns an error if name is not safe to use as the
// final path component of an object-storage key: it must be non-empty and
// free of path separators ('/', '\') and '..' traversal sequences. Intended
// for filenames sourced from untrusted/upstream data (e.g. an upstream
// registry's package descriptor) rather than caller-constructed names.
func ValidateStorageFilename(name string) error {
	if name == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("filename %q must not contain path separators", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("filename %q must not contain '..'", name)
	}
	return nil
}

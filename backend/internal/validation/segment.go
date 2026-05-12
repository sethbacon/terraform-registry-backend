// segment.go validates registry identifier segments (namespace, module name, provider type)
// against the naming rules required by the Terraform registry protocol. Each segment is used
// as a URL path component in source addresses of the form
// <hostname>/<namespace>/<name>/<provider>, so only URL-safe, lowercase characters are allowed.
package validation

import (
	"fmt"
	"regexp"
)

// reRegistrySegment matches valid Terraform registry identifier segments:
//   - lowercase alphanumeric, hyphens, and underscores only
//   - must start with a lowercase alphanumeric character
//   - length: 1–64 characters
var reRegistrySegment = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidateRegistrySegment returns an error if s is not a valid Terraform registry
// identifier segment. The same rule applies to namespace, module name, and provider
// type fields wherever they appear in the API.
func ValidateRegistrySegment(s string) error {
	if !reRegistrySegment.MatchString(s) {
		return fmt.Errorf(
			"%q is not a valid registry identifier: must be 1–64 characters, "+
				"start with a lowercase letter or digit, and contain only "+
				"lowercase letters, digits, hyphens, or underscores",
			s,
		)
	}
	return nil
}

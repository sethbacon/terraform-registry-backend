// platform.go validates OS and architecture strings for provider binaries against the
// set of supported OS/arch pairs recognized by Terraform.
package validation

import "fmt"

// SupportedOS lists all supported operating systems for Terraform providers
var SupportedOS = []string{
	"darwin",
	"freebsd",
	"linux",
	"openbsd",
	"solaris",
	"windows",
}

// SupportedArch lists all supported architectures for Terraform providers
var SupportedArch = []string{
	"386",
	"amd64",
	"arm",
	"arm64",
}

// ValidatePlatform validates that the OS and architecture combination is supported
func ValidatePlatform(os string, arch string) error {
	if os == "" {
		return fmt.Errorf("operating system cannot be empty")
	}

	if arch == "" {
		return fmt.Errorf("architecture cannot be empty")
	}

	// Validate OS
	if !isValidOS(os) {
		return fmt.Errorf("unsupported operating system: %s (supported: %v)", os, SupportedOS)
	}

	// Validate architecture
	if !isValidArch(arch) {
		return fmt.Errorf("unsupported architecture: %s (supported: %v)", arch, SupportedArch)
	}

	// Validate specific OS/arch combinations that are known to be invalid
	if err := validateOSArchCombination(os, arch); err != nil {
		return err
	}

	return nil
}

// isValidOS checks if the operating system is in the supported list
func isValidOS(os string) bool {
	for _, supported := range SupportedOS {
		if os == supported {
			return true
		}
	}
	return false
}

// isValidArch checks if the architecture is in the supported list
func isValidArch(arch string) bool {
	for _, supported := range SupportedArch {
		if arch == supported {
			return true
		}
	}
	return false
}

// validateOSArchCombination validates specific OS/arch combinations
// Some combinations might not make sense (e.g., solaris/arm64)
func validateOSArchCombination(os string, arch string) error {
	// For now, we accept all combinations of valid OS and arch
	// In the future, we could add specific restrictions here
	// For example:
	// - Solaris typically doesn't run on ARM
	// - Certain OS versions only support specific architectures

	return nil
}

// FormatPlatformKey returns a standardized platform key in the format "os_arch"
func FormatPlatformKey(os string, arch string) string {
	return fmt.Sprintf("%s_%s", os, arch)
}

// GetPlatformDisplayName returns a human-readable platform name
func GetPlatformDisplayName(os string, arch string) string {
	osNames := map[string]string{
		"darwin":  "macOS",
		"freebsd": "FreeBSD",
		"linux":   "Linux",
		"openbsd": "OpenBSD",
		"solaris": "Solaris",
		"windows": "Windows",
	}

	archNames := map[string]string{
		"386":   "32-bit",
		"amd64": "64-bit",
		"arm":   "ARM",
		"arm64": "ARM64",
	}

	osName := osNames[os]
	if osName == "" {
		osName = os
	}

	archName := archNames[arch]
	if archName == "" {
		archName = arch
	}

	return fmt.Sprintf("%s %s", osName, archName)
}

package validation

import (
	"strings"
	"testing"
)

func TestValidatePlatform(t *testing.T) {
	tests := []struct {
		name    string
		os      string
		arch    string
		wantErr bool
	}{
		// Valid combinations
		{"linux amd64", "linux", "amd64", false},
		{"linux arm64", "linux", "arm64", false},
		{"linux arm", "linux", "arm", false},
		{"linux 386", "linux", "386", false},
		{"darwin amd64", "darwin", "amd64", false},
		{"darwin arm64", "darwin", "arm64", false},
		{"windows amd64", "windows", "amd64", false},
		{"windows 386", "windows", "386", false},
		{"freebsd amd64", "freebsd", "amd64", false},
		{"openbsd amd64", "openbsd", "amd64", false},
		{"solaris amd64", "solaris", "amd64", false},
		// Invalid: empty fields
		{"empty os", "", "amd64", true},
		{"empty arch", "linux", "", true},
		{"both empty", "", "", true},
		// Invalid: unsupported values
		{"invalid os", "haiku", "amd64", true},
		{"invalid arch", "linux", "mips64", true},
		{"both invalid", "beos", "risc-v", true},
		// Case sensitivity – must be lowercase
		{"uppercase OS", "Linux", "amd64", true},
		{"uppercase arch", "linux", "AMD64", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlatform(tt.os, tt.arch)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePlatform(%q, %q) error = %v, wantErr %v", tt.os, tt.arch, err, tt.wantErr)
			}
		})
	}
}

func TestFormatPlatformKey(t *testing.T) {
	tests := []struct {
		os   string
		arch string
		want string
	}{
		{"linux", "amd64", "linux_amd64"},
		{"darwin", "arm64", "darwin_arm64"},
		{"windows", "386", "windows_386"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatPlatformKey(tt.os, tt.arch)
			if got != tt.want {
				t.Errorf("FormatPlatformKey(%q, %q) = %q, want %q", tt.os, tt.arch, got, tt.want)
			}
		})
	}
}

func TestGetPlatformDisplayName(t *testing.T) {
	tests := []struct {
		os         string
		arch       string
		wantSubstr string
	}{
		{"linux", "amd64", "Linux"},
		{"darwin", "amd64", "macOS"},
		{"windows", "amd64", "Windows"},
		{"freebsd", "amd64", "FreeBSD"},
		{"openbsd", "amd64", "OpenBSD"},
		{"solaris", "amd64", "Solaris"},
		{"linux", "arm64", "ARM64"},
		{"linux", "arm", "ARM"},
		{"linux", "386", "32-bit"},
		{"linux", "amd64", "64-bit"},
		// Unknown values fall back to raw string
		{"plan9", "risc-v", "plan9"},
	}

	for _, tt := range tests {
		t.Run(tt.os+"_"+tt.arch, func(t *testing.T) {
			got := GetPlatformDisplayName(tt.os, tt.arch)
			if !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("GetPlatformDisplayName(%q, %q) = %q, want substring %q", tt.os, tt.arch, got, tt.wantSubstr)
			}
		})
	}
}

func TestSupportedLists(t *testing.T) {
	if len(SupportedOS) == 0 {
		t.Error("SupportedOS should not be empty")
	}
	if len(SupportedArch) == 0 {
		t.Error("SupportedArch should not be empty")
	}
	// All items should be non-empty strings
	for _, os := range SupportedOS {
		if os == "" {
			t.Error("SupportedOS contains empty string")
		}
	}
	for _, arch := range SupportedArch {
		if arch == "" {
			t.Error("SupportedArch contains empty string")
		}
	}
}

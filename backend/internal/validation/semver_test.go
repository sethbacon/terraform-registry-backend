package validation

import "testing"

func TestValidateSemver(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"simple release", "1.0.0", false},
		{"patch release", "1.2.3", false},
		{"pre-release", "1.0.0-beta", false},
		{"pre-release with number", "1.0.0-beta.1", false},
		{"pre-release alpha", "2.0.0-alpha.3", false},
		{"build metadata", "1.0.0+build.1", false},
		{"zero version", "0.0.0", false},
		{"large version", "100.200.300", false},
		{"empty string", "", true},
		{"plain text", "not-a-version", true},
		{"missing patch", "1.0", false}, // hashicorp/go-version is lenient
		{"negative", "-1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSemver(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSemver(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		name    string
		v1      string
		v2      string
		want    int
		wantErr bool
	}{
		{"equal", "1.0.0", "1.0.0", 0, false},
		{"v1 less than v2", "1.0.0", "2.0.0", -1, false},
		{"v1 greater than v2", "2.0.0", "1.0.0", 1, false},
		{"patch difference less", "1.0.0", "1.0.1", -1, false},
		{"patch difference greater", "1.0.1", "1.0.0", 1, false},
		{"minor difference less", "1.0.0", "1.1.0", -1, false},
		{"minor difference greater", "1.1.0", "1.0.0", 1, false},
		{"pre-release less than release", "1.0.0-alpha", "1.0.0", -1, false},
		{"invalid v1", "bad", "1.0.0", 0, true},
		{"invalid v2", "1.0.0", "bad", 0, true},
		{"both invalid", "bad", "also-bad", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareSemver(tt.v1, tt.v2)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareSemver(%q, %q) error = %v, wantErr %v", tt.v1, tt.v2, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("CompareSemver(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

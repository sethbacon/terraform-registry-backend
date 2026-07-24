package validation

import "testing"

func TestValidateStorageFilename(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid: realistic upstream package filenames.
		{"typical provider zip", "terraform-provider-aws_5.0.0_linux_amd64.zip", false},
		{"typical binary zip", "terraform_1.7.0_linux_amd64.zip", false},
		{"dot in version", "terraform-provider-aws_5.0.0-beta.1_linux_amd64.zip", false},

		// Invalid: path traversal / injection attempts from an upstream descriptor.
		{"empty string", "", true},
		{"forward slash", "../../etc/passwd", true},
		{"single parent ref", "..", true},
		{"embedded parent ref", "foo/../bar.zip", true},
		{"leading slash", "/etc/passwd", true},
		{"backslash", `..\..\windows\system32`, true},
		{"dot-dot suffix no separator", "foo..bar.zip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStorageFilename(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStorageFilename(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

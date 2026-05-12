package validation

import "testing"

func TestValidateRegistrySegment(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid
		{"simple lowercase", "myorg", false},
		{"with hyphen", "my-org", false},
		{"with underscore", "my_org", false},
		{"starts with digit", "1org", false},
		{"single char", "a", false},
		{"64 chars", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01", false},
		{"mixed valid", "terraform-aws-123", false},
		{"leading digit", "1-myorg", false},

		// Invalid
		{"empty string", "", true},
		{"starts with hyphen", "-myorg", true},
		{"starts with underscore", "_myorg", true},
		{"contains space", "my org", true},
		{"contains uppercase", "MyOrg", true},
		{"contains dot", "my.org", true},
		{"contains slash", "my/org", true},
		{"65 chars", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012", true},
		{"contains @", "my@org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegistrySegment(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRegistrySegment(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

package validation

import (
	"bytes"
	"strings"
	"testing"
)

func TestExtractReadme(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]string
		wantContent string // substring that must appear, or exact match when wantExact=true
		wantExact   bool
		wantErr     bool
	}{
		{
			name:        "README.md at root",
			files:       map[string]string{"README.md": "# My Module\nHello world."},
			wantContent: "# My Module\nHello world.",
			wantExact:   true,
		},
		{
			name:        "readme.md (lowercase)",
			files:       map[string]string{"readme.md": "lowercase readme"},
			wantContent: "lowercase readme",
			wantExact:   true,
		},
		{
			name:        "README (no extension)",
			files:       map[string]string{"README": "plain readme"},
			wantContent: "plain readme",
			wantExact:   true,
		},
		{
			name:        "README.txt",
			files:       map[string]string{"README.txt": "text readme"},
			wantContent: "text readme",
			wantExact:   true,
		},
		{
			name:        "no README returns empty string",
			files:       map[string]string{"main.tf": "resource {}"},
			wantContent: "",
			wantExact:   true,
		},
		{
			name: "README in subdirectory is ignored",
			files: map[string]string{
				"main.tf":           "resource {}",
				"subdir/README.md":  "nested readme",
			},
			wantContent: "",
			wantExact:   true,
		},
		{
			name: "README.md preferred over other files",
			files: map[string]string{
				"main.tf":   "resource {}",
				"README.md": "preferred readme",
				"README":    "other readme",
			},
			wantContent: "preferred readme",
		},
		{
			name: "multiple files, only readme extracted",
			files: map[string]string{
				"main.tf":      "resource {}",
				"variables.tf": "variable {}",
				"README.md":    "# Docs",
			},
			wantContent: "# Docs",
			wantExact:   true,
		},
		{
			name:    "not gzip data returns error",
			files:   nil, // special-cased below
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reader *bytes.Reader
			if tt.name == "not gzip data returns error" {
				reader = bytes.NewReader([]byte("not gzip data"))
			} else {
				data := makeTarGz(t, tt.files)
				reader = bytes.NewReader(data)
			}

			got, err := ExtractReadme(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractReadme() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if tt.wantExact {
				if got != tt.wantContent {
					t.Errorf("ExtractReadme() = %q, want %q", got, tt.wantContent)
				}
			} else {
				if !strings.Contains(got, tt.wantContent) {
					t.Errorf("ExtractReadme() = %q, want substring %q", got, tt.wantContent)
				}
			}
		})
	}
}

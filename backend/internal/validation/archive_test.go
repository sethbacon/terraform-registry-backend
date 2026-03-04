package validation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// makeTarGz creates an in-memory tar.gz archive from a map of filename → content.
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestValidateArchive(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		maxSize int64
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid single file",
			data:    makeTarGz(t, map[string]string{"main.tf": "resource \"null_resource\" \"a\" {}"}),
			wantErr: false,
		},
		{
			name:    "valid multiple files",
			data:    makeTarGz(t, map[string]string{"main.tf": "content", "variables.tf": "vars", "outputs.tf": "outs"}),
			wantErr: false,
		},
		{
			name:    "not gzip",
			data:    []byte("this is not gzip data"),
			wantErr: true,
		},
		{
			name:    "empty bytes",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "path traversal with dotdot",
			data:    makeTarGz(t, map[string]string{"../etc/passwd": "root:x:0:0"}),
			wantErr: true,
		},
		{
			name:    "git directory",
			data:    makeTarGz(t, map[string]string{".git/config": "[core]"}),
			wantErr: true,
		},
		{
			name:    "hidden file allowed",
			data:    makeTarGz(t, map[string]string{".terraform.lock.hcl": "provider lock"}),
			wantErr: false,
		},
		{
			name:    "exceeds custom max size",
			data:    makeTarGz(t, map[string]string{"big.tf": "x"}),
			maxSize: 1, // 1 byte limit
			wantErr: true,
		},
		{
			name:    "uses default max size when zero",
			data:    makeTarGz(t, map[string]string{"main.tf": "content"}),
			maxSize: 0, // should use MaxArchiveSize default
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArchive(bytes.NewReader(tt.data), tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArchive() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"normal relative path", "modules/main.tf", false},
		{"nested relative path", "subdir/nested/file.tf", false},
		{"dot directory is ok", ".", false},
		{"hidden non-git file", ".terraform.lock.hcl", false},
		{"path traversal", "../outside", true},
		// Absolute path: use a platform-appropriate check. On Windows filepath.Clean
		// converts "/" to "\" which is NOT IsAbs (no drive letter). Use a real
		// Windows absolute path to cover the check; on Unix both forms are absolute.
		{"absolute path with drive letter", `C:\windows\system32\drivers\etc\hosts`, true},
		{"git directory", ".git/config", true},
		// .gitmodules starts with ".git" so it IS rejected by the current implementation
		{"git adjacent file rejected", ".gitmodules", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

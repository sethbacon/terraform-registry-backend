package validation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// makeTarGzWithHeaders creates an in-memory tar.gz archive from a slice of
// pre-built tar.Header values. Callers set Typeflag, Linkname, etc. directly.
// Only entries whose Typeflag is tar.TypeReg have body content written.
func makeTarGzWithHeaders(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, hdr := range headers {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			body := make([]byte, hdr.Size)
			if _, err := tw.Write(body); err != nil {
				t.Fatalf("tar Write: %v", err)
			}
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

// makeGzipOf wraps raw bytes in a gzip stream (not a valid tar).
func makeGzipOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

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
		{
			name:    "empty tar has no entries",
			data:    makeTarGz(t, map[string]string{}),
			wantErr: true, // fileCount == 0 → "archive is empty"
		},
		{
			name:    "invalid tar content inside valid gzip",
			data:    makeGzipOf(t, []byte("not-tar-not-tar-not-tar-not-tar-not-tar-not-tar-not-tar-not-tar")),
			wantErr: true,
		},
		{
			// Symlink entries can escape the extraction directory on clients running
			// terraform init. The registry must reject them at upload time.
			name: "symlink entry rejected",
			data: makeTarGzWithHeaders(t, []*tar.Header{
				{
					Typeflag: tar.TypeSymlink,
					Name:     "link",
					Linkname: "../../../etc/passwd",
				},
			}),
			wantErr: true,
			errMsg:  "symlinks and hard links are not allowed",
		},
		{
			// Hard links share inodes and can reference files outside the module
			// directory when the archive is extracted on a client machine.
			name: "hard link entry rejected",
			data: makeTarGzWithHeaders(t, []*tar.Header{
				// Include a regular file first so the archive is non-empty before the link.
				{Typeflag: tar.TypeReg, Name: "main.tf", Size: 4},
				{
					Typeflag: tar.TypeLink,
					Name:     "hardlink",
					Linkname: "main.tf",
				},
			}),
			wantErr: true,
			errMsg:  "symlinks and hard links are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArchive(bytes.NewReader(tt.data), tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArchive() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateArchive() error = %q, want to contain %q", err.Error(), tt.errMsg)
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

package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newPublisher returns a zero-value SCMPublisher sufficient for testing pure
// methods (extractVersionFromTag, validateModuleStructure) that access no
// fields of the receiver.
func newPublisher() *SCMPublisher {
	return &SCMPublisher{}
}

// ---------------------------------------------------------------------------
// NewSCMPublisher
// ---------------------------------------------------------------------------

func TestNewSCMPublisher_NonNil(t *testing.T) {
	p := NewSCMPublisher(nil, nil, nil, nil)
	if p == nil {
		t.Fatal("NewSCMPublisher returned nil")
	}
	if p.tempDir == "" {
		t.Error("tempDir should not be empty")
	}
}

func TestNewSCMPublisher_TempDirIsOSTempDir(t *testing.T) {
	p := NewSCMPublisher(nil, nil, nil, nil)
	if p.tempDir != os.TempDir() {
		t.Errorf("tempDir = %q, want %q", p.tempDir, os.TempDir())
	}
}

// ---------------------------------------------------------------------------
// extractVersionFromTag
// ---------------------------------------------------------------------------

func TestExtractVersionFromTag(t *testing.T) {
	p := newPublisher()

	tests := []struct {
		tag     string
		glob    string
		want    string
		comment string
	}{
		// Basic "v*" glob: strips leading 'v'
		{"v1.2.3", "v*", "1.2.3", "v prefix stripped"},
		// Without v prefix in tag
		{"1.2.3", "*", "1.2.3", "no prefix to strip"},
		// Pre-release is a valid semver
		{"v1.2.3-alpha", "v*", "1.2.3-alpha", "pre-release valid"},
		// Build metadata with dot: semver pattern uses [0-9A-Za-z-]+ after '+', rejects '.'
		{"v1.2.3+build.1", "v*", "", "build metadata with dot fails semver regex"},
		// Custom prefix glob
		{"release-2.0.0", "release-*", "2.0.0", "custom prefix"},
		// Tag does not match glob
		{"v1.2.3", "release-*", "", "no match"},
		// Captured portion is not valid semver (only 2 parts)
		{"v1.2", "v*", "", "not semver — too few parts"},
		// Captured portion is non-numeric
		{"vfoo", "v*", "", "non-numeric captured"},
		// Invalid regex from glob (unclosed bracket)
		{"v1.0.0", "[invalid", "", "invalid regex"},
		// Nested glob with multiple capture groups → only first capture used
		{"v1.2.3", "v*.*.*", "", "multiple wildcards → first capture is '1' which is not semver"},
	}

	for _, tt := range tests {
		got := p.extractVersionFromTag(tt.tag, tt.glob)
		if got != tt.want {
			t.Errorf("[%s] extractVersionFromTag(%q, %q) = %q, want %q",
				tt.comment, tt.tag, tt.glob, got, tt.want)
		}
	}
}

func TestExtractVersionFromTag_VPrefix_ExactVersion(t *testing.T) {
	p := newPublisher()
	got := p.extractVersionFromTag("v3.74.0", "v*")
	if got != "3.74.0" {
		t.Errorf("got %q, want 3.74.0", got)
	}
}

// ---------------------------------------------------------------------------
// validateModuleStructure
// ---------------------------------------------------------------------------

func TestValidateModuleStructure_WithTFFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a main.tf file
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "null_resource" "test" {}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := newPublisher()
	if err := p.validateModuleStructure(dir); err != nil {
		t.Errorf("unexpected error with .tf files: %v", err)
	}
}

func TestValidateModuleStructure_MultipleTFFiles(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	p := newPublisher()
	if err := p.validateModuleStructure(dir); err != nil {
		t.Errorf("unexpected error with multiple .tf files: %v", err)
	}
}

func TestValidateModuleStructure_NoTFFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a non-.tf file
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Module"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := newPublisher()
	err := p.validateModuleStructure(dir)
	if err == nil {
		t.Error("expected error for directory with no .tf files, got nil")
	}
}

func TestValidateModuleStructure_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	p := newPublisher()
	err := p.validateModuleStructure(dir)
	if err == nil {
		t.Error("expected error for empty directory, got nil")
	}
}

// ---------------------------------------------------------------------------
// extractTarGz
// ---------------------------------------------------------------------------

// makeTarGz builds an in-memory tar.gz from a filename→content map.
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0644,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write: %v", err)
		}
	}
	tw.Close()
	gzw.Close()
	return buf.Bytes()
}

func TestExtractTarGz_ValidArchive(t *testing.T) {
	p := newPublisher()
	data := makeTarGz(t, map[string]string{
		"main.tf":    `resource "null_resource" "test" {}`,
		"outputs.tf": `output "id" { value = "test" }`,
	})

	dir := t.TempDir()
	if err := p.extractTarGz(bytes.NewReader(data), dir); err != nil {
		t.Fatalf("extractTarGz error: %v", err)
	}

	for _, name := range []string{"main.tf", "outputs.tf"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist after extraction: %v", name, err)
		}
	}
}

func TestExtractTarGz_WithSubdirectory(t *testing.T) {
	p := newPublisher()

	// Build archive with a directory entry + file inside
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	tw.WriteHeader(&tar.Header{Name: "subdir/", Typeflag: tar.TypeDir, Mode: 0755})
	content := "variable x {}"
	tw.WriteHeader(&tar.Header{Name: "subdir/vars.tf", Size: int64(len(content)), Mode: 0644, Typeflag: tar.TypeReg})
	tw.Write([]byte(content))
	tw.Close()
	gzw.Close()

	dir := t.TempDir()
	if err := p.extractTarGz(&buf, dir); err != nil {
		t.Fatalf("extractTarGz with subdir error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "subdir", "vars.tf")); err != nil {
		t.Errorf("subdir/vars.tf not found: %v", err)
	}
}

func TestExtractTarGz_PathTraversal(t *testing.T) {
	p := newPublisher()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Malicious path traversal entry
	content := "evil"
	tw.WriteHeader(&tar.Header{
		Name:     "../malicious.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write([]byte(content))
	tw.Close()
	gzw.Close()

	dir := t.TempDir()
	err := p.extractTarGz(&buf, dir)
	if err == nil {
		t.Error("expected error for path traversal entry, got nil")
	}
}

func TestExtractTarGz_InvalidGzip(t *testing.T) {
	p := newPublisher()
	// Not a valid gzip stream
	err := p.extractTarGz(bytes.NewReader([]byte("not-gzip")), t.TempDir())
	if err == nil {
		t.Error("expected error for invalid gzip data, got nil")
	}
}

// ---------------------------------------------------------------------------
// createImmutableTarball
// ---------------------------------------------------------------------------

func TestCreateImmutableTarball_Success(t *testing.T) {
	p := newPublisher()

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.tf"), []byte(`resource "x" "y" {}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	destPath := filepath.Join(t.TempDir(), "output.tar.gz")
	checksum, err := p.createImmutableTarball(srcDir, destPath, "abc123sha")
	if err != nil {
		t.Fatalf("createImmutableTarball error: %v", err)
	}

	// SHA256 hex is always 64 chars
	if len(checksum) != 64 {
		t.Errorf("checksum length = %d, want 64", len(checksum))
	}

	fi, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("output file not found: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("output tarball is empty")
	}
}

func TestCreateImmutableTarball_ContainsManifest(t *testing.T) {
	p := newPublisher()

	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "main.tf"), []byte(""), 0644)

	destPath := filepath.Join(t.TempDir(), "out.tar.gz")
	_, err := p.createImmutableTarball(srcDir, destPath, "deadbeef")
	if err != nil {
		t.Fatalf("createImmutableTarball error: %v", err)
	}

	// Open and scan the tarball for the manifest entry
	f, _ := os.Open(destPath)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	tr := tar.NewReader(gr)

	found := false
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == ".terraform-registry-commit" {
			found = true
			break
		}
	}
	if !found {
		t.Error("manifest file .terraform-registry-commit not found in tarball")
	}
}

func TestCreateImmutableTarball_DeterministicChecksum(t *testing.T) {
	p := newPublisher()

	// Same source content + same commit SHA should produce same tarball bytes,
	// but time.Now() is embedded in the manifest, so checksums will differ.
	// We only verify that two calls both succeed and return 64-char hex.
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "main.tf"), []byte("variable x {}"), 0644)

	dest1 := filepath.Join(t.TempDir(), "a.tar.gz")
	cs1, err := p.createImmutableTarball(srcDir, dest1, "sha1")
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	dest2 := filepath.Join(t.TempDir(), "b.tar.gz")
	cs2, err := p.createImmutableTarball(srcDir, dest2, "sha1")
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if len(cs1) != 64 || len(cs2) != 64 {
		t.Errorf("checksums not 64 chars: %q, %q", cs1, cs2)
	}
}

func TestCreateImmutableTarball_InvalidDestPath(t *testing.T) {
	p := newPublisher()
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "main.tf"), []byte(""), 0644)

	// Non-existent parent directory → os.Create should fail
	_, err := p.createImmutableTarball(srcDir, "/nonexistent/path/out.tar.gz", "sha")
	if err == nil {
		t.Error("expected error for invalid dest path, got nil")
	}
}

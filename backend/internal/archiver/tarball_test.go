package archiver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// buildTarGz creates an in-memory tar.gz archive from a map of path→content.
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
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

func buildTarGzWithDir(t *testing.T, dirEntry string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Write the directory entry
	hdr := &tar.Header{
		Name:     dirEntry,
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader dir: %v", err)
	}

	for name, content := range files {
		fhdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(fhdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
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

// ---------------------------------------------------------------------------
// ExtractTarGz
// ---------------------------------------------------------------------------

func TestExtractTarGz_Simple(t *testing.T) {
	data := buildTarGz(t, map[string]string{
		"main.tf":    `resource "null_resource" "x" {}`,
		"outputs.tf": `output "x" { value = "y" }`,
	})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	for _, name := range []string{"main.tf", "outputs.tf"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestExtractTarGz_WithSubDirectory(t *testing.T) {
	data := buildTarGzWithDir(t, "module-v1.2.3/", map[string]string{
		"module-v1.2.3/main.tf":    `variable "x" {}`,
		"module-v1.2.3/outputs.tf": `output "x" { value = var.x }`,
	})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "module-v1.2.3", "main.tf")); err != nil {
		t.Errorf("expected nested file to exist: %v", err)
	}
}

func TestExtractTarGz_Empty(t *testing.T) {
	data := buildTarGz(t, map[string]string{})
	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("empty archive should not error: %v", err)
	}
}

func TestExtractTarGz_InvalidGzip(t *testing.T) {
	if err := ExtractTarGz(bytes.NewReader([]byte("not gzip")), t.TempDir()); err == nil {
		t.Error("expected error for invalid gzip, got nil")
	}
}

func TestExtractTarGz_PathTraversal(t *testing.T) {
	// Build archive with a path traversal entry
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := "evil"
	_ = tw.WriteHeader(&tar.Header{
		Name: "../../../evil.txt",
		Mode: 0644,
		Size: int64(len(content)),
	})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	_ = gw.Close()

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest); err == nil {
		t.Error("expected path traversal error, got nil")
	}
}

func TestExtractTarGz_FileContents(t *testing.T) {
	const tfContent = `variable "region" { default = "us-east-1" }`
	data := buildTarGz(t, map[string]string{"variables.tf": tfContent})

	dest := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "variables.tf"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != tfContent {
		t.Errorf("file content = %q, want %q", got, tfContent)
	}
}

// ---------------------------------------------------------------------------
// FindModuleRoot
// ---------------------------------------------------------------------------

func TestFindModuleRoot_NoSubdir(t *testing.T) {
	dir := t.TempDir()
	// Write a .tf file directly in the directory
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`variable "x" {}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q", got, dir)
	}
}

func TestFindModuleRoot_SingleSubdirWithTf(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "terraform-module-abc123")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "main.tf"), []byte(`variable "x" {}`), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != sub {
		t.Errorf("FindModuleRoot = %q, want %q", got, sub)
	}
}

func TestFindModuleRoot_SingleSubdirWithoutTf(t *testing.T) {
	// Single subdirectory but no .tf files — should return the root
	dir := t.TempDir()
	sub := filepath.Join(dir, "not-a-module")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "README.md"), []byte("# readme"), 0644); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q (should not unwrap when no .tf files)", got, dir)
	}
}

func TestFindModuleRoot_MultipleEntries(t *testing.T) {
	// Multiple entries — should return the root unchanged
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "b"), 0755); err != nil {
		t.Fatal(err)
	}
	got := FindModuleRoot(dir)
	if got != dir {
		t.Errorf("FindModuleRoot = %q, want %q", got, dir)
	}
}

func TestFindModuleRoot_NonExistentDir(t *testing.T) {
	got := FindModuleRoot("/nonexistent/path/xyz")
	if got != "/nonexistent/path/xyz" {
		t.Errorf("FindModuleRoot for non-existent path = %q, want original path", got)
	}
}

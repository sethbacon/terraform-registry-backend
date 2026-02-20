package local

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// newTestStorage creates a LocalStorage backed by a temporary directory.
// The temp dir is cleaned up when the test ends.
func newTestStorage(t *testing.T, serveDirectly bool, baseURL string) *LocalStorage {
	t.Helper()
	dir, err := os.MkdirTemp("", "local-storage-test-*")
	if err != nil {
		t.Fatal("MkdirTemp:", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	cfg := &config.LocalStorageConfig{
		BasePath:      dir,
		ServeDirectly: serveDirectly,
	}
	s, err := New(cfg, baseURL)
	if err != nil {
		t.Fatal("New:", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew_CreatesDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "new-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	subDir := filepath.Join(dir, "a", "b", "c")
	cfg := &config.LocalStorageConfig{BasePath: subDir}
	_, err = New(cfg, "http://localhost")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Error("New() did not create base directory")
	}
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

func TestUpload(t *testing.T) {
	s := newTestStorage(t, false, "http://localhost")
	ctx := context.Background()

	content := "hello, world"
	result, err := s.Upload(ctx, "test/hello.txt", strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Upload() error: %v", err)
	}

	if result.Path != "test/hello.txt" {
		t.Errorf("Path = %q, want test/hello.txt", result.Path)
	}
	if result.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", result.Size, len(content))
	}
	if len(result.Checksum) != 64 {
		t.Errorf("Checksum len = %d, want 64 (SHA256 hex)", len(result.Checksum))
	}
}

func TestUpload_CreatesSubdirectories(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	_, err := s.Upload(ctx, "deep/nested/path/file.bin", strings.NewReader("data"), 4)
	if err != nil {
		t.Fatalf("Upload() error for deep path: %v", err)
	}

	fullPath := filepath.Join(s.basePath, "deep", "nested", "path", "file.bin")
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Error("Upload() did not create file at nested path")
	}
}

func TestUpload_ChecksumConsistency(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	content := "consistent data"
	r1, _ := s.Upload(ctx, "file1.txt", strings.NewReader(content), int64(len(content)))
	// Delete the file so we can upload again to the same path
	s.Delete(ctx, "file1.txt")
	r2, _ := s.Upload(ctx, "file1.txt", strings.NewReader(content), int64(len(content)))

	if r1.Checksum != r2.Checksum {
		t.Errorf("same content produced different checksums: %q vs %q", r1.Checksum, r2.Checksum)
	}
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func TestDownload(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	want := "download me"
	if _, err := s.Upload(ctx, "dl.txt", strings.NewReader(want), int64(len(want))); err != nil {
		t.Fatal("Upload:", err)
	}

	rc, err := s.Download(ctx, "dl.txt")
	if err != nil {
		t.Fatalf("Download() error: %v", err)
	}
	defer rc.Close()

	data, _ := io.ReadAll(rc)
	if string(data) != want {
		t.Errorf("Download() content = %q, want %q", string(data), want)
	}
}

func TestDownload_NotFound(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	_, err := s.Download(ctx, "nonexistent.txt")
	if err == nil {
		t.Error("Download() expected error for missing file, got nil")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestDelete(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	if _, err := s.Upload(ctx, "to-delete.txt", strings.NewReader("bye"), 3); err != nil {
		t.Fatal("Upload:", err)
	}

	if err := s.Delete(ctx, "to-delete.txt"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	exists, _ := s.Exists(ctx, "to-delete.txt")
	if exists {
		t.Error("Delete() file still exists after deletion")
	}
}

func TestDelete_NonExistentFile(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	// Deleting a file that doesn't exist should be a no-op (no error).
	if err := s.Delete(ctx, "does-not-exist.txt"); err != nil {
		t.Errorf("Delete() error for non-existent file: %v (want nil)", err)
	}
}

func TestDelete_CleansUpEmptyParentDirs(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	// Upload to a subdirectory, then delete and confirm the empty subdir is cleaned.
	if _, err := s.Upload(ctx, "sub/leaf.txt", strings.NewReader("x"), 1); err != nil {
		t.Fatal("Upload:", err)
	}

	if err := s.Delete(ctx, "sub/leaf.txt"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	subDir := filepath.Join(s.basePath, "sub")
	if _, err := os.Stat(subDir); !os.IsNotExist(err) {
		t.Error("Delete() should clean up empty parent directory 'sub'")
	}
}

// ---------------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------------

func TestExists(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	ok, err := s.Exists(ctx, "no-such.txt")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if ok {
		t.Error("Exists() = true for non-existent file, want false")
	}

	if _, err := s.Upload(ctx, "yes.txt", strings.NewReader("data"), 4); err != nil {
		t.Fatal("Upload:", err)
	}

	ok, err = s.Exists(ctx, "yes.txt")
	if err != nil {
		t.Fatalf("Exists() error after upload: %v", err)
	}
	if !ok {
		t.Error("Exists() = false for existing file, want true")
	}
}

// ---------------------------------------------------------------------------
// GetURL
// ---------------------------------------------------------------------------

func TestGetURL_ServeDirectly(t *testing.T) {
	s := newTestStorage(t, true, "http://registry.example.com")
	ctx := context.Background()

	if _, err := s.Upload(ctx, "providers/foo/1.0.0.zip", strings.NewReader("data"), 4); err != nil {
		t.Fatal("Upload:", err)
	}

	url, err := s.GetURL(ctx, "providers/foo/1.0.0.zip", time.Hour)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	want := "http://registry.example.com/v1/files/providers/foo/1.0.0.zip"
	if url != want {
		t.Errorf("GetURL() = %q, want %q", url, want)
	}
}

func TestGetURL_LocalFile(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	if _, err := s.Upload(ctx, "myfile.txt", strings.NewReader("x"), 1); err != nil {
		t.Fatal("Upload:", err)
	}

	url, err := s.GetURL(ctx, "myfile.txt", time.Hour)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	if !strings.HasPrefix(url, "file://") {
		t.Errorf("GetURL() = %q, want to start with file://", url)
	}
	if !strings.Contains(url, "myfile.txt") {
		t.Errorf("GetURL() = %q, want to contain myfile.txt", url)
	}
}

func TestGetURL_NotFound(t *testing.T) {
	s := newTestStorage(t, true, "http://example.com")
	ctx := context.Background()

	_, err := s.GetURL(ctx, "missing.txt", time.Hour)
	if err == nil {
		t.Error("GetURL() expected error for missing file, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetMetadata
// ---------------------------------------------------------------------------

func TestGetMetadata(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	content := []byte("metadata test content")
	if _, err := s.Upload(ctx, "meta.txt", bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal("Upload:", err)
	}

	meta, err := s.GetMetadata(ctx, "meta.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}

	if meta.Path != "meta.txt" {
		t.Errorf("Path = %q, want meta.txt", meta.Path)
	}
	if meta.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", meta.Size, len(content))
	}
	if len(meta.Checksum) != 64 {
		t.Errorf("Checksum len = %d, want 64", len(meta.Checksum))
	}
	if meta.LastModified.IsZero() {
		t.Error("LastModified should not be zero")
	}
}

func TestGetMetadata_NotFound(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	_, err := s.GetMetadata(ctx, "not-here.txt")
	if err == nil {
		t.Error("GetMetadata() expected error for missing file, got nil")
	}
}

func TestGetMetadata_ChecksumMatchesUpload(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	content := "checksum consistency check"
	uploadResult, err := s.Upload(ctx, "cksum.txt", strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal("Upload:", err)
	}

	meta, err := s.GetMetadata(ctx, "cksum.txt")
	if err != nil {
		t.Fatal("GetMetadata:", err)
	}

	if meta.Checksum != uploadResult.Checksum {
		t.Errorf("GetMetadata checksum %q != Upload checksum %q", meta.Checksum, uploadResult.Checksum)
	}
}

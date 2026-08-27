package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage/urlsign"
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

	raw, err := s.GetURL(ctx, "providers/foo/1.0.0.zip", time.Hour)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}

	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatalf("GetURL() returned an unparseable URL %q: %v", raw, err)
	}
	if got, want := u.Scheme+"://"+u.Host+u.Path, "http://registry.example.com/v1/files/providers/foo/1.0.0.zip"; got != want {
		t.Errorf("GetURL() path = %q, want %q", got, want)
	}

	// SIGNED (#973). GET /v1/files/*filepath carries no authentication
	// middleware, so an unsigned URL here is an anonymously fetchable archive.
	// This asserts the parameters are present AND that they verify -- present
	// but wrong would satisfy a existence check while serving nothing.
	if err := urlsign.Verify(
		"providers/foo/1.0.0.zip",
		u.Query().Get(urlsign.ParamExpires),
		u.Query().Get(urlsign.ParamSignature),
		time.Now(),
	); err != nil {
		t.Errorf("GetURL() produced a URL that does not verify: %v (url %q)", err, raw)
	}
}

// TestGetURL_SignatureIsBoundToTheKey — #973.
//
// A signature that authorises ANY path is not a signature. The route serves
// whatever key it is handed, so if the MAC did not cover the path, one legitimate
// download URL would unlock every artifact in storage.
func TestGetURL_SignatureIsBoundToTheKey(t *testing.T) {
	s := newTestStorage(t, true, "http://registry.example.com")
	ctx := context.Background()

	for _, p := range []string{"providers/foo/1.0.0.zip", "modules/acme/vpc/aws/2.0.0.tar.gz"} {
		if _, err := s.Upload(ctx, p, strings.NewReader("data"), 4); err != nil {
			t.Fatal("Upload:", err)
		}
	}

	raw, err := s.GetURL(ctx, "providers/foo/1.0.0.zip", time.Hour)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The same expires+sig, replayed against a different object.
	if err := urlsign.Verify(
		"modules/acme/vpc/aws/2.0.0.tar.gz",
		u.Query().Get(urlsign.ParamExpires),
		u.Query().Get(urlsign.ParamSignature),
		time.Now(),
	); err == nil {
		t.Error("a signature minted for providers/foo/1.0.0.zip also authorised " +
			"modules/acme/vpc/aws/2.0.0.tar.gz -- the MAC does not cover the path, so one " +
			"download URL unlocks all of storage")
	}
}

// TestGetURL_TTLIsHonoured — #973.
//
// The ttl argument was accepted and ignored before signing existed. Every caller
// passes one, so a URL that never expires is a permanent anonymous credential
// handed out on every download.
func TestGetURL_TTLIsHonoured(t *testing.T) {
	s := newTestStorage(t, true, "http://registry.example.com")
	ctx := context.Background()
	const key = "providers/foo/1.0.0.zip"

	if _, err := s.Upload(ctx, key, strings.NewReader("data"), 4); err != nil {
		t.Fatal("Upload:", err)
	}
	raw, err := s.GetURL(ctx, key, time.Minute)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	exp, sig := u.Query().Get(urlsign.ParamExpires), u.Query().Get(urlsign.ParamSignature)

	if err := urlsign.Verify(key, exp, sig, time.Now()); err != nil {
		t.Fatalf("valid now, but rejected: %v", err)
	}
	if err := urlsign.Verify(key, exp, sig, time.Now().Add(2*time.Minute)); !errors.Is(err, urlsign.ErrExpired) {
		t.Errorf("two minutes past a one-minute TTL: got %v, want ErrExpired", err)
	}
}

// TestGetURL_SurvivesVersionMetadataInTheKey — #973.
//
// Real keys carry '+' from build metadata (hashicorp/go-version accepts
// 1.0.0+build.5) and '~' from version strings. '+' means SPACE in a query
// string and is literal in a path, so an escaping mismatch between the signer
// and the verifier breaks exactly these artifacts and no others -- the shape of
// bug that ships green and fails on one customer's module.
func TestGetURL_SurvivesVersionMetadataInTheKey(t *testing.T) {
	s := newTestStorage(t, true, "http://registry.example.com")
	ctx := context.Background()

	for _, key := range []string{
		"modules/acme/vpc/aws/1.0.0+build.5.tar.gz",
		"modules/acme/vpc/aws/1.0.0~rc1.tar.gz",
		"providers/Acme/Foo/1.0.0/linux/amd64/terraform-provider-foo.zip",
	} {
		t.Run(key, func(t *testing.T) {
			if _, err := s.Upload(ctx, key, strings.NewReader("data"), 4); err != nil {
				t.Fatal("Upload:", err)
			}
			raw, err := s.GetURL(ctx, key, time.Hour)
			if err != nil {
				t.Fatalf("GetURL() error: %v", err)
			}
			u, err := neturl.Parse(raw)
			if err != nil {
				t.Fatalf("parse %q: %v", raw, err)
			}
			// What the handler sees: Gin decodes the path parameter, so the
			// verifier is handed the unescaped storage key. u.Path is the
			// decoded form, which models that exactly.
			decoded := strings.TrimPrefix(u.Path, "/v1/files/")
			if decoded != key {
				t.Fatalf("path did not round-trip: encoded %q decoded to %q, want %q", u.EscapedPath(), decoded, key)
			}
			if err := urlsign.Verify(decoded, u.Query().Get(urlsign.ParamExpires), u.Query().Get(urlsign.ParamSignature), time.Now()); err != nil {
				t.Errorf("signature does not verify against the decoded path: %v", err)
			}
		})
	}
}

// TestGetURL_NeverLeaksTheFilesystemPath — issue #751.
//
// This test previously asserted the OPPOSITE: that serve_directly=false
// produced a file:// URL. That value went straight into the X-Terraform-Get
// header of GET /v1/modules/.../download, a documented UNAUTHENTICATED
// endpoint, so every anonymous caller learned the deployment's absolute
// storage root. It was also unfetchable by a remote Terraform client, so the
// configuration was broken as well as leaky.
//
// Asserted for BOTH settings of the flag, because the leak only appeared in one
// of them and a test covering the default alone would never have seen it.
func TestGetURL_NeverLeaksTheFilesystemPath(t *testing.T) {
	for _, serveDirectly := range []bool{true, false} {
		t.Run(fmt.Sprintf("serve_directly=%v", serveDirectly), func(t *testing.T) {
			s := newTestStorage(t, serveDirectly, "https://registry.example.com")
			ctx := context.Background()

			if _, err := s.Upload(ctx, "modules/acme/vpc/aws/1.0.0.tar.gz",
				strings.NewReader("x"), 1); err != nil {
				t.Fatal("Upload:", err)
			}

			url, err := s.GetURL(ctx, "modules/acme/vpc/aws/1.0.0.tar.gz", time.Hour)
			if err != nil {
				t.Fatalf("GetURL() error: %v", err)
			}

			if strings.HasPrefix(url, "file://") {
				t.Errorf("GetURL() = %q — a file:// URL is handed to anonymous callers "+
					"in X-Terraform-Get and is not fetchable by a remote client", url)
			}
			// The storage root must not appear in a value sent to clients.
			if strings.Contains(url, s.basePath) {
				t.Errorf("GetURL() = %q leaks the storage root %q", url, s.basePath)
			}
			if !strings.HasPrefix(url, "https://registry.example.com/v1/files/") {
				t.Errorf("GetURL() = %q, want the API file-serving URL", url)
			}
			if !strings.Contains(url, "modules/acme/vpc/aws/1.0.0.tar.gz") {
				t.Errorf("GetURL() = %q, want it to reference the object key", url)
			}
		})
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

// TestGetMetadata_NoSidecar covers the code path where the .sha256 sidecar does
// not exist and GetMetadata must compute the checksum by reading the file.
func TestGetMetadata_NoSidecar(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	// Write the file directly (bypassing Upload so no .sha256 sidecar is created).
	content := []byte("no sidecar content")
	fullPath := filepath.Join(s.basePath, "no-sidecar.txt")
	if err := os.WriteFile(fullPath, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	meta, err := s.GetMetadata(ctx, "no-sidecar.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}

	if meta.Path != "no-sidecar.txt" {
		t.Errorf("Path = %q, want no-sidecar.txt", meta.Path)
	}
	if meta.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", meta.Size, len(content))
	}
	if len(meta.Checksum) != 64 {
		t.Errorf("Checksum len = %d, want 64", len(meta.Checksum))
	}
	// Verify the sidecar was created as a side effect.
	sidecarPath := fullPath + ".sha256"
	if _, err := os.Stat(sidecarPath); os.IsNotExist(err) {
		t.Error("sidecar .sha256 should have been created by GetMetadata")
	}
}

// ---------------------------------------------------------------------------
// safeJoin / path traversal
// ---------------------------------------------------------------------------

func TestSafeJoin_TraversalRejected(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	traversalPaths := []string{
		"../../etc/passwd",
		"modules/../../../etc/shadow",
		"a/b/c/../../../../secret",
	}
	for _, p := range traversalPaths {
		t.Run(p, func(t *testing.T) {
			_, err := s.Download(ctx, p)
			if err == nil {
				t.Errorf("Download(%q) expected error for traversal path, got nil", p)
			}
			_, err = s.Exists(ctx, p)
			if err == nil {
				t.Errorf("Exists(%q) expected error for traversal path, got nil", p)
			}
			_, err = s.GetMetadata(ctx, p)
			if err == nil {
				t.Errorf("GetMetadata(%q) expected error for traversal path, got nil", p)
			}
		})
	}
}

func TestSafeJoin_NormalPathAllowed(t *testing.T) {
	s := newTestStorage(t, false, "")
	ctx := context.Background()

	content := "hello"
	if _, err := s.Upload(ctx, "modules/foo/1.0.0/archive.tar.gz", strings.NewReader(content), int64(len(content))); err != nil {
		t.Fatal("Upload:", err)
	}

	ok, err := s.Exists(ctx, "modules/foo/1.0.0/archive.tar.gz")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !ok {
		t.Error("Exists() = false for normal nested path, want true")
	}
}

// TestNew_NewDirectory verifies New succeeds when the base path does not yet exist.
func TestNew_NewDirectory(t *testing.T) {
	parent, err := os.MkdirTemp("", "new-dir-test-*")
	if err != nil {
		t.Fatal("MkdirTemp:", err)
	}
	defer os.RemoveAll(parent)

	newPath := filepath.Join(parent, "subdir", "storage")
	cfg := &config.LocalStorageConfig{BasePath: newPath}
	s, err := New(cfg, "")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

// TestGetURL_FailsClosedWhenSigningFails — #973.
//
// The dangerous fallback here is not an error, it is a SUCCESS: returning the
// old unsigned URL when signing fails would reinstate the anonymous-fetch hole
// at exactly the moment something is already wrong, and every caller would
// carry on as though nothing happened. Nothing else reaches this branch, so
// without this test it is deletable with the suite still green.
func TestGetURL_FailsClosedWhenSigningFails(t *testing.T) {
	s := newTestStorage(t, true, "http://registry.example.com")
	ctx := context.Background()
	const key = "providers/foo/1.0.0.zip"

	if _, err := s.Upload(ctx, key, strings.NewReader("data"), 4); err != nil {
		t.Fatal("Upload:", err)
	}

	urlsign.SetSecretSourceForTest(t, func() (string, error) { return "", errors.New("no signing key") })

	got, err := s.GetURL(ctx, key, time.Hour)
	if err == nil {
		t.Fatalf("GetURL succeeded with no signing key and returned %q; "+
			"an unsigned URL is anonymously fetchable by anyone who can reach the deployment", got)
	}
	if got != "" {
		t.Errorf("GetURL returned %q alongside its error; a caller ignoring the error would serve an unsigned URL", got)
	}
}

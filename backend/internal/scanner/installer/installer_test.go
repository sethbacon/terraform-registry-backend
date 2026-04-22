package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildTarGz creates a tar.gz archive in memory with the given entries.
func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// checksumLine returns a "sha256  filename" line for the given data.
func checksumLine(data []byte, filename string) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) + "  " + filename
}

// stubBinary is a minimal shell script to act as a fake scanner binary.
var stubBinary = []byte("#!/bin/sh\necho stub-scanner\n")

// setupTestServer creates an httptest.Server that serves:
//   - /releases/latest and /releases/tags/vVERSION → release JSON
//   - /assets/<name> → archive or checksums file content
//
// Returns the server and a patched AssetSpec for use in tests.
func setupTestServer(t *testing.T, version string, archiveName, checksumsName string, archiveData, checksumsData []byte) (*httptest.Server, AssetSpec) {
	t.Helper()

	mux := http.NewServeMux()

	// We need to know the server URL before creating the release JSON,
	// so we use a two-pass approach: create the server first, then register handlers.
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	release := ghRelease{
		TagName: "v" + version,
		Assets: []ghAsset{
			{Name: archiveName, BrowserDownloadURL: server.URL + "/assets/" + archiveName},
			{Name: checksumsName, BrowserDownloadURL: server.URL + "/assets/" + checksumsName},
		},
	}

	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/assets/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archiveData)
	})
	mux.HandleFunc("/assets/"+checksumsName, func(w http.ResponseWriter, r *http.Request) {
		w.Write(checksumsData)
	})

	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^`+regexp_escape(archiveName)+`$`),
		ChecksumsPattern: mustCompile(t, `^`+regexp_escape(checksumsName)+`$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}

	return server, spec
}

func regexp_escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", `\.`), "+", `\+`)
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile pattern %q: %v", pattern, err)
	}
	return re
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestInstall_Trivy_Latest_Success(t *testing.T) {
	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"

	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.52.2", archiveName, checksumsName, archive, checksums)

	// Patch catalog for this test.
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	installDir := t.TempDir()

	result, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if result.Version != "0.52.2" {
		t.Errorf("version = %q, want 0.52.2", result.Version)
	}
	if result.BinaryPath == "" {
		t.Fatal("BinaryPath empty")
	}

	// Verify symlink resolves.
	target, err := os.Readlink(result.BinaryPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if !strings.Contains(target, "trivy-0.52.2") {
		t.Errorf("symlink target = %q, want to contain trivy-0.52.2", target)
	}

	// Verify binary is executable (skip on Windows where chmod is a no-op).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Mode()&0o111 == 0 {
			t.Error("binary is not executable")
		}
	}
}

func TestInstall_PinnedVersion_UsesVersionedAPI(t *testing.T) {
	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	var calledPath string
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	release := ghRelease{
		TagName: "v0.52.2",
		Assets: []ghAsset{
			{Name: archiveName, BrowserDownloadURL: server.URL + "/assets/" + archiveName},
			{Name: checksumsName, BrowserDownloadURL: server.URL + "/assets/" + checksumsName},
		},
	}

	mux.HandleFunc("/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not call /releases/latest when version is pinned")
		json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, checksumsName) {
			w.Write(checksums)
		} else {
			w.Write(archive)
		}
	})

	platform := runtime.GOOS + "/" + runtime.GOARCH
	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^`+regexp_escape(archiveName)+`$`),
		ChecksumsPattern: mustCompile(t, `^`+regexp_escape(checksumsName)+`$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
		HTTPClient: server.Client(),
	}, "trivy", "0.52.2")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if !strings.Contains(calledPath, "/releases/tags/v0.52.2") {
		t.Errorf("expected /releases/tags/v0.52.2, got %q", calledPath)
	}
}

func TestInstall_ChecksumMismatch(t *testing.T) {
	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})

	// Tamper: create wrong checksums
	wrongChecksum := strings.Repeat("aa", 32) + "  " + archiveName + "\n"

	server, spec := setupTestServer(t, "0.52.2", archiveName, checksumsName, archive, []byte(wrongChecksum))

	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	installDir := t.TempDir()
	_, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error should mention checksum: %v", err)
	}

	// No version dir should remain.
	matches, _ := filepath.Glob(filepath.Join(installDir, "trivy-*"))
	if len(matches) > 0 {
		t.Errorf("leftover dirs after checksum mismatch: %v", matches)
	}
}

func TestInstall_AssetNotFound_Arch(t *testing.T) {
	// Release has no asset matching the current arch
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	release := ghRelease{
		TagName: "v1.0.0",
		Assets:  []ghAsset{{Name: "trivy_1.0.0_Windows-64bit.tar.gz", BrowserDownloadURL: server.URL + "/nope"}},
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})

	platform := runtime.GOOS + "/" + runtime.GOARCH
	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^trivy_[\d.]+_Linux-64bit\.tar\.gz$`),
		ChecksumsPattern: mustCompile(t, `^trivy_[\d.]+_checksums\.txt$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "no matching asset") {
		t.Errorf("expected ErrAssetNotFound, got: %v", err)
	}
}

func TestInstall_NonHTTPS_Rejected(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	release := ghRelease{
		TagName: "v1.0.0",
		Assets: []ghAsset{
			{Name: "trivy_1.0.0_Linux-64bit.tar.gz", BrowserDownloadURL: "http://evil.example.com/file.tar.gz"},
			{Name: "trivy_1.0.0_checksums.txt", BrowserDownloadURL: server.URL + "/checksums"},
		},
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})

	platform := runtime.GOOS + "/" + runtime.GOARCH
	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^trivy_[\d.]+_Linux-64bit\.tar\.gz$`),
		ChecksumsPattern: mustCompile(t, `^trivy_[\d.]+_checksums\.txt$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected ErrNonHTTPS, got: %v", err)
	}
}

func TestInstall_ArchiveSizeCapExceeded(t *testing.T) {
	// Build an archive that exceeds the size cap (use a small cap for the test)
	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"

	// Create large archive data — we'll use a custom server that streams too much
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	release := ghRelease{
		TagName: "v0.52.2",
		Assets: []ghAsset{
			{Name: archiveName, BrowserDownloadURL: server.URL + "/assets/" + archiveName},
			{Name: checksumsName, BrowserDownloadURL: server.URL + "/assets/" + checksumsName},
		},
	}

	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/assets/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		// Stream more than maxArchiveSize bytes
		io.Copy(w, io.LimitReader(neverEndingReader{}, maxArchiveSize+1024))
	})
	mux.HandleFunc("/assets/"+checksumsName, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("deadbeef  " + archiveName))
	})

	platform := runtime.GOOS + "/" + runtime.GOARCH
	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^`+regexp_escape(archiveName)+`$`),
		ChecksumsPattern: mustCompile(t, `^`+regexp_escape(checksumsName)+`$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "exceeds size cap") {
		t.Errorf("expected ErrArchiveTooLarge, got: %v", err)
	}
}

// neverEndingReader is an io.Reader that always returns zero bytes.
type neverEndingReader struct{}

func (neverEndingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestInstall_PathTraversal_Tar(t *testing.T) {
	// Build a tar.gz with a "../evil" entry
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o755, Size: 4})
	tw.Write([]byte("evil"))
	tw.WriteHeader(&tar.Header{Name: "trivy", Mode: 0o755, Size: int64(len(stubBinary))})
	tw.Write(stubBinary)
	tw.Close()
	gw.Close()
	archive := buf.Bytes()

	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.52.2", archiveName, checksumsName, archive, checksums)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	installDir := t.TempDir()
	_, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "path-traversal") {
		t.Errorf("expected ErrPathTraversal, got: %v", err)
	}

	// Verify no file was written outside installDir
	if _, statErr := os.Stat(filepath.Join(installDir, "..", "evil")); statErr == nil {
		t.Error("path traversal succeeded: ../evil exists")
	}
}

func TestInstall_PathTraversal_Absolute(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	tw.WriteHeader(&tar.Header{Name: "/etc/passwd", Mode: 0o755, Size: 4})
	tw.Write([]byte("evil"))
	tw.WriteHeader(&tar.Header{Name: "trivy", Mode: 0o755, Size: int64(len(stubBinary))})
	tw.Write(stubBinary)
	tw.Close()
	gw.Close()
	archive := buf.Bytes()

	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.52.2", archiveName, checksumsName, archive, checksums)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "path-traversal") {
		t.Errorf("expected ErrPathTraversal, got: %v", err)
	}
}

func TestInstall_InstallDirNotWritable(t *testing.T) {
	_, _ = Install(context.Background(), InstallConfig{
		InstallDir: filepath.Join(t.TempDir(), "readonly", "nested"),
	}, "trivy", "")
	// On most systems MkdirAll will succeed for nested paths under TempDir,
	// so we test with an explicitly non-writable directory.
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows — cannot reliably make a non-writable directory")
	}

	roDir := t.TempDir()
	os.Chmod(roDir, 0o444)
	t.Cleanup(func() { os.Chmod(roDir, 0o755) })

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: filepath.Join(roDir, "subdir"),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Errorf("expected ErrInstallDirNotWritable, got: %v", err)
	}
}

func TestInstall_UnsupportedPlatform(t *testing.T) {
	_, err := Install(context.Background(), InstallConfig{
		InstallDir: t.TempDir(),
	}, "snyk", "")
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected ErrUnsupportedTool, got: %v", err)
	}
}

func TestInstall_ExistingVersionReinstall_Idempotent(t *testing.T) {
	archiveName := "trivy_0.52.2_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.52.2_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.52.2", archiveName, checksumsName, archive, checksums)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	installDir := t.TempDir()
	cfg := InstallConfig{InstallDir: installDir, HTTPClient: server.Client()}

	result1, err := Install(context.Background(), cfg, "trivy", "0.52.2")
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	result2, err := Install(context.Background(), cfg, "trivy", "0.52.2")
	if err != nil {
		t.Fatalf("second install: %v", err)
	}

	if result1.BinaryPath != result2.BinaryPath {
		t.Errorf("paths differ: %q vs %q", result1.BinaryPath, result2.BinaryPath)
	}

	// Symlink still works.
	target, err := os.Readlink(result2.BinaryPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if !strings.Contains(target, "trivy-0.52.2") {
		t.Errorf("symlink target = %q", target)
	}
}

func TestInstall_UpgradeSwapsSymlink(t *testing.T) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	installDir := t.TempDir()

	// Install v1
	archiveName1 := "trivy_1.0.0_Linux-64bit.tar.gz"
	checksumsName1 := "trivy_1.0.0_checksums.txt"
	archive1 := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums1 := []byte(checksumLine(archive1, archiveName1) + "\n")
	server1, spec1 := setupTestServer(t, "1.0.0", archiveName1, checksumsName1, archive1, checksums1)

	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec1}

	_, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server1.Client(),
	}, "trivy", "1.0.0")
	if err != nil {
		t.Fatalf("install v1: %v", err)
	}

	// Install v2
	archiveName2 := "trivy_2.0.0_Linux-64bit.tar.gz"
	checksumsName2 := "trivy_2.0.0_checksums.txt"
	archive2 := buildTarGz(t, map[string][]byte{"trivy": []byte("#!/bin/sh\necho v2\n")})
	checksums2 := []byte(checksumLine(archive2, archiveName2) + "\n")
	server2, spec2 := setupTestServer(t, "2.0.0", archiveName2, checksumsName2, archive2, checksums2)

	Catalog["trivy"] = map[string]AssetSpec{platform: spec2}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	result2, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server2.Client(),
	}, "trivy", "2.0.0")
	if err != nil {
		t.Fatalf("install v2: %v", err)
	}

	// Symlink points at v2.
	target, _ := os.Readlink(result2.BinaryPath)
	if !strings.Contains(target, "trivy-2.0.0") {
		t.Errorf("symlink should point at v2, got %q", target)
	}

	// v1 directory still on disk.
	if _, statErr := os.Stat(filepath.Join(installDir, "trivy-1.0.0")); os.IsNotExist(statErr) {
		t.Error("v1 directory was unexpectedly removed")
	}
}

func TestInstall_ContextCancelled(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	// Slow handler to allow cancellation
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	})

	platform := runtime.GOOS + "/" + runtime.GOARCH
	spec := AssetSpec{
		LatestReleaseAPI: server.URL + "/releases/latest",
		VersionedAPI:     server.URL + "/releases/tags/v%s",
		AssetPattern:     mustCompile(t, `^trivy_.*\.tar\.gz$`),
		ChecksumsPattern: mustCompile(t, `^trivy_.*_checksums\.txt$`),
		BinaryInArchive:  "trivy",
		ArchiveFormat:    "tar.gz",
	}
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	installDir := t.TempDir()
	_, err := Install(ctx, InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}

	// No partial files in install dir (temp dir is cleaned up in defer)
	entries, _ := os.ReadDir(installDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tmp-") {
			t.Errorf("leftover temp directory: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// Unit tests for helper functions
// ---------------------------------------------------------------------------

func TestLookup_UnsupportedTool(t *testing.T) {
	_, ok := Lookup("snyk", "linux", "amd64")
	if ok {
		t.Error("snyk should not be in catalog")
	}
}

func TestSupports(t *testing.T) {
	if !Supports("trivy") {
		t.Error("trivy should be supported")
	}
	if Supports("snyk") {
		t.Error("snyk should not be supported")
	}
	if Supports("custom") {
		t.Error("custom should not be supported")
	}
}

func TestSupportedTools(t *testing.T) {
	tools := SupportedTools()
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d: %v", len(tools), tools)
	}
	// Should be sorted.
	expected := []string{"checkov", "terrascan", "trivy"}
	for i, tool := range expected {
		if tools[i] != tool {
			t.Errorf("tools[%d] = %q, want %q", i, tools[i], tool)
		}
	}
}

func TestHandle_UnsupportedTool(t *testing.T) {
	ok, _, msg := Handle(context.Background(), "/tmp", nil, "snyk", "")
	if ok {
		t.Error("expected failure")
	}
	if !strings.Contains(msg, "not available") {
		t.Errorf("message should mention not available: %s", msg)
	}
}

func TestHandle_EmptyInstallDir(t *testing.T) {
	ok, _, msg := Handle(context.Background(), "", nil, "trivy", "")
	if ok {
		t.Error("expected failure")
	}
	if !strings.Contains(msg, "install_dir") {
		t.Errorf("message should mention install_dir: %s", msg)
	}
}

func TestHandle_Success(t *testing.T) {
	stub := func(ctx context.Context, cfg InstallConfig, tool, version string) (*Result, error) {
		return &Result{
			BinaryPath: "/app/scanners/trivy",
			Version:    "0.52.2",
			Sha256:     "abcd1234",
			SourceURL:  "https://example.com/trivy.tar.gz",
		}, nil
	}

	ok, result, msg := Handle(context.Background(), "/app/scanners", InstallFunc(stub), "trivy", "")
	if !ok {
		t.Fatalf("expected success, got error: %s", msg)
	}
	if result.Version != "0.52.2" {
		t.Errorf("version = %q", result.Version)
	}
}

func TestHandle_InstallerError(t *testing.T) {
	stub := func(ctx context.Context, cfg InstallConfig, tool, version string) (*Result, error) {
		return nil, ErrChecksumMismatch
	}

	ok, _, msg := Handle(context.Background(), "/app/scanners", InstallFunc(stub), "trivy", "")
	if ok {
		t.Error("expected failure")
	}
	if !strings.Contains(msg, "checksum") {
		t.Errorf("message should mention checksum: %s", msg)
	}
}

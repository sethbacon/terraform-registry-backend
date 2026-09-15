// symlink_smb_test.go covers issue #1079: the install created the stable
// {InstallDir}/{tool} symlink unconditionally, so on an Azure Files (SMB) share
// — which rejects symlinks unless mounted with mfsymlinks, an option Azure
// Container Apps cannot set — a fully downloaded, checksum- and
// signature-verified binary was thrown away at the very last step. The alias has
// to stay the recorded path wherever symlinks do work, so both filesystems are
// exercised here.
package installer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// errSymlinkRefused stands in for the EPERM an Azure Files mount returns.
var errSymlinkRefused = &fs.PathError{Op: "symlink", Path: "", Err: errors.New("operation not permitted")}

// swapSymlink replaces the package's symlink call for the duration of a test.
func swapSymlink(t *testing.T, fn func(string, string) error) {
	t.Helper()
	orig := symlinkFile
	symlinkFile = fn
	t.Cleanup(func() { symlinkFile = orig })
}

// requireSymlinks skips tests that need a symlink-capable filesystem. Probing
// beats a GOOS check: Windows allows symlinks under Developer Mode, and a Unix
// host can still have the install dir on a share that refuses them.
func requireSymlinks(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("filesystem does not support symlinks: %v", err)
	}
}

// On a filesystem with symlinks the alias stays the recorded path — that is what
// keeps a configured scanning.binary_path of {InstallDir}/{tool} valid across
// upgrades, so the #1079 fallback must not cost symlink-capable deployments it.
func TestStableAliasPath_PrefersSymlinkWhenSupported(t *testing.T) {
	requireSymlinks(t)
	installDir := t.TempDir()
	target := filepath.Join(installDir, "trivy-0.74.0", "trivy")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(target, stubBinary, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	linkPath := filepath.Join(installDir, "trivy")
	if got := stableAliasPath(installDir, "trivy", target); got != linkPath {
		t.Fatalf("stableAliasPath = %q, want the stable alias %q", got, linkPath)
	}
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		t.Fatalf("alias does not resolve: %v", err)
	}
	wantResolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("EvalSymlinks(target): %v", err)
	}
	if resolved != wantResolved {
		t.Errorf("alias resolves to %q, want %q", resolved, wantResolved)
	}
}

// The #1079 case: the share refuses the link, so the versioned path is recorded
// rather than the install failing.
func TestStableAliasPath_FallsBackWhenSymlinkRefused(t *testing.T) {
	installDir := t.TempDir()
	target := filepath.Join(installDir, "trivy-0.74.0", "trivy")
	swapSymlink(t, func(string, string) error { return errSymlinkRefused })

	if got := stableAliasPath(installDir, "trivy", target); got != target {
		t.Errorf("stableAliasPath = %q, want the versioned path %q", got, target)
	}
	if _, err := os.Lstat(filepath.Join(installDir, "trivy")); !os.IsNotExist(err) {
		t.Errorf("no alias should exist when the filesystem refuses symlinks: %v", err)
	}
}

// A link the filesystem accepts but cannot resolve would put a path in the
// database that no scan can execute, so it falls back too.
func TestStableAliasPath_FallsBackWhenLinkDoesNotResolve(t *testing.T) {
	installDir := t.TempDir()
	target := filepath.Join(installDir, "trivy-0.74.0", "trivy") // never created
	swapSymlink(t, os.Symlink)

	if got := stableAliasPath(installDir, "trivy", target); got != target {
		t.Errorf("stableAliasPath = %q, want the versioned path %q for a dangling link", got, target)
	}
}

// A refused link must leave an existing alias alone rather than stranding it on a
// half-installed version, so a symlink-capable host that hits a transient failure
// keeps serving the previous version.
func TestStableAliasPath_RefusedLinkLeavesExistingAliasIntact(t *testing.T) {
	requireSymlinks(t)
	installDir := t.TempDir()
	oldTarget := filepath.Join(installDir, "trivy-0.73.0", "trivy")
	if err := os.MkdirAll(filepath.Dir(oldTarget), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(oldTarget, stubBinary, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	linkPath := filepath.Join(installDir, "trivy")
	if err := os.Symlink(oldTarget, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	swapSymlink(t, func(string, string) error { return errSymlinkRefused })
	stableAliasPath(installDir, "trivy", filepath.Join(installDir, "trivy-0.74.0", "trivy"))

	got, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("existing alias was destroyed by a refused symlink: %v", err)
	}
	if got != oldTarget {
		t.Errorf("alias now points at %q, want the untouched %q", got, oldTarget)
	}
}

// End-to-end on a filesystem that behaves like Azure Files: the install must
// complete and report a path that exists, because Result.BinaryPath is what gets
// persisted as the version row and used as scanning.binary_path.
func TestInstall_SucceedsWhenFilesystemRejectsSymlinks(t *testing.T) {
	archiveName := "trivy_0.74.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.74.0_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.74.0", archiveName, checksumsName, archive, checksums)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	swapSymlink(t, func(string, string) error { return errSymlinkRefused })

	installDir := t.TempDir()
	res, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err != nil {
		t.Fatalf("install of a fully verified binary failed because the filesystem refused a symlink: %v", err)
	}

	versioned := filepath.Join(installDir, "trivy-0.74.0", "trivy")
	if res.BinaryPath != versioned {
		t.Errorf("BinaryPath = %q, want the versioned path %q", res.BinaryPath, versioned)
	}
	if _, statErr := os.Stat(res.BinaryPath); statErr != nil {
		t.Errorf("recorded BinaryPath does not exist on disk: %v", statErr)
	}
}

// The same install on a symlink-capable filesystem still records the alias.
func TestInstall_RecordsStableAliasWhenSymlinksWork(t *testing.T) {
	requireSymlinks(t)
	archiveName := "trivy_0.74.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.74.0_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.74.0", archiveName, checksumsName, archive, checksums)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	installDir := t.TempDir()
	res, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if want := filepath.Join(installDir, "trivy"); res.BinaryPath != want {
		t.Errorf("BinaryPath = %q, want the stable alias %q", res.BinaryPath, want)
	}
	if _, statErr := os.Stat(res.BinaryPath); statErr != nil {
		t.Errorf("recorded BinaryPath does not exist on disk: %v", statErr)
	}
}

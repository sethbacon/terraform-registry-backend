// chmod_smb_test.go covers issue #1076: an unconditional os.Chmod at the end of
// the install threw away a binary that had already been downloaded,
// checksum-verified, signature-verified and extracted. SMB/CIFS mounts (Azure
// Files) return EPERM for every chmod because permissions come from the mount's
// file_mode, so on Azure Container Apps — where an SMB share is the only way to
// get a persistent install dir — no scanner install could ever complete.
package installer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// errChmodRefused stands in for the EPERM an SMB mount returns.
var errChmodRefused = &fs.PathError{Op: "chmod", Path: "", Err: errors.New("operation not permitted")}

// swapChmod replaces the package's chmod for the duration of a test.
func swapChmod(t *testing.T, fn func(string, os.FileMode) error) {
	t.Helper()
	orig := chmodFile
	chmodFile = fn
	t.Cleanup(func() { chmodFile = orig })
}

func TestChmodFailureIsFatal(t *testing.T) {
	cases := []struct {
		name    string
		mode    os.FileMode
		statErr error
		want    bool
	}{
		{"already executable by owner", 0o755, nil, false},
		{"executable via mount file_mode", 0o777, nil, false},
		{"group execute only", 0o750, nil, false},
		{"other execute only", 0o645, nil, false},
		{"not executable at all", 0o644, nil, true},
		{"stat failed", 0o777, errors.New("boom"), true},
	}
	for _, c := range cases {
		if got := chmodFailureIsFatal(c.mode, c.statErr); got != c.want {
			t.Errorf("%s: chmodFailureIsFatal(%v, %v) = %t, want %t", c.name, c.mode, c.statErr, got, c.want)
		}
	}
}

// The #1076 case: chmod is refused but the mount already presents the file as
// executable, so the install must continue.
func TestEnsureExecutable_ChmodRefusedButAlreadyExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows — file permission bits do not carry an execute bit")
	}
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapChmod(t, func(string, os.FileMode) error { return errChmodRefused })

	if err := ensureExecutable(path); err != nil {
		t.Fatalf("ensureExecutable discarded an executable binary because chmod was refused: %v", err)
	}
}

// A refused chmod on a file that genuinely is not executable is still fatal —
// the fix must not turn the check into a no-op.
func TestEnsureExecutable_ChmodRefusedAndNotExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapChmod(t, func(string, os.FileMode) error { return errChmodRefused })

	if err := ensureExecutable(path); err == nil {
		t.Fatal("expected an error for a non-executable binary whose chmod was refused")
	}
}

func TestEnsureExecutable_StatFailureIsFatal(t *testing.T) {
	swapChmod(t, func(string, os.FileMode) error { return errChmodRefused })

	if err := ensureExecutable(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error when the target cannot be stat'd")
	}
}

func TestEnsureExecutable_ChmodSucceeds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows — file permission bits do not carry an execute bit")
	}
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ensureExecutable(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("binary is not executable after ensureExecutable: mode %v", fi.Mode().Perm())
	}
}

// End-to-end: a full verified install onto a filesystem that behaves like an
// Azure Files mount must succeed.
func TestInstall_SucceedsWhenFilesystemRejectsChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows — file permission bits do not carry an execute bit")
	}
	archiveName := "trivy_0.74.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.74.0_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.74.0", archiveName, checksumsName, archive, checksums)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	// An SMB mount refuses chmod while presenting the file as 0777 from the
	// mount's file_mode, so both halves have to be modelled.
	swapChmod(t, func(p string, _ os.FileMode) error {
		_ = os.Chmod(p, 0o777)
		return errChmodRefused
	})

	installDir := t.TempDir()
	res, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err != nil {
		t.Fatalf("install of a fully verified binary failed because the filesystem refused chmod: %v", err)
	}
	if res.Version != "0.74.0" {
		t.Errorf("version = %q, want 0.74.0", res.Version)
	}
	versioned := filepath.Join(installDir, "trivy-0.74.0", "trivy")
	if _, err := os.Stat(versioned); err != nil {
		t.Errorf("versioned binary missing after install: %v", err)
	}
}

// A genuinely fatal chmod failure must not leave an unrecorded binary on the
// volume: the install reports failure, so nothing writes a version row for it,
// and a later cleanup would be deciding about a directory the database has
// never heard of.
func TestInstall_FatalChmodRemovesVersionDir(t *testing.T) {
	archiveName := "trivy_0.74.0_Linux-64bit.tar.gz"
	checksumsName := "trivy_0.74.0_checksums.txt"
	archive := buildTarGz(t, map[string][]byte{"trivy": stubBinary})
	checksums := []byte(checksumLine(archive, archiveName) + "\n")

	server, spec := setupTestServer(t, "0.74.0", archiveName, checksumsName, archive, checksums)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	origCatalog := Catalog["trivy"]
	Catalog["trivy"] = map[string]AssetSpec{platform: spec}
	t.Cleanup(func() { Catalog["trivy"] = origCatalog })

	// Refused, and the file stays non-executable — the real "this binary is not
	// runnable" case.
	swapChmod(t, func(p string, _ os.FileMode) error {
		_ = os.Chmod(p, 0o644)
		return errChmodRefused
	})

	installDir := t.TempDir()
	_, err := Install(context.Background(), InstallConfig{
		InstallDir: installDir,
		HTTPClient: server.Client(),
	}, "trivy", "")
	if err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("expected a chmod error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(installDir, "trivy-0.74.0")); !os.IsNotExist(statErr) {
		t.Errorf("version directory survived a failed install: %v", statErr)
	}
}

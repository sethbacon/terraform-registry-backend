package installer

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Size caps to prevent zip-bomb / decompression-bomb DoS.
const (
	maxArchiveSize   = 500 << 20 // 500 MB
	maxFileSize      = 200 << 20 // 200 MB per extracted file
	maxChecksumsSize = 8 << 10   // 8 KB
)

// InstallConfig holds parameters for an Install call.
type InstallConfig struct {
	// InstallDir is the server-managed directory for scanner binaries.
	InstallDir string
	// Timeout caps the entire operation; default 5 minutes if zero.
	Timeout time.Duration
	// HTTPClient is optional; default is http.Client{Timeout: 5m}.
	HTTPClient *http.Client
}

// Result describes a successful installation.
type Result struct {
	BinaryPath string `json:"binary_path"`
	Version    string `json:"version"`
	Sha256     string `json:"sha256"`
	SourceURL  string `json:"source_url"`
}

// Typed errors for common failure modes.
var (
	ErrUnsupportedTool       = errors.New("scanner tool not supported for auto-install")
	ErrUnsupportedPlatform   = errors.New("server OS/architecture is not supported for this tool")
	ErrChecksumMismatch      = errors.New("downloaded archive does not match published checksum")
	ErrAssetNotFound         = errors.New("no matching asset for this OS/arch in the release")
	ErrInstallDirNotWritable = errors.New("install directory is not writable")
	ErrNonHTTPS              = errors.New("refusing to download from non-HTTPS URL")
	ErrArchiveTooLarge       = errors.New("archive exceeds size cap")
	ErrPathTraversal         = errors.New("archive contains a path-traversal entry")
)

// InstallFunc is the handler-facing type alias so tests can inject a stub.
type InstallFunc func(ctx context.Context, cfg InstallConfig, tool, pinnedVersion string) (*Result, error)

// ghRelease is the subset of the GitHub release JSON we need.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Install resolves, downloads, verifies, and installs a scanner binary.
func Install(ctx context.Context, cfg InstallConfig, tool, pinnedVersion string) (*Result, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	// 1. Verify install dir is writable.
	if err := ensureWritableDir(cfg.InstallDir); err != nil {
		return nil, err
	}

	// 2. Lookup catalog entry.
	spec, ok := Lookup(tool, runtime.GOOS, runtime.GOARCH)
	if !ok {
		if !Supports(tool) {
			return nil, fmt.Errorf("%w: %s (supported: %v)", ErrUnsupportedTool, tool, SupportedTools())
		}
		return nil, fmt.Errorf("%w: %s on %s/%s", ErrUnsupportedPlatform, tool, runtime.GOOS, runtime.GOARCH)
	}

	// 3. Resolve version via GitHub API.
	release, err := resolveRelease(ctx, client, spec, pinnedVersion)
	if err != nil {
		return nil, fmt.Errorf("resolve release: %w", err)
	}
	version := strings.TrimPrefix(release.TagName, "v")

	// 4. Find matching assets.
	var archiveAsset, checksumsAsset *ghAsset
	for i := range release.Assets {
		a := &release.Assets[i]
		if archiveAsset == nil && spec.AssetPattern.MatchString(a.Name) {
			archiveAsset = a
		}
		if checksumsAsset == nil && spec.ChecksumsPattern.MatchString(a.Name) {
			checksumsAsset = a
		}
	}
	if archiveAsset == nil || checksumsAsset == nil {
		return nil, fmt.Errorf("%w: tool=%s version=%s os=%s arch=%s", ErrAssetNotFound, tool, version, runtime.GOOS, runtime.GOARCH)
	}

	// 5. Validate HTTPS-only.
	if !strings.HasPrefix(archiveAsset.BrowserDownloadURL, "https://") {
		return nil, fmt.Errorf("%w: %s", ErrNonHTTPS, archiveAsset.BrowserDownloadURL)
	}
	if !strings.HasPrefix(checksumsAsset.BrowserDownloadURL, "https://") {
		return nil, fmt.Errorf("%w: %s", ErrNonHTTPS, checksumsAsset.BrowserDownloadURL)
	}

	// Create a temp dir for downloads.
	tmpDir, err := os.MkdirTemp(cfg.InstallDir, "tmp-install-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // always clean up temp

	// 6. Download archive with size cap.
	archivePath := filepath.Join(tmpDir, archiveAsset.Name)
	archiveHash, err := downloadFile(ctx, client, archiveAsset.BrowserDownloadURL, archivePath, maxArchiveSize)
	if err != nil {
		return nil, err
	}

	// Download checksums file.
	checksumsPath := filepath.Join(tmpDir, checksumsAsset.Name)
	_, err = downloadFile(ctx, client, checksumsAsset.BrowserDownloadURL, checksumsPath, maxChecksumsSize)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}

	// 7. Verify checksum.
	if err := verifyChecksum(checksumsPath, archiveAsset.Name, archiveHash); err != nil {
		return nil, err
	}

	// 8. Extract binary from archive.
	versionDir := filepath.Join(cfg.InstallDir, tool+"-"+version)
	if err := os.MkdirAll(versionDir, 0o755); err != nil { // #nosec G301 -- scanner binary directory needs execute permission
		return nil, fmt.Errorf("create version dir: %w", err)
	}

	targetBinary := filepath.Join(versionDir, filepath.Base(spec.BinaryInArchive))
	switch spec.ArchiveFormat {
	case "tar.gz":
		err = extractFromTarGz(archivePath, spec.BinaryInArchive, targetBinary)
	case "zip":
		err = extractFromZip(archivePath, spec.BinaryInArchive, targetBinary)
	default:
		err = fmt.Errorf("unsupported archive format: %s", spec.ArchiveFormat)
	}
	if err != nil {
		os.RemoveAll(versionDir) // #nosec G104 -- best-effort cleanup on extraction failure
		return nil, err
	}

	// 9. Make executable.
	if err := os.Chmod(targetBinary, 0o755); err != nil { // #nosec G302 -- scanner binary must be executable
		return nil, fmt.Errorf("chmod: %w", err)
	}

	// 10. Atomically swap symlink.
	symlinkPath := filepath.Join(cfg.InstallDir, tool)
	if err := atomicSymlink(targetBinary, symlinkPath); err != nil {
		return nil, fmt.Errorf("symlink: %w", err)
	}

	return &Result{
		BinaryPath: symlinkPath,
		Version:    version,
		Sha256:     hex.EncodeToString(archiveHash),
		SourceURL:  archiveAsset.BrowserDownloadURL,
	}, nil
}

// ensureWritableDir verifies or creates the install directory and confirms writability.
func ensureWritableDir(dir string) error {
	if dir == "" {
		return ErrInstallDirNotWritable
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- scanner install directory needs execute permission
		return fmt.Errorf("%w: %v", ErrInstallDirNotWritable, err)
	}
	// Probe writability.
	probe := filepath.Join(dir, ".write-probe")
	f, err := os.Create(probe) // #nosec G304 -- path is operator-configured install dir
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInstallDirNotWritable, err)
	}
	f.Close()        // #nosec G104 -- probe file is immediately removed
	os.Remove(probe) // #nosec G104 -- best-effort cleanup of writability probe
	return nil
}

// resolveRelease fetches the GitHub release metadata.
func resolveRelease(ctx context.Context, client *http.Client, spec AssetSpec, pinnedVersion string) (*ghRelease, error) {
	var url string
	if pinnedVersion == "" {
		url = spec.LatestReleaseAPI
	} else {
		v := strings.TrimPrefix(pinnedVersion, "v")
		url = fmt.Sprintf(spec.VersionedAPI, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release JSON: %w", err)
	}
	return &release, nil
}

// downloadFile streams a URL to a local file with a size cap, returning the SHA256 hash.
func downloadFile(ctx context.Context, client *http.Client, url, dest string, sizeLimit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.Create(dest) // #nosec G304 -- dest is inside InstallDir temp directory
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, sizeLimit+1) // +1 to detect overflow
	written, err := io.Copy(f, io.TeeReader(limited, hasher))
	if err != nil {
		return nil, err
	}
	if written > sizeLimit {
		os.Remove(dest) // #nosec G104 -- best-effort cleanup on size cap exceeded
		return nil, fmt.Errorf("%w: downloaded %d bytes (cap %d)", ErrArchiveTooLarge, written, sizeLimit)
	}

	return hasher.Sum(nil), nil
}

// verifyChecksum reads a checksums file and verifies the archive hash.
func verifyChecksum(checksumsPath, archiveName string, archiveHash []byte) error {
	f, err := os.Open(checksumsPath) // #nosec G304 -- path is inside InstallDir temp directory
	if err != nil {
		return fmt.Errorf("open checksums: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: "SHA256  filename" or just "SHA256" (single-file .sha256 files)
		parts := strings.Fields(line)
		if len(parts) == 1 {
			// Single hash (e.g. checkov_linux_X86_64.zip.sha256 contains just the hash)
			expected, err := hex.DecodeString(parts[0])
			if err != nil {
				continue
			}
			if subtle.ConstantTimeCompare(expected, archiveHash) == 1 {
				return nil
			}
			return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, parts[0], hex.EncodeToString(archiveHash))
		}
		if len(parts) >= 2 {
			filename := parts[len(parts)-1]
			// Some checksums files use "*filename" notation
			filename = strings.TrimPrefix(filename, "*")
			if filename == archiveName {
				expected, err := hex.DecodeString(parts[0])
				if err != nil {
					return fmt.Errorf("malformed checksum line: %s", line)
				}
				if subtle.ConstantTimeCompare(expected, archiveHash) == 1 {
					return nil
				}
				return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, parts[0], hex.EncodeToString(archiveHash))
			}
		}
	}
	return fmt.Errorf("%w: no checksum entry found for %s", ErrChecksumMismatch, archiveName)
}

// extractFromTarGz extracts a single file from a .tar.gz archive.
func extractFromTarGz(archivePath, targetEntry, destPath string) error {
	f, err := os.Open(archivePath) // #nosec G304 -- path is inside InstallDir temp directory
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%w: %s not found in archive", ErrAssetNotFound, targetEntry)
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		// Validate path for traversal.
		clean := filepath.Clean(header.Name)
		if strings.Contains(clean, "..") {
			return fmt.Errorf("%w: %s", ErrPathTraversal, header.Name)
		}
		if filepath.IsAbs(clean) || strings.HasPrefix(header.Name, "/") {
			return fmt.Errorf("%w: %s", ErrPathTraversal, header.Name)
		}

		// Match by basename or full path.
		name := header.Name
		if filepath.Base(name) == targetEntry || name == targetEntry {
			return writeExtractedFile(tr, destPath)
		}
	}
}

// extractFromZip extracts a single file from a .zip archive.
func extractFromZip(archivePath, targetEntry, destPath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("zip open: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		// Validate path for traversal.
		clean := filepath.Clean(entry.Name)
		if strings.Contains(clean, "..") {
			return fmt.Errorf("%w: %s", ErrPathTraversal, entry.Name)
		}
		if filepath.IsAbs(clean) || strings.HasPrefix(entry.Name, "/") {
			return fmt.Errorf("%w: %s", ErrPathTraversal, entry.Name)
		}

		if filepath.Base(entry.Name) == targetEntry || entry.Name == targetEntry {
			rc, err := entry.Open()
			if err != nil {
				return fmt.Errorf("zip entry open: %w", err)
			}
			defer rc.Close()
			return writeExtractedFile(rc, destPath)
		}
	}
	return fmt.Errorf("%w: %s not found in archive", ErrAssetNotFound, targetEntry)
}

// writeExtractedFile writes a reader to destPath with a per-file size cap.
func writeExtractedFile(r io.Reader, destPath string) error {
	out, err := os.Create(destPath) // #nosec G304 -- path is derived from InstallDir + catalog-controlled name
	if err != nil {
		return err
	}
	defer out.Close()

	limited := io.LimitReader(r, maxFileSize+1)
	n, err := io.Copy(out, limited) // #nosec G110 -- size capped via io.LimitReader
	if err != nil {
		return err
	}
	if n > maxFileSize {
		os.Remove(destPath) // #nosec G104 -- best-effort cleanup on size cap exceeded
		return fmt.Errorf("extracted file exceeds size cap (%d bytes)", maxFileSize)
	}
	return nil
}

// atomicSymlink creates or replaces a symlink atomically using rename.
func atomicSymlink(target, linkPath string) error {
	tmpLink := linkPath + ".tmp-" + randHex(8)
	if err := os.Symlink(target, tmpLink); err != nil {
		return err
	}
	if err := os.Rename(tmpLink, linkPath); err != nil {
		os.Remove(tmpLink) // #nosec G104 -- best-effort cleanup on rename failure
		return err
	}
	return nil
}

// randHex returns n bytes of random hex.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Handle is a shared helper for both setup and admin install handlers.
// It runs the install logic and returns a JSON-friendly response map.
func Handle(ctx context.Context, installDir string, install InstallFunc, tool, version string) (success bool, result *Result, errMsg string) {
	if !Supports(tool) {
		return false, nil, fmt.Sprintf(
			"auto-install is not available for %q — install it manually and enter the binary path below. Supported: %v",
			tool, SupportedTools(),
		)
	}

	if installDir == "" {
		return false, nil, "scanning.install_dir is not configured on the server"
	}

	if install == nil {
		install = Install
	}

	r, err := install(ctx, InstallConfig{
		InstallDir: installDir,
		Timeout:    5 * time.Minute,
	}, tool, version)
	if err != nil {
		return false, nil, err.Error()
	}

	return true, r, ""
}

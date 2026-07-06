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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	goversion "github.com/hashicorp/go-version"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// Size caps to prevent zip-bomb / decompression-bomb DoS.
const (
	maxArchiveSize   = 500 << 20 // 500 MB
	maxFileSize      = 200 << 20 // 200 MB per extracted file
	maxChecksumsSize = 8 << 10   // 8 KB
	maxSigBundleSize = 1 << 20   // 1 MB; a sigstore bundle (cert chain + inclusion proof) is a few KB-15KB
)

// InstallConfig holds parameters for an Install call.
type InstallConfig struct {
	// InstallDir is the server-managed directory for scanner binaries.
	InstallDir string
	// Timeout caps the entire operation; default 5 minutes if zero.
	Timeout time.Duration
	// HTTPClient is optional; default is http.Client{Timeout: 5m}.
	HTTPClient *http.Client
	// SignatureMode controls the optional cryptographic signature check (on top of
	// the mandatory SHA256 checksum): "off" skips it, "warn" verifies and records
	// the result but never blocks, "enforce" fails the install on a definitive
	// signature/identity mismatch. Empty is treated as "enforce" (safe-by-default).
	SignatureMode string
}

// Result describes a successful installation.
type Result struct {
	BinaryPath string `json:"binary_path"`
	Version    string `json:"version"`
	Sha256     string `json:"sha256"`
	SourceURL  string `json:"source_url"`
	// SignatureVerified indicates whether an additional cryptographic signature
	// (beyond the mandatory SHA256 checksum) was verified for this artifact.
	SignatureVerified bool `json:"signature_verified"`
	// SignatureType is "none", "gpg", or "sigstore" — the signature scheme configured
	// for this tool, regardless of whether SignatureVerified is true.
	SignatureType string `json:"signature_type,omitempty"`
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
	ErrUnsafePath            = errors.New("unsafe path component in a download name or version")
)

// InstallFunc is the handler-facing type alias so tests can inject a stub.
type InstallFunc func(ctx context.Context, cfg InstallConfig, tool, pinnedVersion string) (*Result, error)

// CheckFunc is the handler/job-facing type alias for CheckLatest so tests and
// callers (e.g. ScannerUpdateJob) can inject a stub.
type CheckFunc func(ctx context.Context, cfg InstallConfig, tool string) (*LatestInfo, error)

// ghRelease is the subset of the GitHub release JSON we need.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	// Digest is GitHub's reported content digest, e.g. "sha256:<hex>". Used for tools
	// (e.g. checkov) whose releases publish no separate checksums file/asset.
	Digest string `json:"digest"`
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
	archiveAsset, checksumsAsset, sigAsset := matchAssets(spec, release)
	if archiveAsset == nil || (checksumsAsset == nil && !spec.UseAssetDigest) {
		return nil, fmt.Errorf("%w: tool=%s version=%s os=%s arch=%s", ErrAssetNotFound, tool, version, runtime.GOOS, runtime.GOARCH)
	}

	// 5-9. Download, verify (checksum + optional signature), and extract.
	targetBinary, sha256hex, sourceURL, sigVerified, sigType, err := downloadExtract(ctx, client, cfg, spec, tool, version, archiveAsset, checksumsAsset, sigAsset)
	if err != nil {
		return nil, err
	}

	// 10. Atomically swap symlink.
	symlinkPath := filepath.Join(cfg.InstallDir, tool)
	if err := atomicSymlink(targetBinary, symlinkPath); err != nil {
		return nil, fmt.Errorf("symlink: %w", err)
	}

	return &Result{
		BinaryPath:        symlinkPath,
		Version:           version,
		Sha256:            sha256hex,
		SourceURL:         sourceURL,
		SignatureVerified: sigVerified,
		SignatureType:     sigType,
	}, nil
}

// matchAssets locates the archive, checksums, and (optional) signature assets for a
// release given a catalog spec. Signature matching only occurs when spec.SignaturePattern
// is set.
func matchAssets(spec AssetSpec, release *ghRelease) (archive, checksums, sig *ghAsset) {
	for i := range release.Assets {
		a := &release.Assets[i]
		if archive == nil && spec.AssetPattern.MatchString(a.Name) {
			archive = a
		}
		if checksums == nil && spec.ChecksumsPattern != nil && spec.ChecksumsPattern.MatchString(a.Name) {
			checksums = a
		}
		if sig == nil && spec.SignaturePattern != nil && spec.SignaturePattern.MatchString(a.Name) {
			sig = a
		}
	}
	return archive, checksums, sig
}

// downloadExtract downloads the matched archive (and checksums/signature assets),
// verifies its integrity, and extracts the target binary to the versioned install
// path {cfg.InstallDir}/{tool}-{version}/{basename(spec.BinaryInArchive)}. It is
// shared by Install and DownloadVerified; neither creates/updates the {tool} symlink.
// safeChildPath joins name onto dir and guarantees the result stays within dir.
// It rejects names containing path separators or parent references ("..") and
// verifies containment, defending against path traversal from remote-influenced
// values such as GitHub release asset names and version tags (go/path-injection).
func safeChildPath(dir, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	p := filepath.Join(dir, name)
	if !strings.HasPrefix(p, filepath.Clean(dir)+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q escapes %q", ErrUnsafePath, name, dir)
	}
	return p, nil
}

func downloadExtract(ctx context.Context, client *http.Client, cfg InstallConfig, spec AssetSpec, tool, version string, archiveAsset, checksumsAsset, sigAsset *ghAsset) (versionedBinaryPath, sha256hex, sourceURL string, sigVerified bool, sigType string, err error) {
	// Validate HTTPS-only.
	if !strings.HasPrefix(archiveAsset.BrowserDownloadURL, "https://") {
		return "", "", "", false, "", fmt.Errorf("%w: %s", ErrNonHTTPS, archiveAsset.BrowserDownloadURL)
	}
	if checksumsAsset != nil && !strings.HasPrefix(checksumsAsset.BrowserDownloadURL, "https://") {
		return "", "", "", false, "", fmt.Errorf("%w: %s", ErrNonHTTPS, checksumsAsset.BrowserDownloadURL)
	}

	// Create a temp dir for downloads.
	tmpDir, mkErr := os.MkdirTemp(cfg.InstallDir, "tmp-install-")
	if mkErr != nil {
		return "", "", "", false, "", fmt.Errorf("create temp dir: %w", mkErr)
	}
	defer os.RemoveAll(tmpDir) // always clean up temp

	// Download archive with size cap. safeChildPath guards against a malicious
	// release asset name escaping the temp dir (go/path-injection).
	archivePath, pErr := safeChildPath(tmpDir, archiveAsset.Name)
	if pErr != nil {
		return "", "", "", false, "", pErr
	}
	archiveHash, dlErr := downloadFile(ctx, client, archiveAsset.BrowserDownloadURL, archivePath, maxArchiveSize)
	if dlErr != nil {
		return "", "", "", false, "", dlErr
	}

	// Verify integrity: either a checksums file/asset or the GitHub asset digest.
	var checksumsData []byte
	switch {
	case checksumsAsset != nil:
		checksumsPath, pErr := safeChildPath(tmpDir, checksumsAsset.Name)
		if pErr != nil {
			return "", "", "", false, "", fmt.Errorf("checksums: %w", pErr)
		}
		if _, dlErr := downloadFile(ctx, client, checksumsAsset.BrowserDownloadURL, checksumsPath, maxChecksumsSize); dlErr != nil {
			return "", "", "", false, "", fmt.Errorf("download checksums: %w", dlErr)
		}
		if verErr := verifyChecksum(checksumsPath, archiveAsset.Name, archiveHash); verErr != nil {
			return "", "", "", false, "", verErr
		}
		checksumsData, _ = os.ReadFile(checksumsPath) // #nosec G304 -- path is inside InstallDir temp directory
	case spec.UseAssetDigest:
		if verErr := verifyAssetDigest(archiveAsset.Digest, archiveHash); verErr != nil {
			return "", "", "", false, "", verErr
		}
	}

	// Optional signature verification (additive; never blocks except a genuine gpg failure).
	verified, verSigType, sigErr := verifyArtifactSignature(ctx, client, spec, sigAsset, checksumsData, cfg.SignatureMode, version)
	if sigErr != nil {
		return "", "", "", false, "", sigErr
	}

	// Extract binary from archive. safeChildPath guards against a malicious
	// version tag escaping InstallDir (go/path-injection).
	versionDir, pErr := safeChildPath(cfg.InstallDir, tool+"-"+version)
	if pErr != nil {
		return "", "", "", false, "", pErr
	}
	if mkErr := os.MkdirAll(versionDir, 0o755); mkErr != nil { // #nosec G301 -- scanner binary directory needs execute permission
		return "", "", "", false, "", fmt.Errorf("create version dir: %w", mkErr)
	}

	targetBinary := filepath.Join(versionDir, filepath.Base(spec.BinaryInArchive))
	var extractErr error
	switch spec.ArchiveFormat {
	case "tar.gz":
		extractErr = extractFromTarGz(archivePath, spec.BinaryInArchive, targetBinary)
	case "zip":
		extractErr = extractFromZip(archivePath, spec.BinaryInArchive, targetBinary)
	default:
		extractErr = fmt.Errorf("unsupported archive format: %s", spec.ArchiveFormat)
	}
	if extractErr != nil {
		os.RemoveAll(versionDir) // #nosec G104 -- best-effort cleanup on extraction failure
		return "", "", "", false, "", extractErr
	}

	// Make executable.
	if chmodErr := os.Chmod(targetBinary, 0o755); chmodErr != nil { // #nosec G302 -- scanner binary must be executable
		return "", "", "", false, "", fmt.Errorf("chmod: %w", chmodErr)
	}

	return targetBinary, hex.EncodeToString(archiveHash), archiveAsset.BrowserDownloadURL, verified, verSigType, nil
}

// verifyAssetDigest verifies archiveHash against the GitHub asset's reported `digest`
// field (e.g. "sha256:<hex>"), used for tools that publish no checksums file/asset.
func verifyAssetDigest(digest string, archiveHash []byte) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return fmt.Errorf("%w: asset digest missing or not sha256 (%q)", ErrChecksumMismatch, digest)
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(digest, prefix))
	if err != nil {
		return fmt.Errorf("%w: malformed asset digest %q", ErrChecksumMismatch, digest)
	}
	if subtle.ConstantTimeCompare(expected, archiveHash) != 1 {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, hex.EncodeToString(expected), hex.EncodeToString(archiveHash))
	}
	return nil
}

// verifyArtifactSignature optionally verifies a release's signature per spec.Signature.
// SHA256 checksum verification is mandatory and handled by the caller before this is
// invoked; this is additive. mode is the configured scanning.signature_verification
// setting ("off"/"warn"/"enforce"); empty is treated as "enforce". version is the
// resolved release version (without a "v" prefix), used to interpolate spec.Signature.Identity.
func verifyArtifactSignature(ctx context.Context, client *http.Client, spec AssetSpec, sig *ghAsset, checksums []byte, mode, version string) (verified bool, sigType string, err error) {
	switch spec.Signature.Type {
	case "", "none":
		return false, "none", nil
	case "gpg":
		if sig == nil {
			return false, "gpg", fmt.Errorf("gpg signature verification configured but no signature asset found")
		}
		if !strings.HasPrefix(sig.BrowserDownloadURL, "https://") {
			return false, "gpg", fmt.Errorf("%w: %s", ErrNonHTTPS, sig.BrowserDownloadURL)
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, sig.BrowserDownloadURL, nil)
		if reqErr != nil {
			return false, "gpg", reqErr
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return false, "gpg", doErr
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, "gpg", fmt.Errorf("download signature: HTTP %d", resp.StatusCode)
		}
		sigBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxChecksumsSize))
		if readErr != nil {
			return false, "gpg", readErr
		}
		key, _, keyErr := mirror.FetchReleasesKey(ctx, client, spec.Signature.KeyURL, spec.Signature.Fingerprint)
		if keyErr != nil {
			return false, "gpg", fmt.Errorf("fetch signing key: %w", keyErr)
		}
		if verErr := validation.VerifySignature(key, checksums, sigBytes); verErr != nil {
			return false, "gpg", fmt.Errorf("signature verification failed: %w", verErr)
		}
		return true, "gpg", nil
	case "sigstore":
		if mode == "" {
			mode = "enforce"
		}
		if mode == "off" {
			return false, "sigstore", nil
		}
		if sig == nil {
			// Older releases (pre-v0.68.1 for trivy) publish no Sigstore bundle at all.
			// Never block on this; the mandatory SHA256 checksum check already applies.
			log.Printf("scanner installer: no sigstore signature asset found (older release?); skipping signature verification")
			return false, "sigstore", nil
		}
		if len(checksums) == 0 {
			// Nothing to verify the bundle against (e.g. UseAssetDigest tools).
			return false, "sigstore", nil
		}
		if !strings.HasPrefix(sig.BrowserDownloadURL, "https://") {
			return false, "sigstore", fmt.Errorf("%w: %s", ErrNonHTTPS, sig.BrowserDownloadURL)
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, sig.BrowserDownloadURL, nil)
		if reqErr != nil {
			return false, "sigstore", reqErr
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return false, "sigstore", doErr
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, "sigstore", fmt.Errorf("download signature bundle: HTTP %d", resp.StatusCode)
		}
		bundleBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxSigBundleSize))
		if readErr != nil {
			return false, "sigstore", readErr
		}

		identity := fmt.Sprintf(spec.Signature.Identity, version)
		verErr := sigstoreVerify(bundleBytes, checksums, identity, spec.Signature.Issuer)
		switch {
		case verErr == nil:
			return true, "sigstore", nil
		case errors.Is(verErr, errTrustRootUnavailable):
			// Infra failure (e.g. air-gapped, no TUF access) — never blocks; SHA256
			// checksum verification (already mandatory) still applies.
			log.Printf("scanner installer: sigstore trust root unavailable; falling back to SHA256-only: %v", verErr)
			return false, "sigstore", nil
		default:
			// Definitive signature/identity mismatch.
			log.Printf("scanner installer: sigstore signature verification failed: %v", verErr)
			if mode == "enforce" {
				return false, "sigstore", fmt.Errorf("sigstore signature verification failed: %w", verErr)
			}
			// mode == "warn": record but never block.
			return false, "sigstore", nil
		}
	default:
		return false, spec.Signature.Type, nil
	}
}

// LatestInfo describes the latest available upstream release for a scanner tool on
// the current server OS/arch, without downloading anything.
type LatestInfo struct {
	Tool               string `json:"tool"`
	LatestVersion      string `json:"latest_version"`
	ArchiveURL         string `json:"archive_url"`
	ChecksumsURL       string `json:"checksums_url,omitempty"`
	SignatureURL       string `json:"signature_url,omitempty"`
	SignatureSupported bool   `json:"signature_supported"`
}

// CheckLatest queries the upstream GitHub release for the latest version of tool
// available for the current server OS/arch. It does not download or install anything.
// coverage:skip:integration-only — resolves a real upstream GitHub release via resolveRelease; matchAssets/verifyAssetDigest dispatch logic it shares with Install/DownloadVerified is unit-tested there. GetScannerLatestHandler_UpdateAvailable exercises the success path hermetically via a Catalog+DefaultTransport swap, but the Lookup-failure/asset-not-found branches still require network to reach.
func CheckLatest(ctx context.Context, cfg InstallConfig, tool string) (*LatestInfo, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	spec, ok := Lookup(tool, runtime.GOOS, runtime.GOARCH)
	if !ok {
		if !Supports(tool) {
			return nil, fmt.Errorf("%w: %s (supported: %v)", ErrUnsupportedTool, tool, SupportedTools())
		}
		return nil, fmt.Errorf("%w: %s on %s/%s", ErrUnsupportedPlatform, tool, runtime.GOOS, runtime.GOARCH)
	}

	release, err := resolveRelease(ctx, client, spec, "")
	if err != nil {
		return nil, fmt.Errorf("resolve release: %w", err)
	}
	version := strings.TrimPrefix(release.TagName, "v")

	archiveAsset, checksumsAsset, sigAsset := matchAssets(spec, release)
	if archiveAsset == nil || (checksumsAsset == nil && !spec.UseAssetDigest) {
		return nil, fmt.Errorf("%w: tool=%s version=%s os=%s arch=%s", ErrAssetNotFound, tool, version, runtime.GOOS, runtime.GOARCH)
	}

	info := &LatestInfo{
		Tool:               tool,
		LatestVersion:      version,
		ArchiveURL:         archiveAsset.BrowserDownloadURL,
		SignatureSupported: spec.Signature.Type == "gpg" || spec.Signature.Type == "sigstore",
	}
	if checksumsAsset != nil {
		info.ChecksumsURL = checksumsAsset.BrowserDownloadURL
	}
	if sigAsset != nil {
		info.SignatureURL = sigAsset.BrowserDownloadURL
	}
	return info, nil
}

// DownloadVerified resolves, downloads, verifies, and extracts a scanner binary to its
// versioned install path {cfg.InstallDir}/{tool}-{version}/{basename} WITHOUT creating
// or replacing the {cfg.InstallDir}/{tool} symlink — i.e. the binary is present on disk
// but not activated. This is the "present-but-inactive" path for the pending-approval
// update flow; Install remains the one-step download+activate entry point.
func DownloadVerified(ctx context.Context, cfg InstallConfig, tool, pinnedVersion string) (*Result, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	if err := ensureWritableDir(cfg.InstallDir); err != nil {
		return nil, err
	}

	spec, ok := Lookup(tool, runtime.GOOS, runtime.GOARCH)
	if !ok {
		if !Supports(tool) {
			return nil, fmt.Errorf("%w: %s (supported: %v)", ErrUnsupportedTool, tool, SupportedTools())
		}
		return nil, fmt.Errorf("%w: %s on %s/%s", ErrUnsupportedPlatform, tool, runtime.GOOS, runtime.GOARCH)
	}

	release, err := resolveRelease(ctx, client, spec, pinnedVersion)
	if err != nil {
		return nil, fmt.Errorf("resolve release: %w", err)
	}
	version := strings.TrimPrefix(release.TagName, "v")

	archiveAsset, checksumsAsset, sigAsset := matchAssets(spec, release)
	if archiveAsset == nil || (checksumsAsset == nil && !spec.UseAssetDigest) {
		return nil, fmt.Errorf("%w: tool=%s version=%s os=%s arch=%s", ErrAssetNotFound, tool, version, runtime.GOOS, runtime.GOARCH)
	}

	targetBinary, sha256hex, sourceURL, sigVerified, sigType, err := downloadExtract(ctx, client, cfg, spec, tool, version, archiveAsset, checksumsAsset, sigAsset)
	if err != nil {
		return nil, err
	}

	return &Result{
		BinaryPath:        targetBinary,
		Version:           version,
		Sha256:            sha256hex,
		SourceURL:         sourceURL,
		SignatureVerified: sigVerified,
		SignatureType:     sigType,
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
		// Validate pinnedVersion is a recognisable semver before interpolating it into
		// the GitHub API URL.  An attacker-controlled value could otherwise redirect
		// the request to an unexpected path (CWE-918 / CodeQL go/path-injection).
		if _, err := goversion.NewSemver(v); err != nil {
			return nil, fmt.Errorf("invalid pinned version %q: must be a valid semantic version", pinnedVersion)
		}
		url = fmt.Sprintf(spec.VersionedAPI, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req) // #nosec G107 -- url is built from a static template (spec.LatestReleaseAPI or spec.VersionedAPI) with pinnedVersion validated by goversion.NewSemver; CWE-918 mitigated
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

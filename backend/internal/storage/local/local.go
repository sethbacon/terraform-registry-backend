// Package local implements the local filesystem storage backend for the Terraform Registry. This
// backend is intended for development and single-node deployments only — it does not support
// horizontal scaling (multiple registry instances would need access to the same filesystem, e.g.,
// via NFS). For production, use a cloud storage backend.
package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/storage/urlsign"
)

func init() {
	// Register local storage backend
	storage.Register("local", func(cfg *config.Config) (storage.Storage, error) {
		return New(&cfg.Storage.Local, cfg.Server.BaseURL)
	})
}

// LocalStorage implements the Storage interface for local filesystem storage
type LocalStorage struct {
	basePath      string
	serveDirectly bool
	baseURL       string
}

// New creates a new local filesystem storage backend
func New(cfg *config.LocalStorageConfig, serverBaseURL string) (*LocalStorage, error) {
	// Ensure base path exists
	if err := os.MkdirAll(cfg.BasePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	if !cfg.ServeDirectly {
		slog.Warn("storage.local.serve_directly=false is ignored: download URLs are " +
			"always served through the API. It previously produced a file:// URL, " +
			"which disclosed the absolute storage root to anonymous callers in the " +
			"X-Terraform-Get header and was not fetchable by a remote Terraform " +
			"client anyway.")
	}

	return &LocalStorage{
		// Cleaned once, here, so every later comparison against it is against a
		// canonical path. Storing cfg.BasePath verbatim let a configured
		// trailing slash (or "./storage", or a doubled separator) make
		// filepath.Dir output never string-equal the root -- see Delete's
		// parent walk, which climbed straight past it.
		basePath:      filepath.Clean(cfg.BasePath),
		serveDirectly: cfg.ServeDirectly,
		baseURL:       serverBaseURL,
	}, nil
}

// safeJoin constructs an absolute path by joining basePath and the caller-supplied
// relative path, then verifies that the result is still inside basePath. This is a
// defence-in-depth check: the primary traversal rejection lives in serve.go, but
// this ensures the storage layer cannot be exploited even if a future code path
// skips that check.
func (s *LocalStorage) safeJoin(path string) (string, error) {
	// Cleaned once, up front, so the value CHECKED below and the value RETURNED
	// are the same variable.
	//
	// This was previously `full := filepath.Join(...)` with the containment test
	// applied to `filepath.Clean(full)` while plain `full` was returned.
	// Functionally identical -- filepath.Join already cleans -- but the test then
	// referred to a different expression than the one that escapes the function.
	//
	// CORRECTION (2026-08-24). This comment used to claim that difference was
	// "why CodeQL's go/path-injection could not recognise safeJoin as a sanitiser
	// and kept flagging Delete's os.Remove calls as HIGH" -- i.e. that #826 fixed
	// the alerts. IT DID NOT. Alerts 57 and 60 were still open after it, and the
	// commit they were last analysed on has #826 as an ancestor, so the scanner
	// re-ran with this shape in place and reported anyway. They are now dismissed
	// as false positives on the merits, not resolved by this refactor.
	//
	// The claim mattered because it was load-bearing in the wrong direction:
	// anyone finding those alerts open would read this comment and conclude they
	// predated the fix and could be ignored.
	//
	// Checking exactly what you return is still the clearer contract, which is
	// the reason to keep it -- independent of any scanner.
	//
	// NOT COVERED HERE: symlinks. This resolves lexically and does not call
	// filepath.EvalSymlinks, so a symlink INSIDE basePath pointing outside it is
	// followed by the callers' os.Remove / os.Open. That needs an attacker who
	// can already create symlinks under the storage root, which is why it is
	// noted rather than fixed here -- but it is the one path in this file that is
	// not proven safe.
	full := filepath.Clean(filepath.Join(s.basePath, filepath.FromSlash(path)))
	base := filepath.Clean(s.basePath) + string(os.PathSeparator)
	if !strings.HasPrefix(full+string(os.PathSeparator), base) {
		return "", fmt.Errorf("path escapes storage root: %s", path)
	}
	return full, nil
}

// Upload stores a file in the local filesystem
func (s *LocalStorage) Upload(ctx context.Context, path string, reader io.Reader, size int64) (*storage.UploadResult, error) {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return nil, err
	}
	fullPath, err := s.safeJoin(path)
	if err != nil {
		return nil, err
	}

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Create file
	file, err := os.Create(fullPath) // #nosec G304 -- fullPath has been validated by safeJoin to remain within basePath
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Calculate checksum while writing
	hasher := sha256.New()
	multiWriter := io.MultiWriter(file, hasher)

	written, err := io.Copy(multiWriter, reader)
	if err != nil {
		// Clean up partial file
		_ = os.Remove(fullPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	sidecarPath := fullPath + ".sha256"
	if err := os.WriteFile(sidecarPath, []byte(checksum), 0600); err != nil { //nolint:gosec -- G306: checksum file is non-sensitive; 0600 satisfies gosec while still being readable by the server process
		slog.Warn("failed to write checksum sidecar", "path", sidecarPath, "error", err)
	}

	return &storage.UploadResult{
		Path:     path,
		Size:     written,
		Checksum: checksum,
	}, nil
}

// Download retrieves a file from the local filesystem
func (s *LocalStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return nil, err
	}
	fullPath, err := s.safeJoin(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(fullPath) // #nosec G304 -- fullPath has been validated by safeJoin to remain within basePath
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

// Delete removes a file from the local filesystem
func (s *LocalStorage) Delete(ctx context.Context, path string) error {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return err
	}
	fullPath, err := s.safeJoin(path)
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil { // #nosec G304 -- fullPath has been validated by safeJoin to remain within basePath
		if os.IsNotExist(err) {
			return nil // File doesn't exist, consider it deleted
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Also remove the checksum sidecar if it exists
	_ = os.Remove(fullPath + ".sha256")

	// Try to remove empty parent directories (best effort), never at or above
	// the storage root.
	//
	// This walk used to terminate on `dir != s.basePath` alone. filepath.Dir
	// returns a clean path with no trailing separator, so that comparison
	// silently never matched when base_path was configured with a trailing
	// slash or as a relative path -- and the loop then deleted the storage root
	// itself and kept climbing, removing every empty ancestor until os.Remove
	// happened to fail on a non-empty one. safeJoin could not catch it: nothing
	// about the caller's key is involved, only the shape of the configured root.
	//
	// basePath is now cleaned at construction, which fixes the cause. The
	// containment check below is the second, independent stop: a path that is
	// not strictly inside the root is never a candidate for removal, whatever
	// basePath happens to look like.
	root := s.basePath
	prefix := root + string(os.PathSeparator)
	for dir := filepath.Dir(fullPath); strings.HasPrefix(dir, prefix); dir = filepath.Dir(dir) {
		if err := os.Remove(dir); err != nil { // #nosec G304 -- dir is verified strictly inside basePath by the loop condition
			break // Directory not empty or other error, stop trying
		}
	}

	return nil
}

// GetURL returns the API URL for downloading the file.
//
// It NEVER returns a file:// URL (issue #751). It used to, when
// serve_directly was false, and that value went straight into the
// X-Terraform-Get header of GET /v1/modules/.../download -- a documented
// UNAUTHENTICATED protocol endpoint. So any anonymous caller learned the
// deployment's absolute storage root, and by extension its filesystem layout
// and container mount paths: reconnaissance for chaining against a
// path-handling bug.
//
// It was also functionally wrong. A remote Terraform client cannot fetch
// file://, so that configuration was broken as well as leaky.
//
// serve_directly no longer changes what is returned. It could not usefully:
// /v1/files/*filepath is registered unconditionally (see registerPublicRoutes),
// so the API path works either way, and it is strictly more capable than
// file:// -- a same-host client can fetch it over loopback just as well.
// LocalStorage.New warns when the flag is set to false rather than ignoring it
// silently.
func (s *LocalStorage) GetURL(ctx context.Context, path string, ttl time.Duration) (string, error) {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return "", err
	}
	// Check if file exists
	exists, err := s.Exists(ctx, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file not found: %s", path)
	}

	// SIGNED, because GET /v1/files/*filepath has no authentication middleware
	// on it and storage keys are structural and guessable (#973). The other
	// three backends all return a credential here -- an S3 presign, a GCS
	// signature, an Azure SAS -- and returning a bare path made the local
	// backend the one configuration where every module archive and terraform
	// binary was anonymously fetchable by anyone who could reach the port.
	//
	// The ttl argument was accepted and ignored before this. Every caller
	// already passes one (15 minutes, or an hour for the mirror), so the
	// bound is now real rather than documentary.
	expires, sig, err := urlsign.Sign(path, ttl, time.Now())
	if err != nil {
		// Fail closed. Returning the unsigned URL on a signing failure would
		// reinstate exactly the anonymous-fetch hole this closes, at the moment
		// something is already wrong.
		return "", fmt.Errorf("failed to sign download URL: %w", err)
	}

	// The path is escaped segment-wise; the SIGNATURE is over the unescaped
	// storage key. Gin decodes the path parameter before the handler sees it,
	// so the handler verifies against the same unescaped string this signed --
	// which matters because real keys carry '+' and '~' from version strings
	// such as 1.0.0+build.5.
	return fmt.Sprintf("%s/v1/files/%s?%s=%s&%s=%s",
		s.baseURL, escapePathSegments(path),
		urlsign.ParamExpires, url.QueryEscape(expires),
		urlsign.ParamSignature, url.QueryEscape(sig),
	), nil
}

// escapePathSegments percent-encodes each segment while leaving the separators
// alone.
//
// url.PathEscape on the whole key would encode the slashes too and collapse the
// key into one segment; leaving it raw would break on any key byte that is not
// URL-safe. Segment-wise is the only form that round-trips to the same storage
// key Gin hands the handler.
func escapePathSegments(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// Exists checks if a file exists at the specified path
func (s *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return false, err
	}
	fullPath, err := s.safeJoin(path)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(fullPath) // #nosec G304 -- fullPath has been validated by safeJoin to remain within basePath
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check file existence: %w", err)
	}

	return true, nil
}

// GetMetadata retrieves file metadata without downloading the file
func (s *LocalStorage) GetMetadata(ctx context.Context, path string) (*storage.FileMetadata, error) {
	// Issue #752: uniform key validation. The local backend has always had
	// safeJoin; the cloud backends passed the caller's string through as the
	// object key verbatim.
	if err := storage.ValidateKey(path); err != nil {
		return nil, err
	}
	fullPath, err := s.safeJoin(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get file metadata: %w", err)
	}

	sidecarPath := fullPath + ".sha256"
	if data, err := os.ReadFile(sidecarPath); err == nil { //nolint:gosec -- G304: sidecarPath derived from validated internal storage path, not user input
		checksum := strings.TrimSpace(string(data))
		return &storage.FileMetadata{
			Path:         path,
			Size:         stat.Size(),
			Checksum:     checksum,
			LastModified: stat.ModTime(),
		}, nil
	}

	// Calculate checksum by reading the file
	file, err := os.Open(fullPath) // #nosec G304 -- path is constructed from validated namespace/name/version components; path traversal is prevented at the API and archive-extraction layers
	if err != nil {
		return nil, fmt.Errorf("failed to open file for checksum: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	_ = os.WriteFile(sidecarPath, []byte(checksum), 0600) //nolint:gosec -- G306: checksum file is non-sensitive; 0600 satisfies gosec

	return &storage.FileMetadata{
		Path:         path,
		Size:         stat.Size(),
		Checksum:     checksum,
		LastModified: stat.ModTime(),
	}, nil
}

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
	"os"
	"path/filepath"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
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

	return &LocalStorage{
		basePath:      cfg.BasePath,
		serveDirectly: cfg.ServeDirectly,
		baseURL:       serverBaseURL,
	}, nil
}

// Upload stores a file in the local filesystem
func (s *LocalStorage) Upload(ctx context.Context, path string, reader io.Reader, size int64) (*storage.UploadResult, error) {
	// Create full path
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Create file
	file, err := os.Create(fullPath)
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

	return &storage.UploadResult{
		Path:     path,
		Size:     written,
		Checksum: checksum,
	}, nil
}

// Download retrieves a file from the local filesystem
func (s *LocalStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))

	file, err := os.Open(fullPath)
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
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))

	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, consider it deleted
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Try to remove empty parent directories (best effort)
	dir := filepath.Dir(fullPath)
	for dir != s.basePath {
		if err := os.Remove(dir); err != nil {
			break // Directory not empty or other error, stop trying
		}
		dir = filepath.Dir(dir)
	}

	return nil
}

// GetURL returns a URL for downloading the file
// For local storage with ServeDirectly enabled, this returns a relative URL
// Otherwise, it returns the local file path
func (s *LocalStorage) GetURL(ctx context.Context, path string, ttl time.Duration) (string, error) {
	// Check if file exists
	exists, err := s.Exists(ctx, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file not found: %s", path)
	}

	if s.serveDirectly {
		// Return URL for direct serving through the API
		// The actual file serving will be handled by a separate endpoint
		return fmt.Sprintf("%s/v1/files/%s", s.baseURL, path), nil
	}

	// Return file:// URL for local access
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))
	return fmt.Sprintf("file://%s", fullPath), nil
}

// Exists checks if a file exists at the specified path
func (s *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))

	_, err := os.Stat(fullPath)
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
	fullPath := filepath.Join(s.basePath, filepath.FromSlash(path))

	stat, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get file metadata: %w", err)
	}

	// Calculate checksum by reading the file
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for checksum: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	return &storage.FileMetadata{
		Path:         path,
		Size:         stat.Size(),
		Checksum:     checksum,
		LastModified: stat.ModTime(),
	}, nil
}

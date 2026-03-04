// Package storage defines the Backend interface and common types for all storage
// backends in the Terraform Registry.
//
// New backends are added by implementing the Backend interface and registering
// with the factory via an init() function in the backend's own package:
//
//	func init() {
//	    factory.Register("mybackend", func(cfg *config.Config) (Backend, error) {
//	        return NewMyBackend(cfg)
//	    })
//	}
//
// The main package imports each backend with a blank import to trigger init().
// This means adding a new backend requires no changes to the factory or main
// package — only a blank import in cmd/server/main.go.
package storage

import (
	"context"
	"io"
	"time"
)

// Storage defines the interface for all storage backends
// Implementations must support upload, download, delete, and URL generation
type Storage interface {
	// Upload stores a file and returns the storage result with path and checksum
	Upload(ctx context.Context, path string, reader io.Reader, size int64) (*UploadResult, error)

	// Download retrieves a file and returns a reader
	Download(ctx context.Context, path string) (io.ReadCloser, error)

	// Delete removes a file from storage
	Delete(ctx context.Context, path string) error

	// GetURL returns a direct download URL
	// For cloud storage, this generates a signed URL valid for the specified TTL
	// For local storage, this returns a path for serving
	GetURL(ctx context.Context, path string, ttl time.Duration) (string, error)

	// Exists checks if a file exists at the specified path
	Exists(ctx context.Context, path string) (bool, error)

	// GetMetadata retrieves file metadata without downloading the entire file
	GetMetadata(ctx context.Context, path string) (*FileMetadata, error)
}

// UploadResult contains information about an uploaded file
type UploadResult struct {
	// Path is the storage path where the file was stored
	Path string

	// Size is the file size in bytes
	Size int64

	// Checksum is the SHA256 hash of the file contents
	Checksum string
}

// FileMetadata contains metadata about a stored file
type FileMetadata struct {
	// Path is the storage path of the file
	Path string

	// Size is the file size in bytes
	Size int64

	// Checksum is the SHA256 hash of the file contents
	Checksum string

	// LastModified is the timestamp when the file was last modified
	LastModified time.Time
}

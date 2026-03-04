// Package gcs implements the Google Cloud Storage backend for the Terraform Registry. Downloads use
// time-limited signed URLs generated via the GCS signing API; the registry never proxies binary
// content. Supports Application Default Credentials, service account JSON keys, and Workload
// Identity Federation for keyless authentication in GKE and GitHub Actions environments.
package gcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	appconfig "github.com/terraform-registry/terraform-registry/internal/config"
	appstorage "github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	// Register GCS storage backend
	appstorage.Register("gcs", func(cfg *appconfig.Config) (appstorage.Storage, error) {
		return New(&cfg.Storage.GCS)
	})
}

// GCSStorage implements the Storage interface for Google Cloud Storage
type GCSStorage struct {
	client *storage.Client
	bucket string
}

// New creates a new Google Cloud Storage backend
//
// Authentication methods:
//   - "default" or empty: Uses Application Default Credentials (ADC)
//     This automatically supports:
//   - GOOGLE_APPLICATION_CREDENTIALS environment variable
//   - GCE/GKE metadata service
//   - Cloud Run/Cloud Functions service account
//   - gcloud auth application-default login
//   - "service_account": Uses a service account key file or JSON
//   - "workload_identity": Uses Workload Identity Federation (GKE, GitHub Actions, etc.)
func New(cfg *appconfig.GCSStorageConfig) (*GCSStorage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("gcs bucket name is required")
	}

	ctx := context.Background()
	var opts []option.ClientOption

	// Set custom endpoint for GCS emulators or compatible services
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(cfg.Endpoint))
	}

	// Determine authentication method
	authMethod := cfg.AuthMethod
	if authMethod == "" {
		// Default to ADC if no credentials specified
		if cfg.CredentialsFile != "" || cfg.CredentialsJSON != "" {
			authMethod = "service_account"
		} else {
			authMethod = "default"
		}
	}

	switch authMethod {
	case "service_account":
		// Use service account credentials
		if cfg.CredentialsJSON != "" {
			// Use JSON credentials directly
			opts = append(opts, option.WithCredentialsJSON([]byte(cfg.CredentialsJSON)))
		} else if cfg.CredentialsFile != "" {
			// Use credentials file path
			opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
		} else {
			return nil, fmt.Errorf("credentials_file or credentials_json is required for service_account auth")
		}

	case "workload_identity", "default":
		// Use Application Default Credentials (ADC)
		// This automatically handles:
		// - GOOGLE_APPLICATION_CREDENTIALS environment variable
		// - GCE/GKE metadata service (Workload Identity)
		// - Cloud Run/Cloud Functions service account
		// - gcloud auth application-default login
		// No additional options needed - the client will use ADC automatically

	default:
		return nil, fmt.Errorf("unsupported auth_method: %s (must be 'default', 'service_account', or 'workload_identity')", authMethod)
	}

	// Create GCS client
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	return &GCSStorage{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// Close closes the GCS client
func (s *GCSStorage) Close() error {
	return s.client.Close()
}

// Upload stores a file in GCS
func (s *GCSStorage) Upload(ctx context.Context, path string, reader io.Reader, size int64) (*appstorage.UploadResult, error) {
	// Read all content to calculate checksum
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Calculate SHA256 checksum
	hasher := sha256.New()
	hasher.Write(data)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Get object handle
	obj := s.client.Bucket(s.bucket).Object(path)

	// Create writer and upload
	writer := obj.NewWriter(ctx)
	writer.Metadata = map[string]string{
		"sha256": checksum,
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write to GCS: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close GCS writer: %w", err)
	}

	return &appstorage.UploadResult{
		Path:     path,
		Size:     int64(len(data)),
		Checksum: checksum,
	}, nil
}

// Download retrieves a file from GCS
func (s *GCSStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	obj := s.client.Bucket(s.bucket).Object(path)

	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read from GCS: %w", err)
	}

	return reader, nil
}

// Delete removes a file from GCS
func (s *GCSStorage) Delete(ctx context.Context, path string) error {
	obj := s.client.Bucket(s.bucket).Object(path)

	if err := obj.Delete(ctx); err != nil {
		// Check if object doesn't exist - that's okay
		if err == storage.ErrObjectNotExist {
			return nil
		}
		return fmt.Errorf("failed to delete from GCS: %w", err)
	}

	return nil
}

// GetURL returns a signed URL for downloading the file
func (s *GCSStorage) GetURL(ctx context.Context, path string, ttl time.Duration) (string, error) {
	// Check if file exists first
	exists, err := s.Exists(ctx, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file not found: %s", path)
	}

	// Generate signed URL
	// Note: This requires the service account to have the iam.serviceAccountTokenCreator role
	// or for ADC to have signBlob permissions
	opts := &storage.SignedURLOptions{
		Scheme:  storage.SigningSchemeV4,
		Method:  "GET",
		Expires: time.Now().Add(ttl),
	}

	url, err := s.client.Bucket(s.bucket).SignedURL(path, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate signed URL: %w", err)
	}

	return url, nil
}

// Exists checks if a file exists at the specified path
func (s *GCSStorage) Exists(ctx context.Context, path string) (bool, error) {
	obj := s.client.Bucket(s.bucket).Object(path)

	_, err := obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return false, nil
		}
		return false, fmt.Errorf("failed to check object existence: %w", err)
	}

	return true, nil
}

// GetMetadata retrieves file metadata without downloading the entire file
func (s *GCSStorage) GetMetadata(ctx context.Context, path string) (*appstorage.FileMetadata, error) {
	obj := s.client.Bucket(s.bucket).Object(path)

	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get object metadata: %w", err)
	}

	// Try to get SHA256 from metadata
	var checksum string
	if attrs.Metadata != nil {
		if sha256Val, ok := attrs.Metadata["sha256"]; ok {
			checksum = sha256Val
		}
	}

	// If no stored checksum, download and compute (expensive for large files)
	if checksum == "" {
		reader, err := s.Download(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to download for checksum: %w", err)
		}
		defer reader.Close()

		hasher := sha256.New()
		if _, err := io.Copy(hasher, reader); err != nil {
			return nil, fmt.Errorf("failed to compute checksum: %w", err)
		}
		checksum = hex.EncodeToString(hasher.Sum(nil))
	}

	return &appstorage.FileMetadata{
		Path:         path,
		Size:         attrs.Size,
		Checksum:     checksum,
		LastModified: attrs.Updated,
	}, nil
}

// EnsureBucket creates the bucket if it doesn't exist
func (s *GCSStorage) EnsureBucket(ctx context.Context, projectID string) error {
	bucket := s.client.Bucket(s.bucket)

	// Check if bucket exists
	_, err := bucket.Attrs(ctx)
	if err == nil {
		// Bucket exists
		return nil
	}

	if err != storage.ErrBucketNotExist {
		return fmt.Errorf("failed to check bucket: %w", err)
	}

	// Create the bucket
	if projectID == "" {
		return fmt.Errorf("project_id is required to create a bucket")
	}

	if err := bucket.Create(ctx, projectID, nil); err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	return nil
}

// SetStorageClass changes the storage class of an object
// Supported classes: STANDARD, NEARLINE, COLDLINE, ARCHIVE
func (s *GCSStorage) SetStorageClass(ctx context.Context, path string, storageClass string) error {
	src := s.client.Bucket(s.bucket).Object(path)
	dst := s.client.Bucket(s.bucket).Object(path)

	// Copy the object to itself with new storage class
	copier := dst.CopierFrom(src)
	copier.StorageClass = storageClass

	if _, err := copier.Run(ctx); err != nil {
		return fmt.Errorf("failed to change storage class: %w", err)
	}

	return nil
}

// ListObjects lists objects with a given prefix
func (s *GCSStorage) ListObjects(ctx context.Context, prefix string, maxResults int) ([]string, error) {
	query := &storage.Query{
		Prefix: prefix,
	}

	var objects []string
	it := s.client.Bucket(s.bucket).Objects(ctx, query)

	for i := 0; maxResults <= 0 || i < maxResults; i++ {
		attrs, err := it.Next()
		if err != nil {
			break // End of iteration
		}
		objects = append(objects, attrs.Name)
	}

	return objects, nil
}

// DeletePrefix deletes all objects with a given prefix
func (s *GCSStorage) DeletePrefix(ctx context.Context, prefix string) error {
	objects, err := s.ListObjects(ctx, prefix, 0)
	if err != nil {
		return err
	}

	for _, name := range objects {
		if err := s.Delete(ctx, name); err != nil {
			return fmt.Errorf("failed to delete %s: %w", name, err)
		}
	}

	return nil
}

// ComposeObjects combines multiple objects into a single object
// This is useful for multipart uploads or combining chunks
func (s *GCSStorage) ComposeObjects(ctx context.Context, destPath string, sourcePaths []string) error {
	if len(sourcePaths) == 0 {
		return fmt.Errorf("no source objects to compose")
	}
	if len(sourcePaths) > 32 {
		return fmt.Errorf("cannot compose more than 32 objects at once")
	}

	bucket := s.client.Bucket(s.bucket)
	dest := bucket.Object(destPath)

	sources := make([]*storage.ObjectHandle, len(sourcePaths))
	for i, path := range sourcePaths {
		sources[i] = bucket.Object(path)
	}

	composer := dest.ComposerFrom(sources...)

	if _, err := composer.Run(ctx); err != nil {
		return fmt.Errorf("failed to compose objects: %w", err)
	}

	return nil
}

// UploadResumable uploads a large file using resumable upload
// Recommended for files larger than 5MB
func (s *GCSStorage) UploadResumable(ctx context.Context, path string, reader io.Reader) (*appstorage.UploadResult, error) {
	obj := s.client.Bucket(s.bucket).Object(path)

	// Create resumable writer with chunked upload
	writer := obj.NewWriter(ctx)
	writer.ChunkSize = 16 * 1024 * 1024 // 16MB chunks

	// Calculate checksum while uploading
	hasher := sha256.New()
	teeReader := io.TeeReader(reader, hasher)

	written, err := io.Copy(writer, teeReader)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to GCS: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close GCS writer: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Update metadata with checksum
	obj = s.client.Bucket(s.bucket).Object(path)
	if _, err := obj.Update(ctx, storage.ObjectAttrsToUpdate{
		Metadata: map[string]string{
			"sha256": checksum,
		},
	}); err != nil {
		// Non-fatal: upload succeeded but metadata update failed
	}

	return &appstorage.UploadResult{
		Path:     path,
		Size:     written,
		Checksum: checksum,
	}, nil
}

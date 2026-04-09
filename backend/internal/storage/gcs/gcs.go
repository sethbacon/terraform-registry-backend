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
	"log/slog"
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

// ---------------------------------------------------------------------------
// Interfaces — abstract the GCS SDK's chained-handle pattern into flat calls
// ---------------------------------------------------------------------------

// gcsClientAPI abstracts the GCS SDK operations used by GCSStorage.
type gcsClientAPI interface {
	Close() error
	NewWriter(ctx context.Context, bucket, object string) gcsWriterAPI
	NewReader(ctx context.Context, bucket, object string) (io.ReadCloser, error)
	ObjectAttrs(ctx context.Context, bucket, object string) (*storage.ObjectAttrs, error)
	DeleteObject(ctx context.Context, bucket, object string) error
	UpdateObjectMetadata(ctx context.Context, bucket, object string, update storage.ObjectAttrsToUpdate) (*storage.ObjectAttrs, error)
	CopyObject(ctx context.Context, bucket, srcObject, dstObject, storageClass string) error
	ComposeObjects(ctx context.Context, bucket string, dst string, srcs []string) error
	BucketAttrs(ctx context.Context, bucket string) (*storage.BucketAttrs, error)
	CreateBucket(ctx context.Context, bucket, projectID string) error
	ListObjects(ctx context.Context, bucket string, query *storage.Query) gcsObjectIteratorAPI
	SignedURL(bucket, object string, opts *storage.SignedURLOptions) (string, error)
}

type gcsWriterAPI interface {
	io.WriteCloser
	SetMetadata(m map[string]string)
	SetChunkSize(s int)
}

type gcsObjectIteratorAPI interface {
	Next() (*storage.ObjectAttrs, error)
}

// ---------------------------------------------------------------------------
// Real wrappers — delegate to the concrete GCS SDK types
// ---------------------------------------------------------------------------

// realGCSClient wraps *storage.Client and implements gcsClientAPI. // coverage:skip:trivial-delegation
type realGCSClient struct {
	client *storage.Client
}

func (r *realGCSClient) Close() error {
	return r.client.Close()
}

func (r *realGCSClient) NewWriter(ctx context.Context, bucket, object string) gcsWriterAPI {
	w := r.client.Bucket(bucket).Object(object).NewWriter(ctx)
	return &realWriter{w: w}
}

func (r *realGCSClient) NewReader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	return r.client.Bucket(bucket).Object(object).NewReader(ctx)
}

func (r *realGCSClient) ObjectAttrs(ctx context.Context, bucket, object string) (*storage.ObjectAttrs, error) {
	return r.client.Bucket(bucket).Object(object).Attrs(ctx)
}

func (r *realGCSClient) DeleteObject(ctx context.Context, bucket, object string) error {
	return r.client.Bucket(bucket).Object(object).Delete(ctx)
}

func (r *realGCSClient) UpdateObjectMetadata(ctx context.Context, bucket, object string, update storage.ObjectAttrsToUpdate) (*storage.ObjectAttrs, error) {
	return r.client.Bucket(bucket).Object(object).Update(ctx, update)
}

func (r *realGCSClient) CopyObject(ctx context.Context, bucket, srcObject, dstObject, storageClass string) error {
	src := r.client.Bucket(bucket).Object(srcObject)
	dst := r.client.Bucket(bucket).Object(dstObject)
	copier := dst.CopierFrom(src)
	copier.StorageClass = storageClass
	_, err := copier.Run(ctx)
	return err
}

func (r *realGCSClient) ComposeObjects(ctx context.Context, bucket string, dst string, srcs []string) error {
	bkt := r.client.Bucket(bucket)
	sources := make([]*storage.ObjectHandle, len(srcs))
	for i, s := range srcs {
		sources[i] = bkt.Object(s)
	}
	composer := bkt.Object(dst).ComposerFrom(sources...)
	_, err := composer.Run(ctx)
	return err
}

func (r *realGCSClient) BucketAttrs(ctx context.Context, bucket string) (*storage.BucketAttrs, error) {
	return r.client.Bucket(bucket).Attrs(ctx)
}

func (r *realGCSClient) CreateBucket(ctx context.Context, bucket, projectID string) error {
	return r.client.Bucket(bucket).Create(ctx, projectID, nil)
}

func (r *realGCSClient) ListObjects(ctx context.Context, bucket string, query *storage.Query) gcsObjectIteratorAPI {
	return r.client.Bucket(bucket).Objects(ctx, query)
}

func (r *realGCSClient) SignedURL(bucket, object string, opts *storage.SignedURLOptions) (string, error) {
	return r.client.Bucket(bucket).SignedURL(object, opts)
}

// realWriter wraps *storage.Writer and implements gcsWriterAPI. // coverage:skip:trivial-delegation
type realWriter struct {
	w *storage.Writer
}

func (rw *realWriter) Write(p []byte) (int, error)     { return rw.w.Write(p) }
func (rw *realWriter) Close() error                    { return rw.w.Close() }
func (rw *realWriter) SetMetadata(m map[string]string) { rw.w.Metadata = m }
func (rw *realWriter) SetChunkSize(s int)              { rw.w.ChunkSize = s }

// ---------------------------------------------------------------------------
// GCSStorage
// ---------------------------------------------------------------------------

// GCSStorage implements the Storage interface for Google Cloud Storage
type GCSStorage struct {
	client gcsClientAPI
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
			opts = append(opts, option.WithCredentialsJSON([]byte(cfg.CredentialsJSON))) //nolint:staticcheck // SA1019: replacement requires ADC/WIF refactor; tracked for future update
		} else if cfg.CredentialsFile != "" {
			// Use credentials file path
			opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile)) //nolint:staticcheck // SA1019: replacement requires ADC/WIF refactor; tracked for future update
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
		client: &realGCSClient{client: client},
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

	// Create writer and upload
	writer := s.client.NewWriter(ctx, s.bucket, path)
	writer.SetMetadata(map[string]string{
		"sha256": checksum,
	})

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
	reader, err := s.client.NewReader(ctx, s.bucket, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read from GCS: %w", err)
	}

	return reader, nil
}

// Delete removes a file from GCS
func (s *GCSStorage) Delete(ctx context.Context, path string) error {
	if err := s.client.DeleteObject(ctx, s.bucket, path); err != nil {
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
	opts := &storage.SignedURLOptions{
		Scheme:  storage.SigningSchemeV4,
		Method:  "GET",
		Expires: time.Now().Add(ttl),
	}

	url, err := s.client.SignedURL(s.bucket, path, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate signed URL: %w", err)
	}

	return url, nil
}

// Exists checks if a file exists at the specified path
func (s *GCSStorage) Exists(ctx context.Context, path string) (bool, error) {
	_, err := s.client.ObjectAttrs(ctx, s.bucket, path)
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
	attrs, err := s.client.ObjectAttrs(ctx, s.bucket, path)
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
	// Check if bucket exists
	_, err := s.client.BucketAttrs(ctx, s.bucket)
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

	if err := s.client.CreateBucket(ctx, s.bucket, projectID); err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	return nil
}

// SetStorageClass changes the storage class of an object
// Supported classes: STANDARD, NEARLINE, COLDLINE, ARCHIVE
func (s *GCSStorage) SetStorageClass(ctx context.Context, path string, storageClass string) error {
	if err := s.client.CopyObject(ctx, s.bucket, path, path, storageClass); err != nil {
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
	it := s.client.ListObjects(ctx, s.bucket, query)

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

	if err := s.client.ComposeObjects(ctx, s.bucket, destPath, sourcePaths); err != nil {
		return fmt.Errorf("failed to compose objects: %w", err)
	}

	return nil
}

// UploadResumable uploads a large file using resumable upload
// Recommended for files larger than 5MB
func (s *GCSStorage) UploadResumable(ctx context.Context, path string, reader io.Reader) (*appstorage.UploadResult, error) {
	// Create resumable writer with chunked upload
	writer := s.client.NewWriter(ctx, s.bucket, path)
	writer.SetChunkSize(16 * 1024 * 1024) // 16MB chunks

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
	if _, err := s.client.UpdateObjectMetadata(ctx, s.bucket, path, storage.ObjectAttrsToUpdate{
		Metadata: map[string]string{
			"sha256": checksum,
		},
	}); err != nil {
		slog.Warn("failed to update GCS object metadata with checksum", "path", path, "error", err)
	}

	return &appstorage.UploadResult{
		Path:     path,
		Size:     written,
		Checksum: checksum,
	}, nil
}

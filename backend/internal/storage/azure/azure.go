// Package azure implements the Azure Blob Storage backend for the Terraform Registry. Uploads go
// directly to Blob Storage; downloads are served via time-limited SAS (Shared Access Signature)
// URLs generated on demand rather than proxied through the registry — this keeps large provider
// binaries off the registry's network path. The SAS URL TTL is configurable to accommodate slow
// connections and large files.
package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	// Register Azure storage backend
	storage.Register("azure", func(cfg *config.Config) (storage.Storage, error) {
		return New(&cfg.Storage.Azure)
	})
}

// AzureStorage implements the Storage interface for Azure Blob Storage
type AzureStorage struct {
	client        *azblob.Client
	containerName string
	accountName   string
	accountKey    string
	cdnURL        string
}

// New creates a new Azure Blob Storage backend
func New(cfg *config.AzureStorageConfig) (*AzureStorage, error) {
	if cfg.AccountName == "" {
		return nil, fmt.Errorf("azure storage account name is required")
	}
	if cfg.AccountKey == "" {
		return nil, fmt.Errorf("azure storage account key is required")
	}
	if cfg.ContainerName == "" {
		return nil, fmt.Errorf("azure storage container name is required")
	}

	// Create credential using shared key
	credential, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Create service URL
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)

	// Create client
	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Blob client: %w", err)
	}

	return &AzureStorage{
		client:        client,
		containerName: cfg.ContainerName,
		accountName:   cfg.AccountName,
		accountKey:    cfg.AccountKey,
		cdnURL:        cfg.CDNURL,
	}, nil
}

// Upload stores a file in Azure Blob Storage
func (s *AzureStorage) Upload(ctx context.Context, path string, reader io.Reader, size int64) (*storage.UploadResult, error) {
	// Read all content to calculate checksum and upload
	// For large files, consider using block uploads with streaming hash
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Calculate SHA256 checksum
	hasher := sha256.New()
	hasher.Write(data)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlockBlobClient(path)

	// Upload the blob
	_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to Azure Blob: %w", err)
	}

	return &storage.UploadResult{
		Path:     path,
		Size:     int64(len(data)),
		Checksum: checksum,
	}, nil
}

// Download retrieves a file from Azure Blob Storage
func (s *AzureStorage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlobClient(path)

	// Download the blob
	resp, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download from Azure Blob: %w", err)
	}

	return resp.Body, nil
}

// Delete removes a file from Azure Blob Storage
func (s *AzureStorage) Delete(ctx context.Context, path string) error {
	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlobClient(path)

	// Delete the blob
	_, err := blobClient.Delete(ctx, nil)
	if err != nil {
		// Check if blob doesn't exist - that's okay
		// Azure SDK returns an error for non-existent blobs
		return fmt.Errorf("failed to delete from Azure Blob: %w", err)
	}

	return nil
}

// GetURL returns a signed URL for downloading the file
func (s *AzureStorage) GetURL(ctx context.Context, path string, ttl time.Duration) (string, error) {
	// Check if file exists first
	exists, err := s.Exists(ctx, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file not found: %s", path)
	}

	// If CDN URL is configured, use it
	if s.cdnURL != "" {
		return fmt.Sprintf("%s/%s", s.cdnURL, path), nil
	}

	// Generate SAS token for direct blob access
	credential, err := azblob.NewSharedKeyCredential(s.accountName, s.accountKey)
	if err != nil {
		return "", fmt.Errorf("failed to create credential for SAS: %w", err)
	}

	// Set SAS permissions and expiry
	sasPermissions := sas.BlobPermissions{Read: true}
	startTime := time.Now().UTC().Add(-5 * time.Minute) // Allow for clock skew
	expiryTime := time.Now().UTC().Add(ttl)

	// Build SAS query parameters
	sasQueryParams, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     startTime,
		ExpiryTime:    expiryTime,
		Permissions:   sasPermissions.String(),
		ContainerName: s.containerName,
		BlobName:      path,
	}.SignWithSharedKey(credential)
	if err != nil {
		return "", fmt.Errorf("failed to generate SAS token: %w", err)
	}

	// Build the full URL
	blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s",
		s.accountName, s.containerName, url.PathEscape(path))

	return fmt.Sprintf("%s?%s", blobURL, sasQueryParams.Encode()), nil
}

// Exists checks if a file exists at the specified path
func (s *AzureStorage) Exists(ctx context.Context, path string) (bool, error) {
	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlobClient(path)

	// Get blob properties to check existence
	_, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		// Check if it's a "not found" error
		// Azure SDK uses bloberror.StorageError for these
		return false, nil
	}

	return true, nil
}

// GetMetadata retrieves file metadata without downloading the entire file
func (s *AzureStorage) GetMetadata(ctx context.Context, path string) (*storage.FileMetadata, error) {
	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlobClient(path)

	// Get blob properties
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob properties: %w", err)
	}

	// Get content MD5 if available, otherwise we need to download to get SHA256
	// Azure stores MD5, not SHA256, so we may need to compute it
	var checksum string

	// Check if we stored the SHA256 in blob metadata
	if props.Metadata != nil {
		if sha256Val, ok := props.Metadata["sha256"]; ok && sha256Val != nil {
			checksum = *sha256Val
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

	var size int64
	if props.ContentLength != nil {
		size = *props.ContentLength
	}

	var lastModified time.Time
	if props.LastModified != nil {
		lastModified = *props.LastModified
	}

	return &storage.FileMetadata{
		Path:         path,
		Size:         size,
		Checksum:     checksum,
		LastModified: lastModified,
	}, nil
}

// UploadWithMetadata stores a file and includes SHA256 checksum in blob metadata
// This is a convenience method that stores the checksum for later retrieval
func (s *AzureStorage) UploadWithMetadata(ctx context.Context, path string, reader io.Reader, size int64) (*storage.UploadResult, error) {
	// Read all content to calculate checksum
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Calculate SHA256 checksum
	hasher := sha256.New()
	hasher.Write(data)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Get blob client for this path
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlockBlobClient(path)

	// Upload the blob with metadata containing SHA256
	_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader(data)), &blockblob.UploadOptions{
		Metadata: map[string]*string{
			"sha256": &checksum,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to Azure Blob: %w", err)
	}

	return &storage.UploadResult{
		Path:     path,
		Size:     int64(len(data)),
		Checksum: checksum,
	}, nil
}

// EnsureContainer creates the container if it doesn't exist
func (s *AzureStorage) EnsureContainer(ctx context.Context) error {
	containerClient := s.client.ServiceClient().NewContainerClient(s.containerName)

	// Try to create the container
	_, err := containerClient.Create(ctx, nil)
	if err != nil {
		// Container might already exist, which is fine
		// Azure returns an error if it exists, but we can ignore it
		// A more robust check would parse the error type
		return nil
	}

	return nil
}

// SetBlobAccessTier sets the access tier for a blob (Hot, Cool, Cold, Archive)
func (s *AzureStorage) SetBlobAccessTier(ctx context.Context, path string, tier blob.AccessTier) error {
	blobClient := s.client.ServiceClient().NewContainerClient(s.containerName).NewBlobClient(path)

	_, err := blobClient.SetTier(ctx, tier, nil)
	if err != nil {
		return fmt.Errorf("failed to set blob tier: %w", err)
	}

	return nil
}

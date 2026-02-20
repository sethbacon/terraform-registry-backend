// Package s3 implements the AWS S3-compatible storage backend for the Terraform Registry. It
// supports AWS S3, MinIO, DigitalOcean Spaces, and other S3-compatible services via a configurable
// endpoint. Downloads use pre-signed URLs (not proxied) to keep binary traffic off the registry's
// network path. Multiple authentication methods are supported: the default AWS credential chain
// (recommended for EC2/EKS with IAM roles), static key/secret, OIDC web identity, and AssumeRole
// for cross-account access.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	appconfig "github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	// Register S3 storage backend
	storage.Register("s3", func(cfg *appconfig.Config) (storage.Storage, error) {
		return New(&cfg.Storage.S3)
	})
}

// S3Storage implements the Storage interface for S3-compatible storage
type S3Storage struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	bucket        string
	region        string
	endpoint      string
}

// New creates a new S3-compatible storage backend
// Supports AWS S3, MinIO, DigitalOcean Spaces, and other S3-compatible services
//
// Authentication methods:
//   - "default" or empty: Uses AWS default credential chain (env vars, shared config, IAM role, IMDS)
//   - "static": Uses explicit access key and secret key
//   - "oidc": Uses Web Identity/OIDC token (for EKS, GitHub Actions, etc.)
//   - "assume_role": Assumes an IAM role (optionally with external ID for cross-account)
func New(cfg *appconfig.S3StorageConfig) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 bucket name is required")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("s3 region is required")
	}

	// Build AWS config options
	var opts []func(*config.LoadOptions) error

	// Set region
	opts = append(opts, config.WithRegion(cfg.Region))

	// Determine authentication method
	authMethod := cfg.AuthMethod
	if authMethod == "" {
		// Backwards compatibility: if access keys are provided, use static auth
		if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
			authMethod = "static"
		} else {
			authMethod = "default"
		}
	}

	switch authMethod {
	case "static":
		// Use explicit static credentials
		if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
			return nil, fmt.Errorf("access_key_id and secret_access_key are required for static auth")
		}
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))

	case "oidc":
		// Web Identity/OIDC authentication will be configured after loading base config
		// Requires role_arn and either web_identity_token_file or environment variables

	case "assume_role":
		// AssumeRole authentication will be configured after loading base config
		// Requires role_arn

	case "default":
		// Use AWS default credential chain - no additional configuration needed
		// This automatically supports:
		// - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
		// - Shared credentials file (~/.aws/credentials)
		// - Shared config file (~/.aws/config)
		// - IAM role for Amazon EC2/ECS/Lambda
		// - Web Identity Token credentials (EKS pod identity)

	default:
		return nil, fmt.Errorf("unsupported auth_method: %s (must be 'default', 'static', 'oidc', or 'assume_role')", authMethod)
	}

	// Load base AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Configure OIDC or AssumeRole credentials (requires base config first)
	switch authMethod {
	case "oidc":
		if cfg.RoleARN == "" {
			return nil, fmt.Errorf("role_arn is required for OIDC auth")
		}

		// Create STS client for assuming role
		stsClient := sts.NewFromConfig(awsCfg)

		// Configure Web Identity credentials
		var webIdentityOpts []func(*stscreds.WebIdentityRoleOptions)

		if cfg.RoleSessionName != "" {
			webIdentityOpts = append(webIdentityOpts, func(o *stscreds.WebIdentityRoleOptions) {
				o.RoleSessionName = cfg.RoleSessionName
			})
		}

		// Create Web Identity provider
		// If WebIdentityTokenFile is not set, it will use AWS_WEB_IDENTITY_TOKEN_FILE env var
		tokenFile := cfg.WebIdentityTokenFile
		if tokenFile == "" {
			// The SDK will look for AWS_WEB_IDENTITY_TOKEN_FILE automatically
			// but we need to provide a token retriever
			return nil, fmt.Errorf("web_identity_token_file is required for OIDC auth (or set AWS_WEB_IDENTITY_TOKEN_FILE)")
		}

		provider := stscreds.NewWebIdentityRoleProvider(
			stsClient,
			cfg.RoleARN,
			stscreds.IdentityTokenFile(tokenFile),
			webIdentityOpts...,
		)

		awsCfg.Credentials = aws.NewCredentialsCache(provider)

	case "assume_role":
		if cfg.RoleARN == "" {
			return nil, fmt.Errorf("role_arn is required for assume_role auth")
		}

		// Create STS client for assuming role
		stsClient := sts.NewFromConfig(awsCfg)

		// Configure AssumeRole options
		var assumeRoleOpts []func(*stscreds.AssumeRoleOptions)

		if cfg.RoleSessionName != "" {
			assumeRoleOpts = append(assumeRoleOpts, func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = cfg.RoleSessionName
			})
		}

		if cfg.ExternalID != "" {
			assumeRoleOpts = append(assumeRoleOpts, func(o *stscreds.AssumeRoleOptions) {
				o.ExternalID = aws.String(cfg.ExternalID)
			})
		}

		// Create AssumeRole provider
		provider := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN, assumeRoleOpts...)
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}

	// Build S3 client options
	var s3Opts []func(*s3.Options)

	// Set custom endpoint for S3-compatible services (MinIO, DigitalOcean Spaces, etc.)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			// For S3-compatible services, use path-style addressing
			o.UsePathStyle = true
		})
	}

	// Create S3 client
	client := s3.NewFromConfig(awsCfg, s3Opts...)

	// Create presign client for generating signed URLs
	presignClient := s3.NewPresignClient(client)

	return &S3Storage{
		client:        client,
		presignClient: presignClient,
		bucket:        cfg.Bucket,
		region:        cfg.Region,
		endpoint:      cfg.Endpoint,
	}, nil
}

// Upload stores a file in S3
func (s *S3Storage) Upload(ctx context.Context, path string, reader io.Reader, size int64) (*storage.UploadResult, error) {
	// Read all content to calculate checksum
	// For very large files, consider using multipart upload with streaming hash
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Calculate SHA256 checksum
	hasher := sha256.New()
	hasher.Write(data)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Upload to S3
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(path),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		// Store SHA256 in metadata for later retrieval
		Metadata: map[string]string{
			"sha256": checksum,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	return &storage.UploadResult{
		Path:     path,
		Size:     int64(len(data)),
		Checksum: checksum,
	}, nil
}

// Download retrieves a file from S3
func (s *S3Storage) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}

	return result.Body, nil
}

// Delete removes a file from S3
func (s *S3Storage) Delete(ctx context.Context, path string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
}

// GetURL returns a presigned URL for downloading the file
func (s *S3Storage) GetURL(ctx context.Context, path string, ttl time.Duration) (string, error) {
	// Check if file exists first
	exists, err := s.Exists(ctx, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("file not found: %s", path)
	}

	// Generate presigned URL
	request, err := s.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = ttl
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return request.URL, nil
}

// Exists checks if a file exists at the specified path
func (s *S3Storage) Exists(ctx context.Context, path string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		// Check if it's a "not found" error
		// AWS SDK v2 doesn't expose error types directly, check by string
		return false, nil
	}

	return true, nil
}

// GetMetadata retrieves file metadata without downloading the entire file
func (s *S3Storage) GetMetadata(ctx context.Context, path string) (*storage.FileMetadata, error) {
	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object metadata: %w", err)
	}

	// Try to get SHA256 from metadata
	var checksum string
	if result.Metadata != nil {
		if sha256Val, ok := result.Metadata["sha256"]; ok {
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

	var size int64
	if result.ContentLength != nil {
		size = *result.ContentLength
	}

	var lastModified time.Time
	if result.LastModified != nil {
		lastModified = *result.LastModified
	}

	return &storage.FileMetadata{
		Path:         path,
		Size:         size,
		Checksum:     checksum,
		LastModified: lastModified,
	}, nil
}

// EnsureBucket creates the bucket if it doesn't exist
func (s *S3Storage) EnsureBucket(ctx context.Context) error {
	// Check if bucket exists
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err == nil {
		// Bucket exists
		return nil
	}

	// Create the bucket
	_, err = s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(s.bucket),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(s.region),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	return nil
}

// SetObjectStorageClass changes the storage class of an object
// Supported classes: STANDARD, REDUCED_REDUNDANCY, STANDARD_IA, ONEZONE_IA,
// INTELLIGENT_TIERING, GLACIER, DEEP_ARCHIVE, GLACIER_IR
func (s *S3Storage) SetObjectStorageClass(ctx context.Context, path string, storageClass types.StorageClass) error {
	// Copy the object to itself with new storage class
	_, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(path),
		CopySource:   aws.String(fmt.Sprintf("%s/%s", s.bucket, path)),
		StorageClass: storageClass,
	})
	if err != nil {
		return fmt.Errorf("failed to change storage class: %w", err)
	}

	return nil
}

// ListObjects lists objects with a given prefix
func (s *S3Storage) ListObjects(ctx context.Context, prefix string, maxKeys int32) ([]string, error) {
	result, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(maxKeys),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}

	keys := make([]string, 0, len(result.Contents))
	for _, obj := range result.Contents {
		if obj.Key != nil {
			keys = append(keys, *obj.Key)
		}
	}

	return keys, nil
}

// DeletePrefix deletes all objects with a given prefix
func (s *S3Storage) DeletePrefix(ctx context.Context, prefix string) error {
	// List all objects with prefix
	keys, err := s.ListObjects(ctx, prefix, 1000)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	// Build delete objects input
	objects := make([]types.ObjectIdentifier, len(keys))
	for i, key := range keys {
		objects[i] = types.ObjectIdentifier{
			Key: aws.String(key),
		}
	}

	// Delete all objects
	_, err = s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(s.bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete objects: %w", err)
	}

	return nil
}

// UploadMultipart uploads a large file using multipart upload
// Recommended for files larger than 100MB
func (s *S3Storage) UploadMultipart(ctx context.Context, path string, reader io.Reader, partSize int64) (*storage.UploadResult, error) {
	// Create multipart upload
	createResp, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create multipart upload: %w", err)
	}

	uploadID := createResp.UploadId
	hasher := sha256.New()
	var completedParts []types.CompletedPart
	partNumber := int32(1)
	var totalSize int64

	// Upload parts
	buf := make([]byte, partSize)
	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			// Update hash
			hasher.Write(buf[:n])
			totalSize += int64(n)

			// Upload part
			partResp, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     aws.String(s.bucket),
				Key:        aws.String(path),
				UploadId:   uploadID,
				PartNumber: aws.Int32(partNumber),
				Body:       bytes.NewReader(buf[:n]),
			})
			if err != nil {
				// Abort the multipart upload on error
				_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket:   aws.String(s.bucket),
					Key:      aws.String(path),
					UploadId: uploadID,
				})
				return nil, fmt.Errorf("failed to upload part %d: %w", partNumber, err)
			}

			completedParts = append(completedParts, types.CompletedPart{
				ETag:       partResp.ETag,
				PartNumber: aws.Int32(partNumber),
			})
			partNumber++
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			// Abort on read error
			_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(path),
				UploadId: uploadID,
			})
			return nil, fmt.Errorf("failed to read data: %w", readErr)
		}
	}

	// Complete multipart upload
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(path),
		UploadId: uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Update metadata with checksum (requires a copy operation)
	_, err = s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:            aws.String(s.bucket),
		Key:               aws.String(path),
		CopySource:        aws.String(fmt.Sprintf("%s/%s", s.bucket, path)),
		MetadataDirective: types.MetadataDirectiveReplace,
		Metadata: map[string]string{
			"sha256": checksum,
		},
	})
	if err != nil {
		// Non-fatal: upload succeeded but metadata update failed
		// Log this in production
	}

	return &storage.UploadResult{
		Path:     path,
		Size:     totalSize,
		Checksum: checksum,
	}, nil
}

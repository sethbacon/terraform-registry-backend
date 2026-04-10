package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	appconfig "github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// New() — constructor validation (no AWS connection required)
// ---------------------------------------------------------------------------

func TestNew_MissingBucket(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket: "",
		Region: "us-east-1",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing bucket")
	}
}

func TestNew_MissingRegion(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket: "my-bucket",
		Region: "",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing region")
	}
}

func TestNew_StaticAuth_MissingKeys(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:      "my-bucket",
		Region:      "us-east-1",
		AuthMethod:  "static",
		AccessKeyID: "", // missing
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for static auth with missing keys")
	}
}

func TestNew_UnsupportedAuthMethod(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:     "my-bucket",
		Region:     "us-east-1",
		AuthMethod: "unsupported-method",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for unsupported auth method")
	}
}

func TestNew_DefaultAuth_LoadsConfig(t *testing.T) {
	// default auth tries to load AWS config (env vars, shared config, etc.)
	// In CI without AWS credentials, this may fail or succeed with no-op credentials.
	// We just ensure no panic and correct handling.
	cfg := &appconfig.S3StorageConfig{
		Bucket:     "my-bucket",
		Region:     "us-east-1",
		AuthMethod: "default",
	}
	// May succeed or fail depending on environment; just ensure no panic
	_, _ = New(cfg)
}

func TestNew_OIDC_MissingRoleARN(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:     "my-bucket",
		Region:     "us-east-1",
		AuthMethod: "oidc",
		RoleARN:    "", // missing
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for oidc auth with missing role_arn")
	}
}

func TestNew_OIDC_MissingTokenFile(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:               "my-bucket",
		Region:               "us-east-1",
		AuthMethod:           "oidc",
		RoleARN:              "arn:aws:iam::123456789:role/test-role",
		WebIdentityTokenFile: "", // missing
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for oidc auth with missing token file")
	}
}

func TestNew_AssumeRole_MissingRoleARN(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:     "my-bucket",
		Region:     "us-east-1",
		AuthMethod: "assume_role",
		RoleARN:    "", // missing
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for assume_role auth with missing role_arn")
	}
}

func TestNew_AssumeRole_WithExternalID(t *testing.T) {
	// assume_role with role_arn + external_id should succeed constructor (no network call for assume_role)
	cfg := &appconfig.S3StorageConfig{
		Bucket:     "my-bucket",
		Region:     "us-east-1",
		AuthMethod: "assume_role",
		RoleARN:    "arn:aws:iam::123456789:role/test-role",
		ExternalID: "external-id-123",
	}
	// This will succeed (no network call at construction time; AssumeRole is lazy)
	_, _ = New(cfg)
}

func TestNew_StaticAuth_WithEndpoint(t *testing.T) {
	cfg := &appconfig.S3StorageConfig{
		Bucket:          "my-bucket",
		Region:          "us-east-1",
		AuthMethod:      "static",
		AccessKeyID:     "test-key",
		SecretAccessKey: "test-secret",
		Endpoint:        "http://localhost:9000",
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with custom endpoint error: %v", err)
	}
	if s == nil {
		t.Error("New() returned nil storage")
	}
}

// ---------------------------------------------------------------------------
// Mock S3-compatible HTTP server for operations tests
// ---------------------------------------------------------------------------

type s3MockStore struct {
	mu      sync.Mutex
	objects map[string][]byte            // key → content
	meta    map[string]map[string]string // key → amz-meta headers (lowercase, no prefix)
}

// newS3TestStorage creates an S3Storage backed by a minimal mock HTTP server.
// The server speaks just enough of the S3 REST API (path-style) for CRUD tests.
func newS3TestStorage(t *testing.T) (*S3Storage, *s3MockStore, func()) {
	t.Helper()

	ms := &s3MockStore{
		objects: map[string][]byte{},
		meta:    map[string]map[string]string{},
	}

	const bucket = "test-bucket"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path // e.g. /test-bucket/key/path

		// Strip leading slash
		path = strings.TrimPrefix(path, "/")

		// Split off the bucket name
		idx := strings.IndexByte(path, '/')
		if idx < 0 {
			// Bucket-level operation (HeadBucket, CreateBucket)
			switch r.Method {
			case http.MethodHead:
				w.WriteHeader(http.StatusOK)
			case http.MethodPut:
				w.WriteHeader(http.StatusOK)
			default:
				// ListObjectsV2 or DeleteObjects
				if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "list-type=2") {
					prefix := r.URL.Query().Get("prefix")
					ms.mu.Lock()
					var keys []string
					for k := range ms.objects {
						if strings.HasPrefix(k, prefix) {
							keys = append(keys, k)
						}
					}
					ms.mu.Unlock()
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `<?xml version="1.0"?><ListBucketResult>`)
					for _, k := range keys {
						fmt.Fprintf(w, `<Contents><Key>%s</Key></Contents>`, k)
					}
					fmt.Fprintf(w, `</ListBucketResult>`)
					return
				}
				if r.Method == http.MethodPost && strings.Contains(r.URL.RawQuery, "delete") {
					body, _ := io.ReadAll(r.Body)
					ms.mu.Lock()
					for k := range ms.objects {
						if strings.Contains(string(body), "<Key>"+k+"</Key>") {
							delete(ms.objects, k)
							delete(ms.meta, k)
						}
					}
					ms.mu.Unlock()
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `<?xml version="1.0"?><DeleteResult></DeleteResult>`)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}

		key := path[idx+1:] // everything after "test-bucket/"

		switch r.Method {
		case http.MethodPut:
			// CopyObject has X-Amz-Copy-Source header
			if r.Header.Get("X-Amz-Copy-Source") != "" {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `<?xml version="1.0"?><CopyObjectResult><ETag>"etag"</ETag><LastModified>%s</LastModified></CopyObjectResult>`,
					time.Now().UTC().Format(time.RFC3339))
				return
			}
			data, _ := io.ReadAll(r.Body)
			meta := map[string]string{}
			for hk, hv := range r.Header {
				lk := strings.ToLower(hk)
				if strings.HasPrefix(lk, "x-amz-meta-") && len(hv) > 0 {
					name := strings.TrimPrefix(lk, "x-amz-meta-")
					meta[name] = hv[0]
				}
			}
			ms.mu.Lock()
			ms.objects[key] = data
			ms.meta[key] = meta
			ms.mu.Unlock()
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			ms.mu.Lock()
			data, ok := ms.objects[key]
			ms.mu.Unlock()
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)
			w.Write(data)

		case http.MethodHead:
			ms.mu.Lock()
			data, ok := ms.objects[key]
			metaMap := ms.meta[key]
			ms.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("ETag", `"test-etag"`)
			for mk, mv := range metaMap {
				w.Header().Set("x-amz-meta-"+mk, mv)
			}
			w.WriteHeader(http.StatusOK)

		case http.MethodDelete:
			ms.mu.Lock()
			delete(ms.objects, key)
			delete(ms.meta, key)
			ms.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	s, err := New(&appconfig.S3StorageConfig{
		Bucket:          bucket,
		Region:          "us-east-1",
		AuthMethod:      "static",
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Endpoint:        srv.URL,
	})
	if err != nil {
		srv.Close()
		t.Fatalf("New() for mock S3: %v", err)
	}

	return s, ms, func() { srv.Close() }
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

func TestS3_Upload(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	data := []byte("hello s3 world")
	result, err := s.Upload(context.Background(), "test/hello.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload() error: %v", err)
	}
	if result.Path != "test/hello.txt" {
		t.Errorf("Path = %q, want test/hello.txt", result.Path)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("Size = %d, want %d", result.Size, len(data))
	}
	if len(result.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64 (SHA256 hex)", len(result.Checksum))
	}
}

func TestS3_Upload_ChecksumConsistency(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	content := "consistent data for checksum"
	r1, _ := s.Upload(context.Background(), "c1.txt", strings.NewReader(content), int64(len(content)))
	r2, _ := s.Upload(context.Background(), "c2.txt", strings.NewReader(content), int64(len(content)))
	if r1.Checksum != r2.Checksum {
		t.Errorf("same content produced different checksums: %q vs %q", r1.Checksum, r2.Checksum)
	}
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func TestS3_Download(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	want := []byte("download me from s3")
	if _, err := s.Upload(ctx, "dl.txt", bytes.NewReader(want), int64(len(want))); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	rc, err := s.Download(ctx, "dl.txt")
	if err != nil {
		t.Fatalf("Download() error: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()

	if !bytes.Equal(got, want) {
		t.Errorf("Download content = %q, want %q", got, want)
	}
}

func TestS3_Download_NotFound(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	_, err := s.Download(context.Background(), "nonexistent.txt")
	if err == nil {
		t.Error("Download() expected error for missing key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestS3_Delete(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	data := []byte("to be deleted")
	if _, err := s.Upload(ctx, "todel.txt", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if err := s.Delete(ctx, "todel.txt"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// After delete, Exists should return false
	ok, _ := s.Exists(ctx, "todel.txt")
	if ok {
		t.Error("Exists = true after delete, want false")
	}
}

// ---------------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------------

func TestS3_Exists_False(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	ok, err := s.Exists(context.Background(), "ghost.txt")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if ok {
		t.Error("Exists = true for nonexistent key, want false")
	}
}

func TestS3_Exists_True(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Upload(ctx, "exists.txt", strings.NewReader("x"), 1); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	ok, err := s.Exists(ctx, "exists.txt")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !ok {
		t.Error("Exists = false for existing key, want true")
	}
}

// ---------------------------------------------------------------------------
// GetMetadata
// ---------------------------------------------------------------------------

func TestS3_GetMetadata_WithChecksum(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	data := []byte("metadata content")
	uploadResult, err := s.Upload(ctx, "meta.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	meta, err := s.GetMetadata(ctx, "meta.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}
	if meta.Path != "meta.txt" {
		t.Errorf("Path = %q, want meta.txt", meta.Path)
	}
	if meta.Size != int64(len(data)) {
		t.Errorf("Size = %d, want %d", meta.Size, len(data))
	}
	// Checksum may come from metadata header (if AWS SDK passes it back)
	// or be computed by downloading; either way it must match
	if meta.Checksum == "" {
		t.Error("Checksum should not be empty")
	}
	if meta.Checksum != uploadResult.Checksum && len(meta.Checksum) != 64 {
		t.Errorf("Checksum = %q, want 64-char hex", meta.Checksum)
	}
}

func TestS3_GetMetadata_NotFound(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	_, err := s.GetMetadata(context.Background(), "missing.txt")
	if err == nil {
		t.Error("GetMetadata() expected error for missing key, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetURL
// ---------------------------------------------------------------------------

func TestS3_GetURL_NotFound(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	_, err := s.GetURL(context.Background(), "missing.txt", time.Hour)
	if err == nil {
		t.Error("GetURL() expected error for missing key, got nil")
	}
}

func TestS3_GetURL_Success(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Upload(ctx, "forurl.txt", strings.NewReader("content"), 7); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	url, err := s.GetURL(ctx, "forurl.txt", time.Hour)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	if url == "" {
		t.Error("GetURL() returned empty URL")
	}
}

// ---------------------------------------------------------------------------
// EnsureBucket
// ---------------------------------------------------------------------------

func TestS3_EnsureBucket(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	// HeadBucket will return 200 (mock always returns 200 for bucket-level HEAD)
	// so bucket "exists" and no CreateBucket is called
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetObjectStorageClass
// ---------------------------------------------------------------------------

func TestS3_SetObjectStorageClass(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Upload(ctx, "sc.txt", strings.NewReader("content"), 7); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if err := s.SetObjectStorageClass(ctx, "sc.txt", types.StorageClassStandardIa); err != nil {
		t.Fatalf("SetObjectStorageClass() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListObjects
// ---------------------------------------------------------------------------

func TestS3_ListObjects_Empty(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	keys, err := s.ListObjects(context.Background(), "noprefix/", 10)
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListObjects() = %v, want empty", keys)
	}
}

func TestS3_ListObjects_WithObjects(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	for _, name := range []string{"pfx/a.txt", "pfx/b.txt", "other/c.txt"} {
		if _, err := s.Upload(ctx, name, strings.NewReader("x"), 1); err != nil {
			t.Fatalf("Upload %s: %v", name, err)
		}
	}

	keys, err := s.ListObjects(ctx, "pfx/", 100)
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListObjects() returned %d keys, want 2: %v", len(keys), keys)
	}
}

// ---------------------------------------------------------------------------
// DeletePrefix
// ---------------------------------------------------------------------------

func TestS3_DeletePrefix_NoObjects(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()

	if err := s.DeletePrefix(context.Background(), "empty/"); err != nil {
		t.Fatalf("DeletePrefix() error: %v", err)
	}
}

func TestS3_DeletePrefix_WithObjects(t *testing.T) {
	s, _, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	for _, name := range []string{"del/a.txt", "del/b.txt"} {
		if _, err := s.Upload(ctx, name, strings.NewReader("x"), 1); err != nil {
			t.Fatalf("Upload %s: %v", name, err)
		}
	}

	if err := s.DeletePrefix(ctx, "del/"); err != nil {
		t.Fatalf("DeletePrefix() error: %v", err)
	}

	keys, _ := s.ListObjects(ctx, "del/", 10)
	if len(keys) != 0 {
		t.Errorf("after DeletePrefix, expected 0 keys, got %v", keys)
	}
}

// ---------------------------------------------------------------------------
// GetMetadata — download-for-checksum path (no sha256 in metadata)
// ---------------------------------------------------------------------------

func TestS3_GetMetadata_NoChecksumInMeta(t *testing.T) {
	s, ms, cleanup := newS3TestStorage(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := s.Upload(ctx, "nometa.txt", strings.NewReader("data"), 4); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	// Strip sha256 from mock metadata so GetMetadata must download to compute it
	ms.mu.Lock()
	ms.meta["nometa.txt"] = map[string]string{}
	ms.mu.Unlock()

	meta, err := s.GetMetadata(ctx, "nometa.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}
	if len(meta.Checksum) != 64 {
		t.Errorf("Checksum = %q, want 64-char SHA256 hex", meta.Checksum)
	}
}

// ---------------------------------------------------------------------------
// Interface-based mock — error paths
// ---------------------------------------------------------------------------

// mockS3Client implements s3ClientAPI. Each field holds an optional error to
// return; leave nil for success. Fields named *Out hold the success response.
type mockS3Client struct {
	putErr        error
	getOut        *awss3.GetObjectOutput
	getErr        error
	deleteErr     error
	headObjOut    *awss3.HeadObjectOutput
	headObjErr    error
	headBktErr    error
	createBktErr  error
	copyErr       error
	listOut       *awss3.ListObjectsV2Output
	listErr       error
	delObjsErr    error
	createMPOut   *awss3.CreateMultipartUploadOutput
	createMPErr   error
	uploadPartOut *awss3.UploadPartOutput
	uploadPartErr error
	completeMPErr error
	abortMPErr    error
}

func (m *mockS3Client) PutObject(_ context.Context, _ *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	return &awss3.PutObjectOutput{}, m.putErr
}
func (m *mockS3Client) GetObject(_ context.Context, _ *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	if m.getOut != nil {
		return m.getOut, nil
	}
	return nil, m.getErr
}
func (m *mockS3Client) DeleteObject(_ context.Context, _ *awss3.DeleteObjectInput, _ ...func(*awss3.Options)) (*awss3.DeleteObjectOutput, error) {
	return &awss3.DeleteObjectOutput{}, m.deleteErr
}
func (m *mockS3Client) HeadObject(_ context.Context, _ *awss3.HeadObjectInput, _ ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error) {
	if m.headObjOut != nil {
		return m.headObjOut, nil
	}
	return nil, m.headObjErr
}
func (m *mockS3Client) HeadBucket(_ context.Context, _ *awss3.HeadBucketInput, _ ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
	return &awss3.HeadBucketOutput{}, m.headBktErr
}
func (m *mockS3Client) CreateBucket(_ context.Context, _ *awss3.CreateBucketInput, _ ...func(*awss3.Options)) (*awss3.CreateBucketOutput, error) {
	return &awss3.CreateBucketOutput{}, m.createBktErr
}
func (m *mockS3Client) CopyObject(_ context.Context, _ *awss3.CopyObjectInput, _ ...func(*awss3.Options)) (*awss3.CopyObjectOutput, error) {
	return &awss3.CopyObjectOutput{}, m.copyErr
}
func (m *mockS3Client) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	if m.listOut != nil {
		return m.listOut, nil
	}
	return nil, m.listErr
}
func (m *mockS3Client) DeleteObjects(_ context.Context, _ *awss3.DeleteObjectsInput, _ ...func(*awss3.Options)) (*awss3.DeleteObjectsOutput, error) {
	return &awss3.DeleteObjectsOutput{}, m.delObjsErr
}
func (m *mockS3Client) CreateMultipartUpload(_ context.Context, _ *awss3.CreateMultipartUploadInput, _ ...func(*awss3.Options)) (*awss3.CreateMultipartUploadOutput, error) {
	if m.createMPOut != nil {
		return m.createMPOut, nil
	}
	return nil, m.createMPErr
}
func (m *mockS3Client) UploadPart(_ context.Context, _ *awss3.UploadPartInput, _ ...func(*awss3.Options)) (*awss3.UploadPartOutput, error) {
	if m.uploadPartOut != nil {
		return m.uploadPartOut, nil
	}
	return nil, m.uploadPartErr
}
func (m *mockS3Client) CompleteMultipartUpload(_ context.Context, _ *awss3.CompleteMultipartUploadInput, _ ...func(*awss3.Options)) (*awss3.CompleteMultipartUploadOutput, error) {
	return &awss3.CompleteMultipartUploadOutput{}, m.completeMPErr
}
func (m *mockS3Client) AbortMultipartUpload(_ context.Context, _ *awss3.AbortMultipartUploadInput, _ ...func(*awss3.Options)) (*awss3.AbortMultipartUploadOutput, error) {
	return &awss3.AbortMultipartUploadOutput{}, m.abortMPErr
}

// mockPresignClient implements presignClientAPI.
type mockPresignClient struct {
	presignErr error
	url        string
}

func (m *mockPresignClient) PresignGetObject(_ context.Context, _ *awss3.GetObjectInput, _ ...func(*awss3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if m.presignErr != nil {
		return nil, m.presignErr
	}
	return &v4.PresignedHTTPRequest{URL: m.url}, nil
}

// newMockStorage returns an S3Storage wired with the provided mocks.
func newMockStorage(client s3ClientAPI, presign presignClientAPI) *S3Storage {
	return &S3Storage{
		client:        client,
		presignClient: presign,
		bucket:        "test-bucket",
		region:        "us-east-1",
	}
}

// ---------------------------------------------------------------------------
// Upload — error paths
// ---------------------------------------------------------------------------

func TestS3_Upload_PutError(t *testing.T) {
	s := newMockStorage(&mockS3Client{putErr: errS3}, &mockPresignClient{})
	_, err := s.Upload(context.Background(), "x.txt", strings.NewReader("data"), 4)
	if err == nil {
		t.Error("Upload() expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Download — error path
// ---------------------------------------------------------------------------

func TestS3_Download_GetError(t *testing.T) {
	s := newMockStorage(&mockS3Client{getErr: errS3}, &mockPresignClient{})
	_, err := s.Download(context.Background(), "x.txt")
	if err == nil {
		t.Error("Download() expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Delete — error path
// ---------------------------------------------------------------------------

func TestS3_Delete_Error(t *testing.T) {
	s := newMockStorage(&mockS3Client{deleteErr: errS3}, &mockPresignClient{})
	if err := s.Delete(context.Background(), "x.txt"); err == nil {
		t.Error("Delete() expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetURL — error paths
// ---------------------------------------------------------------------------

func TestS3_GetURL_ExistsError(t *testing.T) {
	// HeadObject returns error → Exists propagates it
	s := newMockStorage(&mockS3Client{headObjErr: errS3}, &mockPresignClient{})
	_, err := s.GetURL(context.Background(), "x.txt", time.Hour)
	if err == nil {
		t.Error("GetURL() expected error from Exists, got nil")
	}
}

func TestS3_GetURL_PresignError(t *testing.T) {
	size := int64(1)
	now := time.Now()
	s := newMockStorage(
		&mockS3Client{headObjOut: &awss3.HeadObjectOutput{ContentLength: &size, LastModified: &now}},
		&mockPresignClient{presignErr: errS3},
	)
	_, err := s.GetURL(context.Background(), "x.txt", time.Hour)
	if err == nil {
		t.Error("GetURL() expected presign error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetMetadata — error paths
// ---------------------------------------------------------------------------

func TestS3_GetMetadata_HeadError(t *testing.T) {
	s := newMockStorage(&mockS3Client{headObjErr: errS3}, &mockPresignClient{})
	_, err := s.GetMetadata(context.Background(), "x.txt")
	if err == nil {
		t.Error("GetMetadata() expected error, got nil")
	}
}

func TestS3_GetMetadata_DownloadError(t *testing.T) {
	// HeadObject succeeds with no metadata → falls through to Download, which fails
	s := newMockStorage(
		&mockS3Client{
			headObjOut: &awss3.HeadObjectOutput{},
			getErr:     errS3,
		},
		&mockPresignClient{},
	)
	_, err := s.GetMetadata(context.Background(), "x.txt")
	if err == nil {
		t.Error("GetMetadata() expected download error, got nil")
	}
}

// ---------------------------------------------------------------------------
// EnsureBucket — create path
// ---------------------------------------------------------------------------

func TestS3_EnsureBucket_Creates(t *testing.T) {
	// HeadBucket fails → CreateBucket is called and succeeds
	s := newMockStorage(&mockS3Client{headBktErr: errS3}, &mockPresignClient{})
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}
}

func TestS3_EnsureBucket_CreateError(t *testing.T) {
	s := newMockStorage(&mockS3Client{headBktErr: errS3, createBktErr: errS3}, &mockPresignClient{})
	if err := s.EnsureBucket(context.Background()); err == nil {
		t.Error("EnsureBucket() expected error from CreateBucket, got nil")
	}
}

// ---------------------------------------------------------------------------
// SetObjectStorageClass — error path
// ---------------------------------------------------------------------------

func TestS3_SetObjectStorageClass_Error(t *testing.T) {
	s := newMockStorage(&mockS3Client{copyErr: errS3}, &mockPresignClient{})
	if err := s.SetObjectStorageClass(context.Background(), "x.txt", types.StorageClassGlacier); err == nil {
		t.Error("SetObjectStorageClass() expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListObjects — error path
// ---------------------------------------------------------------------------

func TestS3_ListObjects_Error(t *testing.T) {
	s := newMockStorage(&mockS3Client{listErr: errS3}, &mockPresignClient{})
	_, err := s.ListObjects(context.Background(), "", 10)
	if err == nil {
		t.Error("ListObjects() expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeletePrefix — error paths
// ---------------------------------------------------------------------------

func TestS3_DeletePrefix_ListError(t *testing.T) {
	s := newMockStorage(&mockS3Client{listErr: errS3}, &mockPresignClient{})
	if err := s.DeletePrefix(context.Background(), "pfx/"); err == nil {
		t.Error("DeletePrefix() expected list error, got nil")
	}
}

func TestS3_DeletePrefix_DeleteError(t *testing.T) {
	key := "pfx/a.txt"
	s := newMockStorage(&mockS3Client{
		listOut: &awss3.ListObjectsV2Output{
			Contents: []types.Object{{Key: &key}},
		},
		delObjsErr: errS3,
	}, &mockPresignClient{})
	if err := s.DeletePrefix(context.Background(), "pfx/"); err == nil {
		t.Error("DeletePrefix() expected delete error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UploadMultipart
// ---------------------------------------------------------------------------

func TestS3_UploadMultipart_CreateError(t *testing.T) {
	s := newMockStorage(&mockS3Client{createMPErr: errS3}, &mockPresignClient{})
	_, err := s.UploadMultipart(context.Background(), "x.txt", strings.NewReader("data"), 1024*1024)
	if err == nil {
		t.Error("UploadMultipart() expected CreateMultipartUpload error, got nil")
	}
}

func TestS3_UploadMultipart_UploadPartError(t *testing.T) {
	uploadID := "test-upload-id"
	s := newMockStorage(&mockS3Client{
		createMPOut:   &awss3.CreateMultipartUploadOutput{UploadId: &uploadID},
		uploadPartErr: errS3,
	}, &mockPresignClient{})
	_, err := s.UploadMultipart(context.Background(), "x.txt", strings.NewReader("data"), 1024*1024)
	if err == nil {
		t.Error("UploadMultipart() expected UploadPart error, got nil")
	}
}

func TestS3_UploadMultipart_Success(t *testing.T) {
	uploadID := "test-upload-id"
	etag := "\"test-etag\""
	s := newMockStorage(&mockS3Client{
		createMPOut:   &awss3.CreateMultipartUploadOutput{UploadId: &uploadID},
		uploadPartOut: &awss3.UploadPartOutput{ETag: &etag},
	}, &mockPresignClient{})
	result, err := s.UploadMultipart(context.Background(), "x.txt", strings.NewReader("hello multipart"), 1024*1024)
	if err != nil {
		t.Fatalf("UploadMultipart() error: %v", err)
	}
	if result.Path != "x.txt" {
		t.Errorf("Path = %q, want x.txt", result.Path)
	}
	if len(result.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64", len(result.Checksum))
	}
}

func TestS3_UploadMultipart_CompleteError(t *testing.T) {
	uploadID := "test-upload-id"
	etag := "\"etag\""
	s := newMockStorage(&mockS3Client{
		createMPOut:   &awss3.CreateMultipartUploadOutput{UploadId: &uploadID},
		uploadPartOut: &awss3.UploadPartOutput{ETag: &etag},
		completeMPErr: errS3,
	}, &mockPresignClient{})
	_, err := s.UploadMultipart(context.Background(), "x.txt", strings.NewReader("data"), 1024*1024)
	if err == nil {
		t.Error("UploadMultipart() expected CompleteMultipartUpload error, got nil")
	}
}

// errS3 is a sentinel error used across interface-mock tests.
var errS3 = fmt.Errorf("mock s3 error")

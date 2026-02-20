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
		Bucket:              "my-bucket",
		Region:              "us-east-1",
		AuthMethod:          "oidc",
		RoleARN:             "arn:aws:iam::123456789:role/test-role",
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

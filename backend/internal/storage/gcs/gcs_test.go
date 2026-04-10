package gcs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	appconfig "github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// New() — constructor validation (no GCS connection required)
// ---------------------------------------------------------------------------

func TestNew_MissingBucket(t *testing.T) {
	cfg := &appconfig.GCSStorageConfig{
		Bucket: "",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing bucket")
	}
}

func TestNew_ServiceAccountNoCredentials(t *testing.T) {
	cfg := &appconfig.GCSStorageConfig{
		Bucket:          "my-bucket",
		AuthMethod:      "service_account",
		CredentialsFile: "",
		CredentialsJSON: "",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for service_account without credentials")
	}
}

func TestNew_ServiceAccountWithCredentialsJSON(t *testing.T) {
	// Invalid JSON credentials → GCS client creation will fail
	cfg := &appconfig.GCSStorageConfig{
		Bucket:          "my-bucket",
		AuthMethod:      "service_account",
		CredentialsJSON: `{"type":"service_account"}`, // minimal but invalid for actual auth
	}
	// May fail with credentials error, but not a validation error
	// We just ensure the function is called and doesn't panic
	_, _ = New(cfg)
}

func TestNew_UnsupportedAuthMethod(t *testing.T) {
	cfg := &appconfig.GCSStorageConfig{
		Bucket:     "my-bucket",
		AuthMethod: "not-a-valid-method",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for unsupported auth_method")
	}
}

func TestNew_ServiceAccountWithCredentialsFile(t *testing.T) {
	// Non-existent credentials file; GCS may fail at client creation or later.
	// We just ensure it follows the credentials-file code path without panicking.
	cfg := &appconfig.GCSStorageConfig{
		Bucket:          "my-bucket",
		AuthMethod:      "service_account",
		CredentialsFile: "/nonexistent/credentials.json",
	}
	_, _ = New(cfg)
}

// ---------------------------------------------------------------------------
// ComposeObjects — pure-logic validation paths (no network)
// ---------------------------------------------------------------------------

func TestComposeObjects_NoSources(t *testing.T) {
	s := &GCSStorage{bucket: "test-bucket"}
	err := s.ComposeObjects(context.Background(), "dest/object", []string{})
	if err == nil {
		t.Error("ComposeObjects expected error for empty source list, got nil")
	}
}

func TestComposeObjects_TooManySources(t *testing.T) {
	s := &GCSStorage{bucket: "test-bucket"}
	sources := make([]string, 33) // GCS compose limit is 32
	err := s.ComposeObjects(context.Background(), "dest/object", sources)
	if err == nil {
		t.Error("ComposeObjects expected error for >32 sources, got nil")
	}
}

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------

var errGCS = fmt.Errorf("mock gcs error")

// mockWriter implements gcsWriterAPI for testing.
type mockWriter struct {
	buf       bytes.Buffer
	writeErr  error
	closeErr  error
	metadata  map[string]string
	chunkSize int
}

func (mw *mockWriter) Write(p []byte) (int, error) {
	if mw.writeErr != nil {
		return 0, mw.writeErr
	}
	return mw.buf.Write(p)
}

func (mw *mockWriter) Close() error { return mw.closeErr }

func (mw *mockWriter) SetMetadata(m map[string]string) { mw.metadata = m }

func (mw *mockWriter) SetChunkSize(s int) { mw.chunkSize = s }

// mockObjectIterator implements gcsObjectIteratorAPI for testing.
type mockObjectIterator struct {
	items []*storage.ObjectAttrs
	idx   int
	err   error // if non-nil, returned on first call
}

func (m *mockObjectIterator) Next() (*storage.ObjectAttrs, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.idx >= len(m.items) {
		return nil, iterator.Done
	}
	item := m.items[m.idx]
	m.idx++
	return item, nil
}

// mockGCSClient implements gcsClientAPI for testing.
type mockGCSClient struct {
	closeErr error

	// NewWriter
	writer *mockWriter

	// NewReader
	readerBody string
	readerErr  error

	// ObjectAttrs
	objAttrs    *storage.ObjectAttrs
	objAttrsErr error

	// DeleteObject
	deleteErr error

	// UpdateObjectMetadata
	updateAttrs    *storage.ObjectAttrs
	updateAttrsErr error

	// CopyObject
	copyErr error

	// ComposeObjects
	composeErr error

	// BucketAttrs
	bucketAttrs    *storage.BucketAttrs
	bucketAttrsErr error

	// CreateBucket
	createBucketErr error

	// ListObjects
	listIterator *mockObjectIterator

	// SignedURL
	signedURL    string
	signedURLErr error
}

func (m *mockGCSClient) Close() error { return m.closeErr }

func (m *mockGCSClient) NewWriter(_ context.Context, _, _ string) gcsWriterAPI {
	if m.writer != nil {
		return m.writer
	}
	return &mockWriter{}
}

func (m *mockGCSClient) NewReader(_ context.Context, _, _ string) (io.ReadCloser, error) {
	if m.readerErr != nil {
		return nil, m.readerErr
	}
	return io.NopCloser(strings.NewReader(m.readerBody)), nil
}

func (m *mockGCSClient) ObjectAttrs(_ context.Context, _, _ string) (*storage.ObjectAttrs, error) {
	if m.objAttrsErr != nil {
		return nil, m.objAttrsErr
	}
	return m.objAttrs, nil
}

func (m *mockGCSClient) DeleteObject(_ context.Context, _, _ string) error {
	return m.deleteErr
}

func (m *mockGCSClient) UpdateObjectMetadata(_ context.Context, _, _ string, _ storage.ObjectAttrsToUpdate) (*storage.ObjectAttrs, error) {
	if m.updateAttrsErr != nil {
		return nil, m.updateAttrsErr
	}
	return m.updateAttrs, nil
}

func (m *mockGCSClient) CopyObject(_ context.Context, _, _, _, _ string) error {
	return m.copyErr
}

func (m *mockGCSClient) ComposeObjects(_ context.Context, _ string, _ string, _ []string) error {
	return m.composeErr
}

func (m *mockGCSClient) BucketAttrs(_ context.Context, _ string) (*storage.BucketAttrs, error) {
	if m.bucketAttrsErr != nil {
		return nil, m.bucketAttrsErr
	}
	return m.bucketAttrs, nil
}

func (m *mockGCSClient) CreateBucket(_ context.Context, _, _ string) error {
	return m.createBucketErr
}

func (m *mockGCSClient) ListObjects(_ context.Context, _ string, _ *storage.Query) gcsObjectIteratorAPI {
	if m.listIterator != nil {
		return m.listIterator
	}
	return &mockObjectIterator{}
}

func (m *mockGCSClient) SignedURL(_, _ string, _ *storage.SignedURLOptions) (string, error) {
	if m.signedURLErr != nil {
		return "", m.signedURLErr
	}
	return m.signedURL, nil
}

// newMockGCSStorage creates a GCSStorage wired with the provided mock client.
func newMockGCSStorage(client gcsClientAPI) *GCSStorage {
	return &GCSStorage{
		client: client,
		bucket: "test-bucket",
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestGCS_Close(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{})
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestGCS_Close_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{closeErr: errGCS})
	if err := s.Close(); err == nil {
		t.Error("Close() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

func TestGCS_Upload(t *testing.T) {
	mw := &mockWriter{}
	s := newMockGCSStorage(&mockGCSClient{writer: mw})

	data := []byte("hello gcs world")
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
	if !bytes.Equal(mw.buf.Bytes(), data) {
		t.Errorf("written data = %q, want %q", mw.buf.Bytes(), data)
	}
	if mw.metadata == nil || mw.metadata["sha256"] == "" {
		t.Error("writer metadata sha256 not set")
	}
}

func TestGCS_Upload_ChecksumConsistency(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{}})
	data := []byte("consistent data")

	r1, _ := s.Upload(context.Background(), "a.txt", bytes.NewReader(data), int64(len(data)))

	s2 := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{}})
	r2, _ := s2.Upload(context.Background(), "b.txt", bytes.NewReader(data), int64(len(data)))

	if r1.Checksum != r2.Checksum {
		t.Errorf("checksums differ for identical data: %s vs %s", r1.Checksum, r2.Checksum)
	}
}

func TestGCS_Upload_WriteError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{writeErr: errGCS}})
	_, err := s.Upload(context.Background(), "f.txt", strings.NewReader("x"), 1)
	if err == nil {
		t.Error("Upload() = nil, want error")
	}
}

func TestGCS_Upload_CloseError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{closeErr: errGCS}})
	_, err := s.Upload(context.Background(), "f.txt", strings.NewReader("x"), 1)
	if err == nil {
		t.Error("Upload() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func TestGCS_Download(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{readerBody: "hello download"})

	rc, err := s.Download(context.Background(), "test/file.txt")
	if err != nil {
		t.Fatalf("Download() error: %v", err)
	}
	defer rc.Close()

	data, _ := io.ReadAll(rc)
	if string(data) != "hello download" {
		t.Errorf("Download() data = %q, want %q", data, "hello download")
	}
}

func TestGCS_Download_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{readerErr: errGCS})
	_, err := s.Download(context.Background(), "f.txt")
	if err == nil {
		t.Error("Download() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestGCS_Delete(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{})
	if err := s.Delete(context.Background(), "test/file.txt"); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestGCS_Delete_NotFound(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{deleteErr: storage.ErrObjectNotExist})
	// Deleting a non-existent object should succeed silently
	if err := s.Delete(context.Background(), "missing.txt"); err != nil {
		t.Errorf("Delete() error = %v, want nil for non-existent object", err)
	}
}

func TestGCS_Delete_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{deleteErr: errGCS})
	if err := s.Delete(context.Background(), "f.txt"); err == nil {
		t.Error("Delete() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------------

func TestGCS_Exists_True(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrs: &storage.ObjectAttrs{Name: "found.txt"}})
	ok, err := s.Exists(context.Background(), "found.txt")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !ok {
		t.Error("Exists() = false, want true")
	}
}

func TestGCS_Exists_False(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: storage.ErrObjectNotExist})
	ok, err := s.Exists(context.Background(), "missing.txt")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if ok {
		t.Error("Exists() = true, want false")
	}
}

func TestGCS_Exists_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: errGCS})
	_, err := s.Exists(context.Background(), "f.txt")
	if err == nil {
		t.Error("Exists() = nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// GetURL
// ---------------------------------------------------------------------------

func TestGCS_GetURL_Success(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs:  &storage.ObjectAttrs{Name: "file.txt"},
		signedURL: "https://storage.example.com/signed",
	})
	url, err := s.GetURL(context.Background(), "file.txt", 15*time.Minute)
	if err != nil {
		t.Fatalf("GetURL() error: %v", err)
	}
	if url != "https://storage.example.com/signed" {
		t.Errorf("GetURL() = %q, want signed URL", url)
	}
}

func TestGCS_GetURL_NotFound(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: storage.ErrObjectNotExist})
	_, err := s.GetURL(context.Background(), "missing.txt", 15*time.Minute)
	if err == nil {
		t.Error("GetURL() = nil, want error for missing file")
	}
}

func TestGCS_GetURL_ExistsError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: errGCS})
	_, err := s.GetURL(context.Background(), "f.txt", 15*time.Minute)
	if err == nil {
		t.Error("GetURL() = nil, want error")
	}
}

func TestGCS_GetURL_SignError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs:     &storage.ObjectAttrs{Name: "file.txt"},
		signedURLErr: errGCS,
	})
	_, err := s.GetURL(context.Background(), "file.txt", 15*time.Minute)
	if err == nil {
		t.Error("GetURL() = nil, want error for signing failure")
	}
}

// ---------------------------------------------------------------------------
// GetMetadata
// ---------------------------------------------------------------------------

func TestGCS_GetMetadata_WithChecksum(t *testing.T) {
	now := time.Now()
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs: &storage.ObjectAttrs{
			Name:    "meta.txt",
			Size:    42,
			Updated: now,
			Metadata: map[string]string{
				"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
		},
	})
	meta, err := s.GetMetadata(context.Background(), "meta.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}
	if meta.Path != "meta.txt" {
		t.Errorf("Path = %q", meta.Path)
	}
	if meta.Size != 42 {
		t.Errorf("Size = %d, want 42", meta.Size)
	}
	if meta.Checksum != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("Checksum = %q", meta.Checksum)
	}
}

func TestGCS_GetMetadata_NoChecksum(t *testing.T) {
	// When no sha256 in metadata, GetMetadata downloads file to compute it
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs: &storage.ObjectAttrs{
			Name:     "nosha.txt",
			Size:     4,
			Metadata: map[string]string{},
		},
		readerBody: "data",
	})
	meta, err := s.GetMetadata(context.Background(), "nosha.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}
	if len(meta.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64 (SHA256 hex)", len(meta.Checksum))
	}
}

func TestGCS_GetMetadata_NilMetadataMap(t *testing.T) {
	// When metadata map is nil, should also fall back to download
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs: &storage.ObjectAttrs{
			Name: "nilmeta.txt",
			Size: 5,
		},
		readerBody: "hello",
	})
	meta, err := s.GetMetadata(context.Background(), "nilmeta.txt")
	if err != nil {
		t.Fatalf("GetMetadata() error: %v", err)
	}
	if len(meta.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64", len(meta.Checksum))
	}
}

func TestGCS_GetMetadata_NotFound(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: storage.ErrObjectNotExist})
	_, err := s.GetMetadata(context.Background(), "missing.txt")
	if err == nil {
		t.Error("GetMetadata() = nil, want error for missing file")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Errorf("error = %q, want 'file not found'", err.Error())
	}
}

func TestGCS_GetMetadata_AttrsError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{objAttrsErr: errGCS})
	_, err := s.GetMetadata(context.Background(), "f.txt")
	if err == nil {
		t.Error("GetMetadata() = nil, want error")
	}
}

func TestGCS_GetMetadata_DownloadError(t *testing.T) {
	// Attrs succeed with no checksum, but download fails
	s := newMockGCSStorage(&mockGCSClient{
		objAttrs: &storage.ObjectAttrs{
			Name:     "dl-fail.txt",
			Metadata: map[string]string{},
		},
		readerErr: errGCS,
	})
	_, err := s.GetMetadata(context.Background(), "dl-fail.txt")
	if err == nil {
		t.Error("GetMetadata() = nil, want download error")
	}
}

// ---------------------------------------------------------------------------
// EnsureBucket
// ---------------------------------------------------------------------------

func TestGCS_EnsureBucket_Exists(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{bucketAttrs: &storage.BucketAttrs{}})
	if err := s.EnsureBucket(context.Background(), "my-project"); err != nil {
		t.Errorf("EnsureBucket() error = %v, want nil", err)
	}
}

func TestGCS_EnsureBucket_Creates(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		bucketAttrsErr: storage.ErrBucketNotExist,
	})
	if err := s.EnsureBucket(context.Background(), "my-project"); err != nil {
		t.Errorf("EnsureBucket() error = %v, want nil", err)
	}
}

func TestGCS_EnsureBucket_AttrsError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{bucketAttrsErr: errGCS})
	if err := s.EnsureBucket(context.Background(), "my-project"); err == nil {
		t.Error("EnsureBucket() = nil, want error")
	}
}

func TestGCS_EnsureBucket_CreateError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		bucketAttrsErr:  storage.ErrBucketNotExist,
		createBucketErr: errGCS,
	})
	if err := s.EnsureBucket(context.Background(), "my-project"); err == nil {
		t.Error("EnsureBucket() = nil, want error")
	}
}

func TestGCS_EnsureBucket_NoProjectID(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		bucketAttrsErr: storage.ErrBucketNotExist,
	})
	err := s.EnsureBucket(context.Background(), "")
	if err == nil {
		t.Error("EnsureBucket() = nil, want error for empty project_id")
	}
	if !strings.Contains(err.Error(), "project_id is required") {
		t.Errorf("error = %q, want 'project_id is required'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// SetStorageClass
// ---------------------------------------------------------------------------

func TestGCS_SetStorageClass(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{})
	if err := s.SetStorageClass(context.Background(), "file.txt", "NEARLINE"); err != nil {
		t.Errorf("SetStorageClass() error = %v, want nil", err)
	}
}

func TestGCS_SetStorageClass_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{copyErr: errGCS})
	if err := s.SetStorageClass(context.Background(), "f.txt", "NEARLINE"); err == nil {
		t.Error("SetStorageClass() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// ListObjects
// ---------------------------------------------------------------------------

func TestGCS_ListObjects_Empty(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{},
	})
	keys, err := s.ListObjects(context.Background(), "prefix/", 10)
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListObjects() = %v, want empty", keys)
	}
}

func TestGCS_ListObjects_WithObjects(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{
			items: []*storage.ObjectAttrs{
				{Name: "prefix/a.txt"},
				{Name: "prefix/b.txt"},
				{Name: "prefix/c.txt"},
			},
		},
	})
	keys, err := s.ListObjects(context.Background(), "prefix/", 10)
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListObjects() returned %d items, want 3", len(keys))
	}
}

func TestGCS_ListObjects_MaxResults(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{
			items: []*storage.ObjectAttrs{
				{Name: "a.txt"},
				{Name: "b.txt"},
				{Name: "c.txt"},
			},
		},
	})
	keys, _ := s.ListObjects(context.Background(), "", 2)
	if len(keys) != 2 {
		t.Errorf("ListObjects() returned %d items, want 2 (maxResults)", len(keys))
	}
}

func TestGCS_ListObjects_Unlimited(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{
			items: []*storage.ObjectAttrs{
				{Name: "a.txt"},
				{Name: "b.txt"},
				{Name: "c.txt"},
			},
		},
	})
	keys, _ := s.ListObjects(context.Background(), "", 0)
	if len(keys) != 3 {
		t.Errorf("ListObjects() returned %d items, want 3 (unlimited)", len(keys))
	}
}

// ---------------------------------------------------------------------------
// DeletePrefix
// ---------------------------------------------------------------------------

func TestGCS_DeletePrefix_NoObjects(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{},
	})
	if err := s.DeletePrefix(context.Background(), "empty/"); err != nil {
		t.Errorf("DeletePrefix() error = %v", err)
	}
}

func TestGCS_DeletePrefix_WithObjects(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{
			items: []*storage.ObjectAttrs{
				{Name: "del/a.txt"},
				{Name: "del/b.txt"},
			},
		},
	})
	if err := s.DeletePrefix(context.Background(), "del/"); err != nil {
		t.Fatalf("DeletePrefix() error: %v", err)
	}
}

func TestGCS_DeletePrefix_DeleteError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{
		listIterator: &mockObjectIterator{
			items: []*storage.ObjectAttrs{{Name: "f.txt"}},
		},
		deleteErr: errGCS,
	})
	if err := s.DeletePrefix(context.Background(), "f"); err == nil {
		t.Error("DeletePrefix() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// ComposeObjects (beyond input validation — mock the actual compose call)
// ---------------------------------------------------------------------------

func TestGCS_ComposeObjects_Success(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{})
	err := s.ComposeObjects(context.Background(), "dest.txt", []string{"a.txt", "b.txt"})
	if err != nil {
		t.Errorf("ComposeObjects() error = %v, want nil", err)
	}
}

func TestGCS_ComposeObjects_Error(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{composeErr: errGCS})
	err := s.ComposeObjects(context.Background(), "dest.txt", []string{"a.txt"})
	if err == nil {
		t.Error("ComposeObjects() = nil, want error")
	}
}

// ---------------------------------------------------------------------------
// UploadResumable
// ---------------------------------------------------------------------------

func TestGCS_UploadResumable(t *testing.T) {
	mw := &mockWriter{}
	s := newMockGCSStorage(&mockGCSClient{
		writer:      mw,
		updateAttrs: &storage.ObjectAttrs{},
	})

	data := []byte("resumable upload data")
	result, err := s.UploadResumable(context.Background(), "big/file.bin", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UploadResumable() error: %v", err)
	}
	if result.Path != "big/file.bin" {
		t.Errorf("Path = %q", result.Path)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("Size = %d, want %d", result.Size, len(data))
	}
	if len(result.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64", len(result.Checksum))
	}
	if mw.chunkSize != 16*1024*1024 {
		t.Errorf("chunkSize = %d, want 16MB", mw.chunkSize)
	}
}

func TestGCS_UploadResumable_MetadataUpdateFails(t *testing.T) {
	// When metadata update fails, UploadResumable should still succeed (just warns)
	mw := &mockWriter{}
	s := newMockGCSStorage(&mockGCSClient{
		writer:         mw,
		updateAttrsErr: errGCS,
	})

	result, err := s.UploadResumable(context.Background(), "f.bin", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("UploadResumable() error: %v (should succeed even if metadata update fails)", err)
	}
	if len(result.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64", len(result.Checksum))
	}
}

func TestGCS_UploadResumable_WriteError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{writeErr: errGCS}})
	_, err := s.UploadResumable(context.Background(), "f.bin", strings.NewReader("data"))
	if err == nil {
		t.Error("UploadResumable() = nil, want error")
	}
}

func TestGCS_UploadResumable_CloseError(t *testing.T) {
	s := newMockGCSStorage(&mockGCSClient{writer: &mockWriter{closeErr: errGCS}})
	_, err := s.UploadResumable(context.Background(), "f.bin", strings.NewReader("data"))
	if err == nil {
		t.Error("UploadResumable() = nil, want error")
	}
}

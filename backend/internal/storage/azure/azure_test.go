package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

type storedBlob struct {
	content      []byte
	metadata     map[string]string
	lastModified time.Time
}

// helper to create a test storage pointed at an httptest server
func newTestStorage(t *testing.T) (*AzureStorage, func()) {
	t.Helper()

	// map of path -> blob
	store := map[string]*storedBlob{}

	// Simple handler imitating enough of the Azure Blob REST API for tests
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// path: /container/blob...
		p := strings.TrimPrefix(r.URL.Path, "/")

		// container creation: PUT /container?restype=container
		if r.Method == http.MethodPut && strings.Contains(r.URL.RawQuery, "restype=container") {
			w.WriteHeader(http.StatusCreated)
			return
		}

		// identify blob key as full path (container/blob...)
		key := p

		switch r.Method {
		case http.MethodPut:
			// Upload: read body and store
			data, _ := io.ReadAll(r.Body)
			// capture metadata headers x-ms-meta-*
			meta := map[string]string{}
			for k, v := range r.Header {
				lk := strings.ToLower(k)
				if strings.HasPrefix(lk, "x-ms-meta-") && len(v) > 0 {
					name := strings.TrimPrefix(lk, "x-ms-meta-")
					meta[name] = v[0]
				}
			}
			store[key] = &storedBlob{content: data, metadata: meta, lastModified: time.Now().UTC()}
			// Reply as created
			if strings.Contains(r.URL.RawQuery, "comp=tier") {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusCreated)
			}
			return

		case http.MethodGet:
			// Download stream
			if b, ok := store[key]; ok {
				// return content
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b.content)))
				w.WriteHeader(http.StatusOK)
				w.Write(b.content)
				return
			}
			http.NotFound(w, r)
			return

		case http.MethodHead:
			if b, ok := store[key]; ok {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b.content)))
				w.Header().Set("Last-Modified", b.lastModified.Format(time.RFC1123))
				// set metadata headers
				for k, v := range b.metadata {
					w.Header().Set("x-ms-meta-"+k, v)
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
			return

		case http.MethodDelete:
			// delete blob
			delete(store, key)
			w.WriteHeader(http.StatusAccepted)
			return

		default:
			http.NotFound(w, r)
			return
		}
	}))

	// create a client that points to the test server
	client, err := azblob.NewClientWithNoCredential(srv.URL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to create azblob client: %v", err)
	}

	s := &AzureStorage{
		client:        client,
		containerName: "container",
		accountName:   "account",
		accountKey:    "key",
		cdnURL:        "",
	}

	cleanup := func() { srv.Close() }
	return s, cleanup
}

func TestUploadDownloadDeleteAndExists(t *testing.T) {
	s, done := newTestStorage(t)
	defer done()

	ctx := context.Background()
	data := []byte("hello azure")

	// Upload
	res, err := s.Upload(ctx, "container/testblob.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	if res.Size != int64(len(data)) {
		t.Fatalf("unexpected size: got %d want %d", res.Size, len(data))
	}

	// Download
	rc, err := s.Download(ctx, "container/testblob.txt")
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatalf("download content mismatch: %q", string(got))
	}

	// Exists -> should be true
	exists, err := s.Exists(ctx, "container/testblob.txt")
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !exists {
		t.Fatalf("Exists = false, want true")
	}

	// Delete
	if err := s.Delete(ctx, "container/testblob.txt"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Now should not exist
	exists, err = s.Exists(ctx, "container/testblob.txt")
	if err != nil {
		t.Fatalf("Exists after delete returned error: %v", err)
	}
	if exists {
		t.Fatalf("Exists = true after delete, want false")
	}
}

func TestUploadWithMetadataAndGetMetadata(t *testing.T) {
	s, done := newTestStorage(t)
	defer done()

	ctx := context.Background()
	data := []byte("content-for-metadata")

	// Upload with metadata
	res, err := s.UploadWithMetadata(ctx, "container/meta.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("UploadWithMetadata failed: %v", err)
	}
	if res.Size != int64(len(data)) {
		t.Fatalf("unexpected size: %d", res.Size)
	}

	// GetMetadata should return stored checksum and size
	meta, err := s.GetMetadata(ctx, "container/meta.txt")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if meta.Size != int64(len(data)) {
		t.Fatalf("metadata size mismatch: %d", meta.Size)
	}
	if meta.Path != "container/meta.txt" {
		t.Fatalf("metadata path mismatch: %s", meta.Path)
	}
	if meta.Checksum == "" {
		t.Fatalf("expected checksum, got empty")
	}
}

func TestGetMetadata_ComputesWhenMissing(t *testing.T) {
	s, done := newTestStorage(t)
	defer done()

	ctx := context.Background()
	data := []byte("no-metadata-content")

	// Use Upload (which does not add metadata in our handler), then GetMetadata should compute via download
	if _, err := s.Upload(ctx, "container/nometadata.txt", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	meta, err := s.GetMetadata(ctx, "container/nometadata.txt")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if meta.Size != int64(len(data)) {
		t.Fatalf("expected size %d got %d", len(data), meta.Size)
	}
	if meta.Checksum == "" {
		t.Fatalf("expected computed checksum, got empty")
	}
}

func TestGetURL_CDNAndNotFound(t *testing.T) {
	s, done := newTestStorage(t)
	defer done()

	ctx := context.Background()

	// CDN configured: should return cdn URL without SAS generation
	s.cdnURL = "https://cdn.example"
	// Put an entry so Exists returns true
	if _, err := s.Upload(ctx, "container/forcdn.txt", strings.NewReader("x"), 1); err != nil {
		t.Fatalf("Upload for CDN failed: %v", err)
	}
	u, err := s.GetURL(ctx, "container/forcdn.txt", time.Hour)
	if err != nil {
		t.Fatalf("GetURL failed: %v", err)
	}
	if !strings.HasPrefix(u, "https://cdn.example/") {
		t.Fatalf("unexpected CDN URL: %s", u)
	}

	// Not found case
	s.cdnURL = ""
	_, err = s.GetURL(ctx, "container/nonexistent.txt", time.Hour)
	if err == nil {
		t.Fatalf("GetURL expected error for nonexistent file")
	}
}

func TestEnsureContainerAndSetTier_NoErrors(t *testing.T) {
	s, done := newTestStorage(t)
	defer done()

	ctx := context.Background()
	if err := s.EnsureContainer(ctx); err != nil {
		t.Fatalf("EnsureContainer failed: %v", err)
	}

	// Set blob access tier should return nil (handler treats PUT as OK)
	if err := s.SetBlobAccessTier(ctx, "container/any.txt", "Hot"); err != nil {
		t.Fatalf("SetBlobAccessTier failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// New() — constructor validation (no cloud connection required)
// ---------------------------------------------------------------------------

func TestNew_MissingAccountName(t *testing.T) {
	cfg := &config.AzureStorageConfig{
		AccountName:   "",
		AccountKey:    "somekey",
		ContainerName: "container",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing account name")
	}
}

func TestNew_MissingAccountKey(t *testing.T) {
	cfg := &config.AzureStorageConfig{
		AccountName:   "myaccount",
		AccountKey:    "",
		ContainerName: "container",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing account key")
	}
}

func TestNew_MissingContainerName(t *testing.T) {
	cfg := &config.AzureStorageConfig{
		AccountName:   "myaccount",
		AccountKey:    "mykey",
		ContainerName: "",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("New() = nil error, want error for missing container name")
	}
}

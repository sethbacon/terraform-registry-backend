package storage_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ---------------------------------------------------------------------------
// Minimal mock Storage implementation for Register tests
// ---------------------------------------------------------------------------

type mockStorage struct{}

func (m *mockStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return nil, nil
}
func (m *mockStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) { return nil, nil }
func (m *mockStorage) Delete(_ context.Context, _ string) error                    { return nil }
func (m *mockStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (m *mockStorage) Exists(_ context.Context, _ string) (bool, error)              { return false, nil }
func (m *mockStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegister_AddsFactory(t *testing.T) {
	storage.Register("test-backend", func(_ *config.Config) (storage.Storage, error) {
		return &mockStorage{}, nil
	})

	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = "test-backend"

	s, err := storage.NewStorage(cfg)
	if err != nil {
		t.Fatalf("NewStorage() error: %v", err)
	}
	if s == nil {
		t.Fatal("NewStorage() returned nil")
	}
}

// ---------------------------------------------------------------------------
// NewStorage
// ---------------------------------------------------------------------------

func TestNewStorage_UnknownBackend(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = "completely-unknown-backend"

	_, err := storage.NewStorage(cfg)
	if err == nil {
		t.Error("NewStorage() = nil error, want error for unregistered backend")
	}
}

func TestNewStorage_EmptyBackend(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.DefaultBackend = ""

	_, err := storage.NewStorage(cfg)
	if err == nil {
		t.Error("NewStorage() = nil error, want error for empty backend name")
	}
}

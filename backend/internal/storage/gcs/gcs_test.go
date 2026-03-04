package gcs

import (
	"context"
	"testing"

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

package mirror

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestRegistry starts a test server and returns an UpstreamRegistry pointing at it.
func newTestRegistry(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *UpstreamRegistry) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, NewUpstreamRegistry(srv.URL)
}

// newDiscoveryHandler returns an HTTP handler that serves service discovery + additional routes.
func newDiscoveryHandler(providersV1 string, extra http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/terraform.json" {
			json.NewEncoder(w).Encode(ServiceDiscoveryResponse{
				ProvidersV1: providersV1,
				ModulesV1:   "/v1/modules/",
			})
			return
		}
		if extra != nil {
			extra.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

// ---------------------------------------------------------------------------
// NewUpstreamRegistry
// ---------------------------------------------------------------------------

func TestNewUpstreamRegistry(t *testing.T) {
	u := NewUpstreamRegistry("https://registry.terraform.io/")
	// TrimRight removes trailing slash
	if u.BaseURL != "https://registry.terraform.io" {
		t.Errorf("BaseURL = %q, want no trailing slash", u.BaseURL)
	}
	if u.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if u.DownloadClient == nil {
		t.Error("DownloadClient is nil")
	}
}

// ---------------------------------------------------------------------------
// ValidateRegistryURL
// ---------------------------------------------------------------------------

func TestValidateRegistryURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"", true},
		{"ftp://registry.example.com", true},
		{"//no-scheme.example.com", true},
		{"http://", true},
		{"http://registry.terraform.io", false},
		{"https://registry.terraform.io", false},
		{"https://private.registry.example.com:8443", false},
	}
	for _, tt := range tests {
		err := ValidateRegistryURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateRegistryURL(%q) error=%v, wantErr=%v", tt.url, err, tt.wantErr)
		}
	}
}

// ---------------------------------------------------------------------------
// DiscoverServices
// ---------------------------------------------------------------------------

func TestDiscoverServices_Success(t *testing.T) {
	_, u := newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/terraform.json" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(ServiceDiscoveryResponse{
			ProvidersV1: "/v1/providers/",
			ModulesV1:   "/v1/modules/",
		})
	})

	disc, err := u.DiscoverServices(context.Background())
	if err != nil {
		t.Fatalf("DiscoverServices error: %v", err)
	}
	if disc.ProvidersV1 != "/v1/providers/" {
		t.Errorf("ProvidersV1 = %q, want /v1/providers/", disc.ProvidersV1)
	}
}

func TestDiscoverServices_Error(t *testing.T) {
	_, u := newTestRegistry(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	_, err := u.DiscoverServices(context.Background())
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListProviderVersions
// ---------------------------------------------------------------------------

func TestListProviderVersions_Success(t *testing.T) {
	_, u := newTestRegistry(t, newDiscoveryHandler("/v1/providers/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "hashicorp/aws/versions") {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(ProviderVersionsResponse{
			Versions: []ProviderVersion{
				{Version: "5.0.0", Protocols: []string{"6.0"}},
				{Version: "4.67.0", Protocols: []string{"6.0"}},
			},
		})
	})))

	versions, err := u.ListProviderVersions(context.Background(), "hashicorp", "aws")
	if err != nil {
		t.Fatalf("ListProviderVersions error: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("versions len = %d, want 2", len(versions))
	}
	if versions[0].Version != "5.0.0" {
		t.Errorf("first version = %q, want 5.0.0", versions[0].Version)
	}
}

func TestListProviderVersions_NotFound(t *testing.T) {
	_, u := newTestRegistry(t, newDiscoveryHandler("/v1/providers/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})))

	// 404 should return empty list (not an error)
	versions, err := u.ListProviderVersions(context.Background(), "acme", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected empty list for 404, got %d versions", len(versions))
	}
}

func TestListProviderVersions_ServerError(t *testing.T) {
	_, u := newTestRegistry(t, newDiscoveryHandler("/v1/providers/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})))

	_, err := u.ListProviderVersions(context.Background(), "acme", "broken")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetProviderPackage
// ---------------------------------------------------------------------------

func TestGetProviderPackage_Success(t *testing.T) {
	pkg := ProviderPackageResponse{
		OS:          "linux",
		Arch:        "amd64",
		Filename:    "terraform-provider-aws_5.0.0_linux_amd64.zip",
		DownloadURL: "https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip",
		SHA256Sum:   "abc123",
	}

	_, u := newTestRegistry(t, newDiscoveryHandler("/v1/providers/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(pkg)
	})))

	result, err := u.GetProviderPackage(context.Background(), "hashicorp", "aws", "5.0.0", "linux", "amd64")
	if err != nil {
		t.Fatalf("GetProviderPackage error: %v", err)
	}
	if result.Filename != pkg.Filename {
		t.Errorf("Filename = %q, want %q", result.Filename, pkg.Filename)
	}
	if result.SHA256Sum != "abc123" {
		t.Errorf("SHA256Sum = %q, want abc123", result.SHA256Sum)
	}
}

func TestGetProviderPackage_Error(t *testing.T) {
	_, u := newTestRegistry(t, newDiscoveryHandler("/v1/providers/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})))

	_, err := u.GetProviderPackage(context.Background(), "acme", "missing", "1.0.0", "linux", "amd64")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// DownloadFile
// ---------------------------------------------------------------------------

func TestDownloadFile_Success(t *testing.T) {
	content := []byte("provider binary content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	u := NewUpstreamRegistry("http://example.com")
	// Override DownloadClient to point at test server (use HTTPClient for simplicity)
	u.DownloadClient = u.HTTPClient

	data, err := u.DownloadFile(context.Background(), srv.URL+"/file.zip")
	if err != nil {
		t.Fatalf("DownloadFile error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("data = %q, want %q", data, content)
	}
}

func TestDownloadFile_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u := NewUpstreamRegistry("http://example.com")
	u.DownloadClient = u.HTTPClient

	// DownloadFile retries 3 times before giving up
	_, err := u.DownloadFile(context.Background(), srv.URL+"/file.zip")
	if err == nil {
		t.Error("expected error after retries, got nil")
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("error should mention attempt count: %v", err)
	}
}

func TestDownloadFile_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	u := NewUpstreamRegistry("http://example.com")
	u.DownloadClient = u.HTTPClient

	_, err := u.DownloadFile(ctx, srv.URL+"/file.zip")
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

package mirror

import (
	"context"
	"encoding/json"
	"fmt"
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

// ---------------------------------------------------------------------------
// resolveProviderVersionID + GetProviderDocIndexByVersion helpers
// ---------------------------------------------------------------------------

func makeVersionListPage(entries []providerVersionEntryV2, nextPage *int) providerVersionListV2 {
	p := providerVersionListV2{}
	p.Data = entries
	p.Meta.Pagination.NextPage = nextPage
	return p
}

func makeVersionEntry(id, version string) providerVersionEntryV2 {
	e := providerVersionEntryV2{ID: id}
	e.Attributes.Version = version
	return e
}

func makeDocListPage(docs []providerDocEntryV2, nextPage *int) providerDocListV2 {
	p := providerDocListV2{}
	p.Data = docs
	p.Meta.Pagination.NextPage = nextPage
	return p
}

func makeDocEntry(id, slug, category, language string) providerDocEntryV2 {
	e := providerDocEntryV2{ID: id}
	e.Attributes.Slug = slug
	e.Attributes.Category = category
	e.Attributes.Language = language
	e.Attributes.Title = slug
	return e
}

// ---------------------------------------------------------------------------
// resolveProviderVersionID
// ---------------------------------------------------------------------------

func TestResolveProviderVersionID_NotFound(t *testing.T) {
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/aws":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "100"}})
		case "/v2/providers/100/provider-versions":
			json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
				makeVersionEntry("1", "4.0.0"),
				makeVersionEntry("2", "4.1.0"),
			}, nil))
		default:
			http.NotFound(w, r)
		}
	}))

	_, err := u.resolveProviderVersionID(context.Background(), "hashicorp", "aws", "5.0.0")
	if err == nil {
		t.Error("expected error when version is not in the list")
	}
}

func TestResolveProviderVersionID_Found(t *testing.T) {
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/aws":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "100"}})
		case "/v2/providers/100/provider-versions":
			json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
				makeVersionEntry("10", "4.0.0"),
				makeVersionEntry("20", "5.0.0"),
			}, nil))
		default:
			http.NotFound(w, r)
		}
	}))

	id, err := u.resolveProviderVersionID(context.Background(), "hashicorp", "aws", "5.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "20" {
		t.Errorf("got id %q, want %q", id, "20")
	}
}

func TestResolveProviderVersionID_Pagination(t *testing.T) {
	// Page 1 returns a full page of 100 versions (not the target); page 2 returns
	// a partial page that contains the target version.
	page1Versions := make([]providerVersionEntryV2, 100)
	for i := range page1Versions {
		page1Versions[i] = makeVersionEntry(fmt.Sprintf("%d", i+1000), fmt.Sprintf("1.%d.0", i))
	}
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/aws":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "200"}})
		case "/v2/providers/200/provider-versions":
			switch r.URL.Query().Get("page[number]") {
			case "1", "":
				json.NewEncoder(w).Encode(makeVersionListPage(page1Versions, nil))
			case "2":
				json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
					makeVersionEntry("9999", "99.0.0"),
				}, nil))
			default:
				http.Error(w, "unexpected page", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))

	id, err := u.resolveProviderVersionID(context.Background(), "hashicorp", "aws", "99.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "9999" {
		t.Errorf("got id %q, want %q", id, "9999")
	}
}

// ---------------------------------------------------------------------------
// GetProviderDocIndexByVersion
// ---------------------------------------------------------------------------

func TestGetProviderDocIndexByVersion_SinglePage(t *testing.T) {
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/aws":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "5000"}})
		case "/v2/providers/5000/provider-versions":
			json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
				makeVersionEntry("999", "5.0.0"),
			}, nil))
		case "/v2/provider-docs":
			q := r.URL.Query()
			if q.Get("filter[provider-version]") != "999" || q.Get("filter[language]") != "hcl" {
				http.Error(w, "unexpected query params", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(makeDocListPage([]providerDocEntryV2{
				makeDocEntry("100", "index", "overview", "hcl"),
				makeDocEntry("101", "aws_s3_bucket", "resources", "hcl"),
			}, nil))
		default:
			http.NotFound(w, r)
		}
	}))

	docs, err := u.GetProviderDocIndexByVersion(context.Background(), "hashicorp", "aws", "5.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("got %d docs, want 2", len(docs))
	}
	if docs[0].ID != "100" || docs[0].Category != "overview" {
		t.Errorf("first doc = {%q %q}, want {100 overview}", docs[0].ID, docs[0].Category)
	}
	if docs[1].ID != "101" || docs[1].Category != "resources" {
		t.Errorf("second doc = {%q %q}, want {101 resources}", docs[1].ID, docs[1].Category)
	}
}

func TestGetProviderDocIndexByVersion_Pagination(t *testing.T) {
	// The registry API does not populate meta.pagination; pagination is detected
	// by receiving fewer entries than the requested page size (< 100).
	// Page 1 returns a full page of 100 docs; page 2 returns 3 docs (partial → stop).
	page1 := make([]providerDocEntryV2, 100)
	for i := range page1 {
		page1[i] = makeDocEntry(fmt.Sprintf("%d", i+1), fmt.Sprintf("resource_%d", i+1), "resources", "hcl")
	}
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/aws":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "5000"}})
		case "/v2/providers/5000/provider-versions":
			json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
				makeVersionEntry("777", "5.0.0"),
			}, nil))
		case "/v2/provider-docs":
			switch r.URL.Query().Get("page[number]") {
			case "1", "":
				json.NewEncoder(w).Encode(makeDocListPage(page1, nil))
			case "2":
				json.NewEncoder(w).Encode(makeDocListPage([]providerDocEntryV2{
					makeDocEntry("101", "index", "overview", "hcl"),
					makeDocEntry("102", "aws_instance", "resources", "hcl"),
					makeDocEntry("103", "aws_vpc", "resources", "hcl"),
				}, nil))
			default:
				http.Error(w, "unexpected page", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))

	docs, err := u.GetProviderDocIndexByVersion(context.Background(), "hashicorp", "aws", "5.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 103 {
		t.Fatalf("got %d docs across pages, want 103", len(docs))
	}
	if docs[102].ID != "103" {
		t.Errorf("last doc ID = %q, want %q", docs[102].ID, "103")
	}
}

func TestGetProviderDocIndexByVersion_HTTPError(t *testing.T) {
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))

	_, err := u.GetProviderDocIndexByVersion(context.Background(), "hashicorp", "aws", "5.0.0")
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestGetProviderDocIndexByVersion_Empty(t *testing.T) {
	_, u := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/providers/hashicorp/null":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "6000"}})
		case "/v2/providers/6000/provider-versions":
			json.NewEncoder(w).Encode(makeVersionListPage([]providerVersionEntryV2{
				makeVersionEntry("555", "1.0.0"),
			}, nil))
		case "/v2/provider-docs":
			json.NewEncoder(w).Encode(makeDocListPage(nil, nil))
		default:
			http.NotFound(w, r)
		}
	}))

	docs, err := u.GetProviderDocIndexByVersion(context.Background(), "hashicorp", "null", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("expected empty docs, got %d", len(docs))
	}
}

// ---------------------------------------------------------------------------
// GetProviderDocContent
// ---------------------------------------------------------------------------

func TestGetProviderDocContent_Success(t *testing.T) {
	_, u := newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/provider-docs/12345" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(providerDocContentV2{
			Data: struct {
				Attributes struct {
					Content   string  `json:"content"`
					Title     string  `json:"title"`
					Category  string  `json:"category"`
					Slug      string  `json:"slug"`
					Language  string  `json:"language"`
					Truncated bool    `json:"truncated"`
					Path      *string `json:"path"`
				} `json:"attributes"`
			}{
				Attributes: struct {
					Content   string  `json:"content"`
					Title     string  `json:"title"`
					Category  string  `json:"category"`
					Slug      string  `json:"slug"`
					Language  string  `json:"language"`
					Truncated bool    `json:"truncated"`
					Path      *string `json:"path"`
				}{
					Content:  "# Random Provider\n\nThis is the overview.",
					Title:    "overview",
					Category: "overview",
					Slug:     "index",
					Language: "hcl",
				},
			},
		})
	})

	content, err := u.GetProviderDocContent(context.Background(), "12345")
	if err != nil {
		t.Fatalf("GetProviderDocContent error: %v", err)
	}
	if !strings.Contains(content, "Random Provider") {
		t.Errorf("content = %q, expected to contain 'Random Provider'", content)
	}
}

func TestGetProviderDocContent_HTTPError(t *testing.T) {
	_, u := newTestRegistry(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	_, err := u.GetProviderDocContent(context.Background(), "99999")
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestGetProviderDocContent_InvalidJSON(t *testing.T) {
	_, u := newTestRegistry(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	})

	_, err := u.GetProviderDocContent(context.Background(), "12345")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

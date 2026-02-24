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

// ---------------------------------------------------------------------------
// IsGitHubReleasesURL
// ---------------------------------------------------------------------------

func TestIsGitHubReleasesURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"github releases URL", "https://github.com/opentofu/opentofu/releases", true},
		{"github api URL", "https://api.github.com/repos/opentofu/opentofu/releases", true},
		{"github URL with trailing slash", "https://github.com/opentofu/opentofu/", true},
		{"github uppercase", "https://GITHUB.COM/opentofu/opentofu", true},
		{"hashicorp releases", "https://releases.hashicorp.com", false},
		{"empty URL", "", false},
		{"opentofu releases", "https://releases.opentofu.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitHubReleasesURL(tt.url)
			if got != tt.want {
				t.Errorf("IsGitHubReleasesURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseGitHubOwnerRepo
// ---------------------------------------------------------------------------

func TestParseGitHubOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "github.com owner/repo",
			url:       "https://github.com/opentofu/opentofu",
			wantOwner: "opentofu",
			wantRepo:  "opentofu",
		},
		{
			name:      "github.com with /releases suffix",
			url:       "https://github.com/opentofu/opentofu/releases",
			wantOwner: "opentofu",
			wantRepo:  "opentofu",
		},
		{
			name:      "api.github.com repos path",
			url:       "https://api.github.com/repos/hashicorp/terraform/releases",
			wantOwner: "hashicorp",
			wantRepo:  "terraform",
		},
		{
			name:      "github.com with .git suffix",
			url:       "https://github.com/myorg/myrepo.git",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
		},
		{
			name:      "github.com with trailing slash",
			url:       "https://github.com/myorg/myrepo/",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
		},
		{
			name:    "no owner or repo",
			url:     "https://github.com/",
			wantErr: true,
		},
		{
			name:    "only owner",
			url:     "https://github.com/onlyowner",
			wantErr: true,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := ParseGitHubOwnerRepo(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseGitHubOwnerRepo(%q) expected error, got owner=%q repo=%q", tt.url, owner, repo)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseGitHubOwnerRepo(%q) unexpected error: %v", tt.url, err)
				return
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewGitHubReleasesClient
// ---------------------------------------------------------------------------

func TestNewGitHubReleasesClient_Success(t *testing.T) {
	c, err := NewGitHubReleasesClient("https://github.com/opentofu/opentofu", "opentofu")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Owner != "opentofu" {
		t.Errorf("Owner = %q, want opentofu", c.Owner)
	}
	if c.Repo != "opentofu" {
		t.Errorf("Repo = %q, want opentofu", c.Repo)
	}
	if c.ProductName != "opentofu" {
		t.Errorf("ProductName = %q, want opentofu", c.ProductName)
	}
}

func TestNewGitHubReleasesClient_DefaultProductName(t *testing.T) {
	c, err := NewGitHubReleasesClient("https://github.com/hashicorp/terraform", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// When productName is empty, it falls back to the repo name
	if c.ProductName != "terraform" {
		t.Errorf("ProductName = %q, want terraform", c.ProductName)
	}
}

func TestNewGitHubReleasesClient_InvalidURL(t *testing.T) {
	_, err := NewGitHubReleasesClient("https://github.com/", "myproduct")
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseRelease (internal method)
// ---------------------------------------------------------------------------

func TestParseRelease_BasicAssets(t *testing.T) {
	c := &GitHubReleasesClient{
		Owner:       "opentofu",
		Repo:        "opentofu",
		ProductName: "opentofu",
	}

	rel := gitHubRelease{
		TagName:    "v1.9.0",
		Draft:      false,
		Prerelease: false,
		Assets: []gitHubAsset{
			{Name: "opentofu_1.9.0_linux_amd64.zip", BrowserDownloadURL: "https://github.com/opentofu/opentofu/releases/download/v1.9.0/opentofu_1.9.0_linux_amd64.zip"},
			{Name: "opentofu_1.9.0_darwin_arm64.zip", BrowserDownloadURL: "https://github.com/opentofu/opentofu/releases/download/v1.9.0/opentofu_1.9.0_darwin_arm64.zip"},
			{Name: "opentofu_1.9.0_SHA256SUMS", BrowserDownloadURL: "https://github.com/opentofu/opentofu/releases/download/v1.9.0/opentofu_1.9.0_SHA256SUMS"},
			{Name: "opentofu_1.9.0_SHA256SUMS.sig", BrowserDownloadURL: "https://github.com/opentofu/opentofu/releases/download/v1.9.0/opentofu_1.9.0_SHA256SUMS.sig"},
		},
	}

	vi, ok := c.parseRelease(rel)
	if !ok {
		t.Fatal("parseRelease returned ok=false, expected true")
	}
	if vi.Version != "1.9.0" {
		t.Errorf("Version = %q, want 1.9.0", vi.Version)
	}
	if len(vi.Builds) != 2 {
		t.Errorf("Builds count = %d, want 2", len(vi.Builds))
	}
	if vi.SHASumsURL == "" {
		t.Error("SHASumsURL should not be empty")
	}
	if vi.SHASumsSignature == "" {
		t.Error("SHASumsSignature should not be empty")
	}
}

func TestParseRelease_NoMatchingAssets(t *testing.T) {
	c := &GitHubReleasesClient{
		Owner:       "opentofu",
		Repo:        "opentofu",
		ProductName: "opentofu",
	}

	rel := gitHubRelease{
		TagName: "v1.9.0",
		Assets: []gitHubAsset{
			// Assets belong to a different product
			{Name: "terraform_1.9.0_linux_amd64.zip", BrowserDownloadURL: "https://example.com/download.zip"},
		},
	}

	_, ok := c.parseRelease(rel)
	if ok {
		t.Error("parseRelease returned ok=true for non-matching assets, expected false")
	}
}

func TestParseRelease_TagWithLeadingV(t *testing.T) {
	c := &GitHubReleasesClient{ProductName: "terraform"}

	rel := gitHubRelease{
		TagName: "v2.0.0",
		Assets: []gitHubAsset{
			{Name: "terraform_2.0.0_linux_amd64.zip", BrowserDownloadURL: "https://example.com/terraform_2.0.0_linux_amd64.zip"},
		},
	}

	vi, ok := c.parseRelease(rel)
	if !ok {
		t.Fatal("parseRelease returned ok=false")
	}
	// Leading "v" should be stripped from the version
	if vi.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", vi.Version)
	}
}

// ---------------------------------------------------------------------------
// Asset regex patterns
// ---------------------------------------------------------------------------

func TestBinaryZipRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{"valid linux amd64", "opentofu_1.9.0_linux_amd64.zip", true},
		{"valid darwin arm64", "terraform_1.5.0_darwin_arm64.zip", true},
		{"sha256sums file", "opentofu_1.9.0_SHA256SUMS", false},
		{"sig file", "opentofu_1.9.0_SHA256SUMS.sig", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := binaryZipRE.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("binaryZipRE.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}

func TestSHA256SumsRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{"valid sums file", "opentofu_1.9.0_SHA256SUMS", true},
		{"terraform sums file", "terraform_1.5.0_SHA256SUMS", true},
		{"sums sig file", "opentofu_1.9.0_SHA256SUMS.sig", false},
		{"binary zip", "opentofu_1.9.0_linux_amd64.zip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sha256sumsRE.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("sha256sumsRE.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}

func TestSHA256SumsSigRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{"standard sig", "opentofu_1.9.0_SHA256SUMS.sig", true},
		{"hashicorp sig", "terraform_1.5.0_SHA256SUMS.72D7468F.sig", true},
		{"sums file no ext", "opentofu_1.9.0_SHA256SUMS", false},
		{"binary zip", "opentofu_1.9.0_linux_amd64.zip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sha256sumsSigRE.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("sha256sumsSigRE.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Redirect transport: rewrites any host → test server
// ---------------------------------------------------------------------------

// allRedirectTransport rewrites every outbound request to go to testServer,
// preserving the path and query string. This lets a single httptest.Server
// handle both api.github.com tag lookups and BrowserDownloadURL asset fetches.
type allRedirectTransport struct {
	testServer *httptest.Server
}

func (t *allRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Keep path + query, replace scheme+host with test server.
	pathAndQuery := req.URL.RequestURI() // "/path?query"
	newURL := t.testServer.URL + pathAndQuery

	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header.Clone()
	return http.DefaultTransport.RoundTrip(newReq)
}

func redirectClient(ts *httptest.Server) *http.Client {
	return &http.Client{Transport: &allRedirectTransport{testServer: ts}}
}

// newTestGitHubClient creates a GitHubReleasesClient that talks to testServer.
func newTestGitHubClient(ts *httptest.Server, owner, repo, product string) *GitHubReleasesClient {
	c, _ := NewGitHubReleasesClient(fmt.Sprintf("https://github.com/%s/%s/releases", owner, repo), product)
	rc := redirectClient(ts)
	c.HTTPClient = rc
	c.DownloadClient = rc
	return c
}

// sampleGitHubRelease builds a minimal gitHubRelease JSON fragment.
func sampleReleaseJSON(tag, product string) gitHubRelease {
	var assets []gitHubAsset
	for _, plat := range []struct{ os, arch string }{{"linux", "amd64"}, {"darwin", "arm64"}} {
		filename := fmt.Sprintf("%s_%s_%s_%s.zip", product, strings.TrimPrefix(tag, "v"), plat.os, plat.arch)
		assets = append(assets, gitHubAsset{
			Name:               filename,
			BrowserDownloadURL: "https://github.com/releases/" + filename,
		})
	}
	// SHA256SUMS
	sumsFile := fmt.Sprintf("%s_%s_SHA256SUMS", product, strings.TrimPrefix(tag, "v"))
	assets = append(assets, gitHubAsset{Name: sumsFile, BrowserDownloadURL: "https://github.com/releases/" + sumsFile})
	// SHA256SUMS sig
	sigFile := sumsFile + ".sig"
	assets = append(assets, gitHubAsset{Name: sigFile, BrowserDownloadURL: "https://github.com/releases/" + sigFile})
	return gitHubRelease{TagName: tag, Draft: false, Assets: assets}
}

// ---------------------------------------------------------------------------
// ListVersions HTTP tests
// ---------------------------------------------------------------------------

func TestGitHubListVersions_Success(t *testing.T) {
	rel1 := sampleReleaseJSON("v1.9.0", "opentofu")
	rel2 := sampleReleaseJSON("1.8.5", "opentofu") // no leading v

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releases := []gitHubRelease{rel1, rel2}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(releases)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}
	if versions[0].Version != "1.9.0" {
		t.Errorf("versions[0].Version = %q, want 1.9.0", versions[0].Version)
	}
	if len(versions[0].Builds) != 2 {
		t.Errorf("len(versions[0].Builds) = %d, want 2", len(versions[0].Builds))
	}
}

func TestGitHubListVersions_SkipDraftReleases(t *testing.T) {
	draft := sampleReleaseJSON("v1.10.0-alpha1", "opentofu")
	draft.Draft = true
	normal := sampleReleaseJSON("v1.9.1", "opentofu")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gitHubRelease{draft, normal})
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	// Draft should be excluded
	if len(versions) != 1 {
		t.Errorf("len(versions) = %d, want 1 (draft excluded)", len(versions))
	}
}

func TestGitHubListVersions_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	_, err := client.ListVersions(context.Background())
	if err == nil {
		t.Fatal("expected error from non-200 response, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in error, got: %v", err)
	}
}

func TestGitHubListVersions_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	_, err := client.ListVersions(context.Background())
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestGitHubListVersions_MultiPage(t *testing.T) {
	// Return exactly 100 releases on page 1, then 1 on page 2 to trigger pagination.
	page1 := make([]gitHubRelease, 100)
	for i := range page1 {
		page1[i] = sampleReleaseJSON(fmt.Sprintf("v1.%d.0", i), "opentofu")
	}
	page2 := []gitHubRelease{sampleReleaseJSON("v1.100.0", "opentofu")}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageParam := r.URL.Query().Get("page")
		var data []gitHubRelease
		if pageParam == "2" {
			data = page2
		} else {
			data = page1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if len(versions) != 101 {
		t.Errorf("len(versions) = %d, want 101", len(versions))
	}
}

func TestGitHubListVersions_WithAPIToken(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gitHubRelease{})
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	client.APIToken = "ghp_secret"
	_, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("ListVersions error: %v", err)
	}
	if gotAuth != "Bearer ghp_secret" {
		t.Errorf("Authorization header = %q, want 'Bearer ghp_secret'", gotAuth)
	}
}

// ---------------------------------------------------------------------------
// FetchSHASums tests (exercises findAssetURL, fetchReleaseByTag, fetchURL)
// ---------------------------------------------------------------------------

func TestGitHubFetchSHASums_Success(t *testing.T) {
	const product = "opentofu"
	const version = "1.9.0"
	sumsContent := "abc123  opentofu_1.9.0_linux_amd64.zip\ndef456  opentofu_1.9.0_darwin_arm64.zip\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/tags/") {
			rel := sampleReleaseJSON("v"+version, product)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rel)
			return
		}
		// SHA256SUMS file download
		_, _ = w.Write([]byte(sumsContent))
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", product)
	parsed, raw, err := client.FetchSHASums(context.Background(), version)
	if err != nil {
		t.Fatalf("FetchSHASums error: %v", err)
	}
	if string(raw) != sumsContent {
		t.Errorf("raw = %q, want %q", string(raw), sumsContent)
	}
	if len(parsed) == 0 {
		t.Error("expected non-empty parsed SHA256 map")
	}
}

func TestGitHubFetchSHASums_NotFound(t *testing.T) {
	// Server returns 404 for all tag lookups → no asset URL found → error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	_, _, err := client.FetchSHASums(context.Background(), "1.9.0")
	if err == nil {
		t.Fatal("expected error when no SHA256SUMS asset found, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSHASumsSignature tests
// ---------------------------------------------------------------------------

func TestGitHubFetchSHASumsSignature_Success(t *testing.T) {
	const product = "opentofu"
	const version = "1.9.0"
	sigContent := []byte("fake-gpg-signature-bytes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/tags/") {
			rel := sampleReleaseJSON("v"+version, product)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rel)
			return
		}
		_, _ = w.Write(sigContent)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", product)
	got, err := client.FetchSHASumsSignature(context.Background(), version)
	if err != nil {
		t.Fatalf("FetchSHASumsSignature error: %v", err)
	}
	if string(got) != string(sigContent) {
		t.Errorf("signature = %q, want %q", got, sigContent)
	}
}

func TestGitHubFetchSHASumsSignature_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	_, err := client.FetchSHASumsSignature(context.Background(), "1.9.0")
	if err == nil {
		t.Fatal("expected error when no signature asset found, got nil")
	}
}

// ---------------------------------------------------------------------------
// DownloadBinary tests
// ---------------------------------------------------------------------------

func TestGitHubDownloadBinary_Success(t *testing.T) {
	zipContent := []byte("PK\x03\x04fake zip content")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipContent)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	data, sha, err := client.DownloadBinary(context.Background(), ts.URL+"/opentofu_1.9.0_linux_amd64.zip")
	if err != nil {
		t.Fatalf("DownloadBinary error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
	if sha == "" {
		t.Error("expected non-empty SHA256")
	}
}

func TestGitHubDownloadBinary_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := newTestGitHubClient(ts, "opentofu", "opentofu", "opentofu")
	_, _, err := client.DownloadBinary(context.Background(), ts.URL+"/missing.zip")
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

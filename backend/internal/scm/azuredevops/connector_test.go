package azuredevops

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// newTestConnector creates a connector with organization set, pointing at the test server.
// Since ConnectorSettings has no Organization field, we initialize the struct directly.
func newTestConnector(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *AzureDevOpsConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := &AzureDevOpsConnector{
		clientID:     "test-client",
		clientSecret: "test-secret",
		callbackURL:  srv.URL + "/callback",
		baseURL:      srv.URL,
		tenantID:     "test-tenant",
		organization: "myorg",
	}
	return srv, c
}

func creds() *scm.AccessToken { return &scm.AccessToken{AccessToken: "ado-token"} }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewAzureDevOpsConnector_DefaultURL(t *testing.T) {
	c, err := NewAzureDevOpsConnector(&scm.ConnectorSettings{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultAzureDevOpsURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultAzureDevOpsURL)
	}
}

func TestNewAzureDevOpsConnector_CustomURL(t *testing.T) {
	c, _ := NewAzureDevOpsConnector(&scm.ConnectorSettings{
		InstanceBaseURL: "http://ado.corp.example.com",
	})
	if c.baseURL != "http://ado.corp.example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

func TestPlatform(t *testing.T) {
	c, _ := NewAzureDevOpsConnector(&scm.ConnectorSettings{})
	if c.Platform() != scm.KindAzureDevOps {
		t.Errorf("Platform() = %v, want KindAzureDevOps", c.Platform())
	}
}

// ---------------------------------------------------------------------------
// AuthorizationEndpoint (pure — no HTTP call)
// ---------------------------------------------------------------------------

func TestAuthorizationEndpoint_DefaultScope(t *testing.T) {
	c := &AzureDevOpsConnector{
		clientID:    "myapp",
		callbackURL: "http://localhost/cb",
		tenantID:    "my-tenant",
	}
	url := c.AuthorizationEndpoint("state1", nil)
	if !strings.Contains(url, "client_id=myapp") {
		t.Errorf("missing client_id: %s", url)
	}
	if !strings.Contains(url, "my-tenant") {
		t.Errorf("missing tenant in URL: %s", url)
	}
	if !strings.Contains(url, azureDevOpsResourceID) {
		t.Errorf("missing resource ID: %s", url)
	}
}

func TestAuthorizationEndpoint_CustomScopes(t *testing.T) {
	c := &AzureDevOpsConnector{tenantID: "t", callbackURL: "http://localhost/cb"}
	url := c.AuthorizationEndpoint("s", []string{"custom.scope"})
	if !strings.Contains(url, "custom.scope") {
		t.Errorf("custom scope not in URL: %s", url)
	}
}

// ---------------------------------------------------------------------------
// FetchRepository
// ---------------------------------------------------------------------------

func TestFetchRepository_Success(t *testing.T) {
	repo := adoRepo{
		ID: "repo-id", Name: "myrepo",
		WebURL:        "https://dev.azure.com/myorg/proj/_git/myrepo",
		RemoteURL:     "https://myorg@dev.azure.com/myorg/proj/_git/myrepo",
		DefaultBranch: "refs/heads/main",
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(repo)
	})

	result, err := c.FetchRepository(context.Background(), creds(), "proj", "myrepo")
	if err != nil {
		t.Fatalf("FetchRepository error: %v", err)
	}
	if result.RepoName != "myrepo" {
		t.Errorf("RepoName = %q, want myrepo", result.RepoName)
	}
}

func TestFetchRepository_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchRepository(context.Background(), creds(), "proj", "missing")
	if err != scm.ErrRepoNotFound {
		t.Errorf("error = %v, want ErrRepoNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchBranches
// ---------------------------------------------------------------------------

func TestFetchBranches_Success(t *testing.T) {
	result := struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}{
		Value: []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		}{
			{Name: "refs/heads/main", ObjectID: "abc"},
			{Name: "refs/heads/dev", ObjectID: "def"},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(result)
	})

	branches, err := c.FetchBranches(context.Background(), creds(), "proj", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchBranches error: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("branches len = %d, want 2", len(branches))
	}
	if branches[0].BranchName != "main" {
		t.Errorf("BranchName = %q, want main (refs/heads/ stripped)", branches[0].BranchName)
	}
}

// ---------------------------------------------------------------------------
// FetchTags
// ---------------------------------------------------------------------------

func TestFetchTags_Success(t *testing.T) {
	result := struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}{
		Value: []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		}{
			{Name: "refs/tags/v1.0.0", ObjectID: "sha1"},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(result)
	})

	tags, err := c.FetchTags(context.Background(), creds(), "proj", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchTags error: %v", err)
	}
	if len(tags) != 1 || tags[0].TagName != "v1.0.0" {
		t.Errorf("unexpected tags: %+v", tags)
	}
}

func TestFetchTags_AnnotatedTagUsesPeeledSHA(t *testing.T) {
	// The migration script creates annotated tags; ADO returns peeledObjectId (commit SHA)
	// alongside objectId (tag object SHA). FetchTags must use peeledObjectId.
	result := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"name":           "refs/tags/v1.2.3",
				"objectId":       "tagobjectsha0000000000000000000000000000",
				"peeledObjectId": "commitsha0000000000000000000000000000000",
			},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(result)
	})

	tags, err := c.FetchTags(context.Background(), creds(), "proj", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchTags error: %v", err)
	}
	if len(tags) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(tags))
	}
	if tags[0].TargetCommit != "commitsha0000000000000000000000000000000" {
		t.Errorf("TargetCommit = %q, want commit SHA (peeled); got tag object SHA", tags[0].TargetCommit)
	}
}

func TestFetchTags_PeelTagsInURL(t *testing.T) {
	// Verify the request includes peelTags=true so ADO returns peeledObjectId.
	var requestURL string
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
	})

	_, _ = c.FetchTags(context.Background(), creds(), "proj", "repo", scm.DefaultPagination())
	if !strings.Contains(requestURL, "peelTags=true") {
		t.Errorf("request URL query %q does not include peelTags=true", requestURL)
	}
}

// ---------------------------------------------------------------------------
// FetchTagByName (uses FetchTags then filters)
// ---------------------------------------------------------------------------

func TestFetchTagByName_Found(t *testing.T) {
	result := struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}{
		Value: []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		}{
			{Name: "refs/tags/v1.0.0", ObjectID: "abc123"},
			{Name: "refs/tags/v2.0.0", ObjectID: "def456"},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(result)
	})

	tag, err := c.FetchTagByName(context.Background(), creds(), "proj", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("FetchTagByName error: %v", err)
	}
	if tag.TargetCommit != "abc123" {
		t.Errorf("TargetCommit = %q, want abc123", tag.TargetCommit)
	}
}

func TestFetchTagByName_NotFound(t *testing.T) {
	result := struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}{Value: nil}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(result)
	})

	_, err := c.FetchTagByName(context.Background(), creds(), "proj", "repo", "vX")
	if err != scm.ErrTagNotFound {
		t.Errorf("error = %v, want ErrTagNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchCommit
// ---------------------------------------------------------------------------

func TestFetchCommit_Success(t *testing.T) {
	commit := struct {
		CommitID string `json:"commitId"`
		Comment  string `json:"comment"`
		Author   struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		RemoteURL string `json:"remoteUrl"`
	}{CommitID: "sha-abc", Comment: "fix: bug", Author: struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}{Name: "Carol", Email: "carol@example.com"}}

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(commit)
	})

	result, err := c.FetchCommit(context.Background(), creds(), "proj", "repo", "sha-abc")
	if err != nil {
		t.Fatalf("FetchCommit error: %v", err)
	}
	if result.CommitHash != "sha-abc" {
		t.Errorf("CommitHash = %q, want sha-abc", result.CommitHash)
	}
	if result.AuthorName != "Carol" {
		t.Errorf("AuthorName = %q, want Carol", result.AuthorName)
	}
}

func TestFetchCommit_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchCommit(context.Background(), creds(), "proj", "repo", "missing")
	if err != scm.ErrCommitNotFound {
		t.Errorf("error = %v, want ErrCommitNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// DownloadSourceArchive
// ---------------------------------------------------------------------------

// makeMinimalZip returns a minimal valid in-memory zip archive containing a single file.
func makeMinimalZip() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, _ := zw.Create("hello.txt")
	fw.Write([]byte("hello"))
	zw.Close()
	return buf.Bytes()
}

func TestDownloadSourceArchive_Success(t *testing.T) {
	zipData := makeMinimalZip()
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(zipData)
	})

	rc, err := c.DownloadSourceArchive(context.Background(), creds(), "proj", "repo", "v1.0", scm.ArchiveZipball)
	if err != nil {
		t.Fatalf("DownloadSourceArchive error: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	// Output is a tar.gz (converted from zip); just verify it is non-empty.
	if len(data) == 0 {
		t.Error("expected non-empty tar.gz output")
	}
}

// ---------------------------------------------------------------------------
// SearchRepositories (filters in-memory from FetchRepositories)
// ---------------------------------------------------------------------------

func TestSearchRepositories_Filters(t *testing.T) {
	// FetchRepositories calls fetchProjects first, then per-project repos.
	// With organization="myorg", first call is projects, second is repos.
	callCount := 0
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// projects endpoint
			json.NewEncoder(w).Encode(struct {
				Value []adoProject `json:"value"`
			}{Value: []adoProject{{ID: "p1", Name: "project1"}}})
		} else {
			// repos for project1
			json.NewEncoder(w).Encode(struct {
				Value []adoRepo `json:"value"`
			}{Value: []adoRepo{
				{ID: "r1", Name: "terraform-module-network"},
				{ID: "r2", Name: "frontend-app"},
			}})
		}
	})

	result, err := c.SearchRepositories(context.Background(), creds(), "terraform", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("SearchRepositories error: %v", err)
	}
	// Only the "terraform-module-network" repo matches "terraform"
	if len(result.Repos) != 1 {
		t.Errorf("Repos len = %d, want 1 (filtered)", len(result.Repos))
	}
}

// ---------------------------------------------------------------------------
// Webhook stubs
// ---------------------------------------------------------------------------

func TestWebhookStubs(t *testing.T) {
	c, _ := NewAzureDevOpsConnector(&scm.ConnectorSettings{})
	if _, err := c.RegisterWebhook(context.Background(), creds(), "o", "r", scm.WebhookSetup{}); err == nil {
		t.Error("RegisterWebhook: expected error, got nil")
	}
	if err := c.RemoveWebhook(context.Background(), creds(), "o", "r", "1"); err == nil {
		t.Error("RemoveWebhook: expected error, got nil")
	}
	if _, err := c.ParseDelivery([]byte("{}"), nil); err == nil {
		t.Error("ParseDelivery: expected error, got nil")
	}
	if c.VerifyDeliverySignature([]byte("p"), "sig", "sec") {
		t.Error("VerifyDeliverySignature: expected false, got true")
	}
}

// ---------------------------------------------------------------------------
// readErrorBody
// ---------------------------------------------------------------------------

func TestReadErrorBody_NilResponse(t *testing.T) {
	result := readErrorBody(nil)
	if result != "" {
		t.Errorf("result = %q, want empty", result)
	}
}

func TestReadErrorBody_EmptyBody(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(""))}
	result := readErrorBody(resp)
	if result != "" {
		t.Errorf("result = %q, want empty", result)
	}
}

func TestReadErrorBody_WithContent(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("  error message  "))}
	result := readErrorBody(resp)
	if result != "error message" {
		t.Errorf("result = %q, want 'error message'", result)
	}
}

// ---------------------------------------------------------------------------
// redirectTransport redirects all HTTP(S) requests to a fixed base URL,
// preserving the path and query — used to intercept http.DefaultClient calls
// that use hard-coded external URLs (e.g. Entra token endpoint).
// ---------------------------------------------------------------------------

type redirectTransport struct {
	base string // e.g. "http://127.0.0.1:12345"
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	redirected := req.Clone(req.Context())
	redirected.URL.Scheme = "http"
	redirected.URL.Host = rt.base[len("http://"):]
	return http.DefaultTransport.RoundTrip(redirected)
}

// withRedirectClient temporarily replaces http.DefaultTransport and restores it via t.Cleanup.
func withRedirectClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := http.DefaultClient.Transport
	http.DefaultClient.Transport = &redirectTransport{base: srv.URL}
	t.Cleanup(func() { http.DefaultClient.Transport = orig })
}

// ---------------------------------------------------------------------------
// CompleteAuthorization
// ---------------------------------------------------------------------------

func TestCompleteAuthorization_Success(t *testing.T) {
	tokenResp := map[string]interface{}{
		"access_token":  "acc-token",
		"refresh_token": "ref-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "vso.code vso.project",
	}
	srv, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	})
	withRedirectClient(t, srv)

	token, err := c.CompleteAuthorization(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "acc-token" {
		t.Errorf("AccessToken = %q, want acc-token", token.AccessToken)
	}
	if token.RefreshToken != "ref-token" {
		t.Errorf("RefreshToken = %q, want ref-token", token.RefreshToken)
	}
	if len(token.Scopes) != 2 {
		t.Errorf("len(Scopes) = %d, want 2", len(token.Scopes))
	}
}

func TestCompleteAuthorization_HTTPError(t *testing.T) {
	srv, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid credentials"))
	})
	withRedirectClient(t, srv)

	_, err := c.CompleteAuthorization(context.Background(), "bad-code")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RenewToken
// ---------------------------------------------------------------------------

func TestRenewToken_Success(t *testing.T) {
	tokenResp := map[string]interface{}{
		"access_token":  "new-token",
		"refresh_token": "new-refresh",
		"token_type":    "Bearer",
		"expires_in":    3600,
	}
	srv, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	})
	withRedirectClient(t, srv)

	token, err := c.RenewToken(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "new-token" {
		t.Errorf("AccessToken = %q, want new-token", token.AccessToken)
	}
}

func TestRenewToken_HTTPError(t *testing.T) {
	srv, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid refresh token"))
	})
	withRedirectClient(t, srv)

	_, err := c.RenewToken(context.Background(), "bad-refresh")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestBuildConnector_AzureDevOps(t *testing.T) {
	settings := &scm.ConnectorSettings{
		Kind:         scm.KindAzureDevOps,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		CallbackURL:  "https://example.com/callback",
	}
	c, err := scm.BuildConnector(settings)
	if err != nil {
		t.Fatalf("BuildConnector: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil connector")
	}
}

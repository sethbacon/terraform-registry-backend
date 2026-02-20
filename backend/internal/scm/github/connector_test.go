package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// newTestConnector starts an httptest server and returns a connector pointing at it.
func newTestConnector(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *GitHubConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewGitHubConnector(&scm.ConnectorSettings{
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		CallbackURL:     srv.URL + "/callback",
		InstanceBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGitHubConnector: %v", err)
	}
	return srv, c
}

func creds() *scm.AccessToken { return &scm.AccessToken{AccessToken: "tok"} }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewGitHubConnector_Defaults(t *testing.T) {
	c, err := NewGitHubConnector(&scm.ConnectorSettings{
		ClientID:     "cid",
		ClientSecret: "csec",
		CallbackURL:  "http://localhost/cb",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultGitHubURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultGitHubURL)
	}
	if c.apiURL != defaultAPIURL {
		t.Errorf("apiURL = %q, want %q", c.apiURL, defaultAPIURL)
	}
}

func TestNewGitHubConnector_CustomBase(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{
		InstanceBaseURL: "http://ghe.example.com",
	})
	if c.baseURL != "http://ghe.example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.apiURL != "http://ghe.example.com/api/v3" {
		t.Errorf("apiURL = %q", c.apiURL)
	}
}

func TestPlatform(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{})
	if c.Platform() != scm.KindGitHub {
		t.Errorf("Platform() = %v, want KindGitHub", c.Platform())
	}
}

// ---------------------------------------------------------------------------
// AuthorizationEndpoint (pure string construction)
// ---------------------------------------------------------------------------

func TestAuthorizationEndpoint_DefaultScopes(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{
		ClientID:    "myclient",
		CallbackURL: "http://localhost/cb",
	})
	url := c.AuthorizationEndpoint("state123", nil)
	if !strings.Contains(url, "client_id=myclient") {
		t.Errorf("missing client_id: %s", url)
	}
	if !strings.Contains(url, "state=state123") {
		t.Errorf("missing state: %s", url)
	}
	if !strings.Contains(url, "scope=repo") {
		t.Errorf("missing default scope: %s", url)
	}
}

func TestAuthorizationEndpoint_CustomScopes(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{ClientID: "cid"})
	url := c.AuthorizationEndpoint("s", []string{"read:org", "repo"})
	if !strings.Contains(url, "read%3Aorg") && !strings.Contains(url, "read:org") {
		t.Errorf("custom scopes not reflected: %s", url)
	}
}

// ---------------------------------------------------------------------------
// CompleteAuthorization
// ---------------------------------------------------------------------------

func TestCompleteAuthorization_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/login/oauth/access_token" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "ghp_test",
			"token_type":   "bearer",
			"scope":        "repo,read:user",
		})
	})

	tok, err := c.CompleteAuthorization(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("CompleteAuthorization error: %v", err)
	}
	if tok.AccessToken != "ghp_test" {
		t.Errorf("AccessToken = %q, want ghp_test", tok.AccessToken)
	}
	if len(tok.Scopes) != 2 {
		t.Errorf("Scopes = %v, want 2 items", tok.Scopes)
	}
}

func TestCompleteAuthorization_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	_, err := c.CompleteAuthorization(context.Background(), "code")
	if err == nil {
		t.Error("expected error for non-200 response, got nil")
	}
}

// ---------------------------------------------------------------------------
// RenewToken (stub — always errors)
// ---------------------------------------------------------------------------

func TestRenewToken_AlwaysErrors(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{})
	_, err := c.RenewToken(context.Background(), "rt")
	if err == nil {
		t.Error("expected error from RenewToken stub, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchRepositories
// ---------------------------------------------------------------------------

func TestFetchRepositories_Success(t *testing.T) {
	repos := []githubRepo{
		{Name: "repo1", FullName: "owner/repo1", Owner: struct {
			Login string `json:"login"`
		}{Login: "owner"}},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(repos)
	})

	result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchRepositories error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Errorf("Repos len = %d, want 1", len(result.Repos))
	}
	if result.Repos[0].RepoName != "repo1" {
		t.Errorf("RepoName = %q, want repo1", result.Repos[0].RepoName)
	}
}

func TestFetchRepositories_PaginationClamp(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		// verify per_page is clamped to 30 when 0 supplied
		if !strings.Contains(r.URL.RawQuery, "per_page=30") {
			t.Errorf("expected per_page=30 in query, got %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode([]githubRepo{})
	})
	c.FetchRepositories(context.Background(), creds(), scm.Pagination{PageNum: 0, PageSize: 0})
}

// ---------------------------------------------------------------------------
// FetchRepository
// ---------------------------------------------------------------------------

func TestFetchRepository_Success(t *testing.T) {
	repo := githubRepo{Name: "myrepo", FullName: "org/myrepo", DefaultBranch: "main",
		Owner: struct {
			Login string `json:"login"`
		}{Login: "org"}}
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(repo)
	})

	result, err := c.FetchRepository(context.Background(), creds(), "org", "myrepo")
	if err != nil {
		t.Fatalf("FetchRepository error: %v", err)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main", result.DefaultBranch)
	}
}

func TestFetchRepository_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchRepository(context.Background(), creds(), "org", "nope")
	if err != scm.ErrRepoNotFound {
		t.Errorf("error = %v, want ErrRepoNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchBranches
// ---------------------------------------------------------------------------

func TestFetchBranches_Success(t *testing.T) {
	branches := []struct {
		Name      string `json:"name"`
		Commit    struct{ SHA string `json:"sha"` } `json:"commit"`
		Protected bool   `json:"protected"`
	}{
		{Name: "main", Protected: true},
		{Name: "dev", Protected: false},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(branches)
	})

	result, err := c.FetchBranches(context.Background(), creds(), "org", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchBranches error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("branches len = %d, want 2", len(result))
	}
	if !result[0].IsProtected {
		t.Error("first branch should be protected")
	}
}

// ---------------------------------------------------------------------------
// FetchTags
// ---------------------------------------------------------------------------

func TestFetchTags_Success(t *testing.T) {
	tags := []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
			URL string `json:"url"`
		} `json:"commit"`
	}{
		{Name: "v1.0.0"},
		{Name: "v2.0.0"},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(tags)
	})

	result, err := c.FetchTags(context.Background(), creds(), "org", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchTags error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("tags len = %d, want 2", len(result))
	}
	if result[0].TagName != "v1.0.0" {
		t.Errorf("TagName = %q, want v1.0.0", result[0].TagName)
	}
}

// ---------------------------------------------------------------------------
// FetchTagByName
// ---------------------------------------------------------------------------

func TestFetchTagByName_Success(t *testing.T) {
	ref := map[string]interface{}{
		"ref":    "refs/tags/v1.0.0",
		"object": map[string]string{"sha": "abc123", "type": "commit", "url": ""},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(ref)
	})

	tag, err := c.FetchTagByName(context.Background(), creds(), "org", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("FetchTagByName error: %v", err)
	}
	if tag.TagName != "v1.0.0" {
		t.Errorf("TagName = %q, want v1.0.0", tag.TagName)
	}
	if tag.TargetCommit != "abc123" {
		t.Errorf("TargetCommit = %q, want abc123", tag.TargetCommit)
	}
}

func TestFetchTagByName_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchTagByName(context.Background(), creds(), "org", "repo", "vX")
	if err != scm.ErrTagNotFound {
		t.Errorf("error = %v, want ErrTagNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchCommit
// ---------------------------------------------------------------------------

func TestFetchCommit_Success(t *testing.T) {
	commit := map[string]interface{}{
		"sha":      "deadbeef",
		"html_url": "http://github.com/org/repo/commit/deadbeef",
		"commit": map[string]interface{}{
			"message": "fix bug",
			"author": map[string]interface{}{
				"name":  "Alice",
				"email": "alice@example.com",
				"date":  time.Now().Format(time.RFC3339),
			},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(commit)
	})

	result, err := c.FetchCommit(context.Background(), creds(), "org", "repo", "deadbeef")
	if err != nil {
		t.Fatalf("FetchCommit error: %v", err)
	}
	if result.CommitHash != "deadbeef" {
		t.Errorf("CommitHash = %q, want deadbeef", result.CommitHash)
	}
	if result.AuthorName != "Alice" {
		t.Errorf("AuthorName = %q, want Alice", result.AuthorName)
	}
}

func TestFetchCommit_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchCommit(context.Background(), creds(), "org", "repo", "missing")
	if err != scm.ErrCommitNotFound {
		t.Errorf("error = %v, want ErrCommitNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// DownloadSourceArchive
// ---------------------------------------------------------------------------

func TestDownloadSourceArchive_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("archive-data"))
	})

	rc, err := c.DownloadSourceArchive(context.Background(), creds(), "org", "repo", "v1.0", scm.ArchiveTarball)
	if err != nil {
		t.Fatalf("DownloadSourceArchive error: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "archive-data" {
		t.Errorf("data = %q, want archive-data", data)
	}
}

func TestDownloadSourceArchive_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.DownloadSourceArchive(context.Background(), creds(), "org", "repo", "v1.0", scm.ArchiveTarball)
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

// ---------------------------------------------------------------------------
// SearchRepositories
// ---------------------------------------------------------------------------

func TestSearchRepositories_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/search/repositories") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 1,
			"items": []map[string]interface{}{
				{
					"id":             1,
					"name":           "found-repo",
					"full_name":      "owner/found-repo",
					"description":    "a repo",
					"private":        false,
					"html_url":       "https://example.com/owner/found-repo",
					"clone_url":      "https://example.com/owner/found-repo.git",
					"default_branch": "main",
					"updated_at":     time.Now(),
					"owner":          map[string]string{"login": "owner"},
				},
			},
		})
	})

	result, err := c.SearchRepositories(context.Background(), creds(), "found-repo", scm.Pagination{PageNum: 1, PageSize: 30})
	if err != nil {
		t.Fatalf("SearchRepositories() error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Errorf("got %d repos, want 1", len(result.Repos))
	}
}

func TestSearchRepositories_NotOK(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.SearchRepositories(context.Background(), creds(), "term", scm.Pagination{PageNum: 1, PageSize: 30})
	if err == nil {
		t.Error("SearchRepositories() expected error for non-200, got nil")
	}
}

// ---------------------------------------------------------------------------
// Webhook stubs
// ---------------------------------------------------------------------------

func TestWebhookStubs(t *testing.T) {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{})

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

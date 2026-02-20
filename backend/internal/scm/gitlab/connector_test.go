package gitlab

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

func newTestConnector(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *GitLabConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewGitLabConnector(&scm.ConnectorSettings{
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		CallbackURL:     srv.URL + "/callback",
		InstanceBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGitLabConnector: %v", err)
	}
	return srv, c
}

func creds() *scm.AccessToken { return &scm.AccessToken{AccessToken: "glpat-test"} }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewGitLabConnector_Defaults(t *testing.T) {
	c, err := NewGitLabConnector(&scm.ConnectorSettings{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != defaultGitLabURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, defaultGitLabURL)
	}
	if c.apiURL != defaultGitLabURL+"/api/v4" {
		t.Errorf("apiURL = %q", c.apiURL)
	}
}

func TestNewGitLabConnector_CustomBase(t *testing.T) {
	c, _ := NewGitLabConnector(&scm.ConnectorSettings{
		InstanceBaseURL: "http://gitlab.corp.example.com",
	})
	if c.baseURL != "http://gitlab.corp.example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.apiURL != "http://gitlab.corp.example.com/api/v4" {
		t.Errorf("apiURL = %q", c.apiURL)
	}
}

func TestPlatform(t *testing.T) {
	c, _ := NewGitLabConnector(&scm.ConnectorSettings{})
	if c.Platform() != scm.KindGitLab {
		t.Errorf("Platform() = %v, want KindGitLab", c.Platform())
	}
}

// ---------------------------------------------------------------------------
// AuthorizationEndpoint
// ---------------------------------------------------------------------------

func TestAuthorizationEndpoint_DefaultScopes(t *testing.T) {
	c, _ := NewGitLabConnector(&scm.ConnectorSettings{
		ClientID:    "myclient",
		CallbackURL: "http://localhost/cb",
	})
	url := c.AuthorizationEndpoint("state42", nil)
	if !strings.Contains(url, "client_id=myclient") {
		t.Errorf("missing client_id: %s", url)
	}
	if !strings.Contains(url, "response_type=code") {
		t.Errorf("missing response_type: %s", url)
	}
}

// ---------------------------------------------------------------------------
// CompleteAuthorization
// ---------------------------------------------------------------------------

func TestCompleteAuthorization_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "glpat-new",
			"token_type":    "bearer",
			"expires_in":    7200,
			"refresh_token": "rt-123",
			"scope":         "read_api read_repository",
		})
	})

	tok, err := c.CompleteAuthorization(context.Background(), "code")
	if err != nil {
		t.Fatalf("CompleteAuthorization error: %v", err)
	}
	if tok.AccessToken != "glpat-new" {
		t.Errorf("AccessToken = %q, want glpat-new", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-123" {
		t.Errorf("RefreshToken = %q, want rt-123", tok.RefreshToken)
	}
	if tok.ExpiresAt == nil {
		t.Error("ExpiresAt is nil, want non-nil")
	}
}

func TestCompleteAuthorization_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	_, err := c.CompleteAuthorization(context.Background(), "bad-code")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RenewToken
// ---------------------------------------------------------------------------

func TestRenewToken_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "glpat-refreshed",
			"token_type":    "bearer",
			"expires_in":    7200,
			"refresh_token": "rt-new",
		})
	})

	tok, err := c.RenewToken(context.Background(), "old-rt")
	if err != nil {
		t.Fatalf("RenewToken error: %v", err)
	}
	if tok.AccessToken != "glpat-refreshed" {
		t.Errorf("AccessToken = %q, want glpat-refreshed", tok.AccessToken)
	}
}

func TestRenewToken_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.RenewToken(context.Background(), "bad-rt")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchRepositories
// ---------------------------------------------------------------------------

func TestFetchRepositories_Success(t *testing.T) {
	projects := []gitlabProject{
		{
			ID: 1, Name: "myproject", Path: "myproject",
			PathWithNamespace: "group/myproject",
			Visibility:        "private",
			Namespace:         struct {
				ID       int64  `json:"id"`
				Name     string `json:"name"`
				Path     string `json:"path"`
				FullPath string `json:"full_path"`
			}{Path: "group"},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(projects)
	})

	result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchRepositories error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Errorf("Repos len = %d, want 1", len(result.Repos))
	}
	if !result.Repos[0].IsPrivate {
		t.Error("repo should be private (visibility != public)")
	}
}

// ---------------------------------------------------------------------------
// FetchRepository
// ---------------------------------------------------------------------------

func TestFetchRepository_Success(t *testing.T) {
	proj := gitlabProject{
		Path: "repo", PathWithNamespace: "ns/repo",
		DefaultBranch: "main", Visibility: "public",
		WebURL: "https://gitlab.com/ns/repo",
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(proj)
	})

	repo, err := c.FetchRepository(context.Background(), creds(), "ns", "repo")
	if err != nil {
		t.Fatalf("FetchRepository error: %v", err)
	}
	if repo.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main", repo.DefaultBranch)
	}
	if repo.IsPrivate {
		t.Error("public visibility should not be private")
	}
}

func TestFetchRepository_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchRepository(context.Background(), creds(), "ns", "missing")
	if err != scm.ErrRepoNotFound {
		t.Errorf("error = %v, want ErrRepoNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchBranches
// ---------------------------------------------------------------------------

func TestFetchBranches_Success(t *testing.T) {
	branches := []struct {
		Name    string `json:"name"`
		Commit  struct{ ID string `json:"id"` } `json:"commit"`
		Protected bool `json:"protected"`
		Default   bool `json:"default"`
	}{
		{Name: "main", Protected: true, Default: true},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(branches)
	})

	result, err := c.FetchBranches(context.Background(), creds(), "ns", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchBranches error: %v", err)
	}
	if len(result) != 1 || !result[0].IsMainBranch {
		t.Error("expected 1 branch that is main branch")
	}
}

// ---------------------------------------------------------------------------
// FetchTags
// ---------------------------------------------------------------------------

func TestFetchTags_Success(t *testing.T) {
	tags := []struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Commit  struct {
			ID          string    `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			AuthorName  string    `json:"author_name"`
			AuthorEmail string    `json:"author_email"`
		} `json:"commit"`
	}{
		{Name: "v1.0.0", Message: "release 1.0.0"},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(tags)
	})

	result, err := c.FetchTags(context.Background(), creds(), "ns", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchTags error: %v", err)
	}
	if len(result) != 1 || result[0].TagName != "v1.0.0" {
		t.Errorf("unexpected result: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// FetchTagByName
// ---------------------------------------------------------------------------

func TestFetchTagByName_Success(t *testing.T) {
	tag := struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Commit  struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"commit"`
	}{Name: "v2.0.0", Commit: struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}{ID: "cafebabe"}}

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(tag)
	})

	result, err := c.FetchTagByName(context.Background(), creds(), "ns", "repo", "v2.0.0")
	if err != nil {
		t.Fatalf("FetchTagByName error: %v", err)
	}
	if result.TargetCommit != "cafebabe" {
		t.Errorf("TargetCommit = %q, want cafebabe", result.TargetCommit)
	}
}

func TestFetchTagByName_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchTagByName(context.Background(), creds(), "ns", "repo", "vX")
	if err != scm.ErrTagNotFound {
		t.Errorf("error = %v, want ErrTagNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchCommit
// ---------------------------------------------------------------------------

func TestFetchCommit_Success(t *testing.T) {
	commit := struct {
		ID            string    `json:"id"`
		Title         string    `json:"title"`
		Message       string    `json:"message"`
		AuthorName    string    `json:"author_name"`
		AuthorEmail   string    `json:"author_email"`
		CommittedDate time.Time `json:"committed_date"`
		WebURL        string    `json:"web_url"`
	}{ID: "abc", Title: "fix: regression", AuthorName: "Bob"}

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(commit)
	})

	result, err := c.FetchCommit(context.Background(), creds(), "ns", "repo", "abc")
	if err != nil {
		t.Fatalf("FetchCommit error: %v", err)
	}
	if result.CommitHash != "abc" || result.AuthorName != "Bob" {
		t.Errorf("unexpected result: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// DownloadSourceArchive
// ---------------------------------------------------------------------------

func TestDownloadSourceArchive_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("tar-data"))
	})

	rc, err := c.DownloadSourceArchive(context.Background(), creds(), "ns", "repo", "v1.0", scm.ArchiveTarball)
	if err != nil {
		t.Fatalf("DownloadSourceArchive error: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "tar-data" {
		t.Errorf("data = %q, want tar-data", data)
	}
}

func TestDownloadSourceArchive_Zipball(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".zip") {
			t.Errorf("expected .zip extension, got path: %s", r.URL.Path)
		}
		w.Write([]byte("zip-data"))
	})

	rc, err := c.DownloadSourceArchive(context.Background(), creds(), "ns", "repo", "v1.0", scm.ArchiveZipball)
	if err != nil {
		t.Fatalf("DownloadSourceArchive error: %v", err)
	}
	rc.Close()
}

// ---------------------------------------------------------------------------
// SearchRepositories
// ---------------------------------------------------------------------------

func TestSearchRepositories_Success(t *testing.T) {
	projects := []map[string]interface{}{
		{
			"id":                  42,
			"name":                "found-project",
			"path":                "found-project",
			"path_with_namespace": "owner/found-project",
			"description":         "a project",
			"web_url":             "https://gitlab.example.com/owner/found-project",
			"http_url_to_repo":    "https://gitlab.example.com/owner/found-project.git",
			"default_branch":      "main",
			"visibility":          "private",
			"last_activity_at":    time.Now(),
			"namespace": map[string]interface{}{
				"id": 1, "name": "owner", "path": "owner", "full_path": "owner",
			},
		},
	}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(projects)
	})

	result, err := c.SearchRepositories(context.Background(), creds(), "found-project", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("SearchRepositories() error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Errorf("got %d repos, want 1", len(result.Repos))
	}
}

func TestSearchRepositories_NotOK(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.SearchRepositories(context.Background(), creds(), "term", scm.DefaultPagination())
	if err == nil {
		t.Error("SearchRepositories() expected error for non-200, got nil")
	}
}

// ---------------------------------------------------------------------------
// Webhook stubs
// ---------------------------------------------------------------------------

func TestWebhookStubs(t *testing.T) {
	c, _ := NewGitLabConnector(&scm.ConnectorSettings{})
	if _, err := c.RegisterWebhook(context.Background(), creds(), "ns", "repo", scm.WebhookSetup{}); err == nil {
		t.Error("RegisterWebhook: expected error, got nil")
	}
	if err := c.RemoveWebhook(context.Background(), creds(), "ns", "repo", "1"); err == nil {
		t.Error("RemoveWebhook: expected error, got nil")
	}
	if _, err := c.ParseDelivery([]byte("{}"), nil); err == nil {
		t.Error("ParseDelivery: expected error, got nil")
	}
	if c.VerifyDeliverySignature([]byte("p"), "sig", "sec") {
		t.Error("VerifyDeliverySignature: expected false, got true")
	}
}

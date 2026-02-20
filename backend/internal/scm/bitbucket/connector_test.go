package bitbucket

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

func newTestConnector(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *BitbucketDCConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewBitbucketDCConnector(&scm.ConnectorSettings{
		InstanceBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewBitbucketDCConnector: %v", err)
	}
	return srv, c
}

func creds() *scm.AccessToken { return &scm.AccessToken{AccessToken: "pat-token"} }

func pagedJSON(values []json.RawMessage, isLast bool) []byte {
	resp := pagedResponse{Values: values, IsLastPage: isLast, Size: len(values)}
	data, _ := json.Marshal(resp)
	return data
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewBitbucketDCConnector_Success(t *testing.T) {
	c, err := NewBitbucketDCConnector(&scm.ConnectorSettings{
		InstanceBaseURL: "http://bitbucket.corp.example.com/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// TrimRight removes trailing slash
	if c.baseURL != "http://bitbucket.corp.example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

func TestNewBitbucketDCConnector_MissingURL(t *testing.T) {
	if _, err := NewBitbucketDCConnector(&scm.ConnectorSettings{}); err == nil {
		t.Error("expected error for missing InstanceBaseURL, got nil")
	}
}

func TestPlatform(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if c.Platform() != scm.KindBitbucketDC {
		t.Errorf("Platform() = %v, want KindBitbucketDC", c.Platform())
	}
}

func TestAuthorizationEndpoint_Empty(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if url := c.AuthorizationEndpoint("s", nil); url != "" {
		t.Errorf("AuthorizationEndpoint = %q, want empty", url)
	}
}

func TestCompleteAuthorization_PATRequired(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	_, err := c.CompleteAuthorization(context.Background(), "code")
	if err != scm.ErrPATRequired {
		t.Errorf("error = %v, want ErrPATRequired", err)
	}
}

func TestRenewToken_Stub(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	_, err := c.RenewToken(context.Background(), "rt")
	if err == nil {
		t.Error("expected error from RenewToken stub, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchRepositories
// ---------------------------------------------------------------------------

func TestFetchRepositories_Success(t *testing.T) {
	repo := bbRepository{ID: 1, Slug: "myrepo", Name: "My Repo", Public: false,
		Project: &bbProject{Key: "PRJ", Name: "Project"},
		Links: &bbLinks{Clone: []bbLink{
			{Name: "http", Href: "http://bb.corp/scm/prj/myrepo.git"},
		}},
	}
	raw, _ := json.Marshal(repo)
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(pagedJSON([]json.RawMessage{raw}, true))
	})

	result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchRepositories error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Fatalf("Repos len = %d, want 1", len(result.Repos))
	}
	if result.Repos[0].Name != "myrepo" {
		t.Errorf("Name = %q, want myrepo", result.Repos[0].Name)
	}
	if result.MorePages {
		t.Error("MorePages should be false when isLastPage=true")
	}
}

func TestFetchRepositories_Empty(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pagedJSON(nil, true))
	})
	result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchRepositories error: %v", err)
	}
	if len(result.Repos) != 0 {
		t.Errorf("expected 0 repos, got %d", len(result.Repos))
	}
}

// ---------------------------------------------------------------------------
// FetchRepository
// ---------------------------------------------------------------------------

func TestFetchRepository_Success(t *testing.T) {
	repo := bbRepository{ID: 2, Slug: "myrepo", Public: true,
		Project: &bbProject{Key: "PRJ"}}
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(repo)
	})

	result, err := c.FetchRepository(context.Background(), creds(), "PRJ", "myrepo")
	if err != nil {
		t.Fatalf("FetchRepository error: %v", err)
	}
	if result.IsPrivate {
		t.Error("public repo should not be private")
	}
}

func TestFetchRepository_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.FetchRepository(context.Background(), creds(), "PRJ", "missing")
	if err != scm.ErrRepoNotFound {
		t.Errorf("error = %v, want ErrRepoNotFound", err)
	}
}

func TestFetchRepository_Forbidden(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.FetchRepository(context.Background(), creds(), "PRJ", "secret")
	if err != scm.ErrRepoAccessDenied {
		t.Errorf("error = %v, want ErrRepoAccessDenied", err)
	}
}

// ---------------------------------------------------------------------------
// FetchBranches
// ---------------------------------------------------------------------------

func TestFetchBranches_Success(t *testing.T) {
	branch := struct {
		ID           string `json:"id"`
		DisplayID    string `json:"displayId"`
		LatestCommit string `json:"latestCommit"`
		IsDefault    bool   `json:"isDefault"`
	}{DisplayID: "main", LatestCommit: "aabbcc", IsDefault: true}
	raw, _ := json.Marshal(branch)

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pagedJSON([]json.RawMessage{raw}, true))
	})

	result, err := c.FetchBranches(context.Background(), creds(), "PRJ", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchBranches error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("branches len = %d, want 1", len(result))
	}
	if result[0].BranchName != "main" || !result[0].IsMainBranch {
		t.Errorf("unexpected branch: %+v", result[0])
	}
}

// ---------------------------------------------------------------------------
// FetchTags
// ---------------------------------------------------------------------------

func TestFetchTags_Success(t *testing.T) {
	tag := bbTag{DisplayID: "v1.0.0", LatestCommit: "deadbeef"}
	raw, _ := json.Marshal(tag)

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pagedJSON([]json.RawMessage{raw}, true))
	})

	result, err := c.FetchTags(context.Background(), creds(), "PRJ", "repo", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchTags error: %v", err)
	}
	if len(result) != 1 || result[0].TagName != "v1.0.0" || result[0].TargetCommit != "deadbeef" {
		t.Errorf("unexpected result: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// FetchTagByName
// ---------------------------------------------------------------------------

func TestFetchTagByName_Success(t *testing.T) {
	tag := bbTag{DisplayID: "v1.0.0", LatestCommit: "cafebabe"}
	raw, _ := json.Marshal(tag)

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pagedJSON([]json.RawMessage{raw}, true))
	})

	result, err := c.FetchTagByName(context.Background(), creds(), "PRJ", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("FetchTagByName error: %v", err)
	}
	if result.TargetCommit != "cafebabe" {
		t.Errorf("TargetCommit = %q, want cafebabe", result.TargetCommit)
	}
}

func TestFetchTagByName_NotFound(t *testing.T) {
	// Return a list without the requested tag
	tag := bbTag{DisplayID: "v9.9.9"}
	raw, _ := json.Marshal(tag)

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pagedJSON([]json.RawMessage{raw}, true))
	})

	_, err := c.FetchTagByName(context.Background(), creds(), "PRJ", "repo", "v1.0.0")
	if err != scm.ErrTagNotFound {
		t.Errorf("error = %v, want ErrTagNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// FetchCommit
// ---------------------------------------------------------------------------

func TestFetchCommit_Success(t *testing.T) {
	commit := struct {
		ID        string `json:"id"`
		Message   string `json:"message"`
		Author    struct {
			Name         string `json:"name"`
			EmailAddress string `json:"emailAddress"`
		} `json:"author"`
		AuthorTimestamp int64 `json:"authorTimestamp"`
	}{ID: "abc123", Message: "initial commit",
		Author: struct {
			Name         string `json:"name"`
			EmailAddress string `json:"emailAddress"`
		}{Name: "Alice", EmailAddress: "alice@example.com"},
		AuthorTimestamp: 1700000000000}

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(commit)
	})

	result, err := c.FetchCommit(context.Background(), creds(), "PRJ", "repo", "abc123")
	if err != nil {
		t.Fatalf("FetchCommit error: %v", err)
	}
	if result.CommitHash != "abc123" {
		t.Errorf("CommitHash = %q, want abc123", result.CommitHash)
	}
	if result.AuthorName != "Alice" {
		t.Errorf("AuthorName = %q, want Alice", result.AuthorName)
	}
}

// ---------------------------------------------------------------------------
// DownloadSourceArchive
// ---------------------------------------------------------------------------

func TestDownloadSourceArchive_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("archive"))
	})

	rc, err := c.DownloadSourceArchive(context.Background(), creds(), "PRJ", "repo", "v1.0", scm.ArchiveTarball)
	if err != nil {
		t.Fatalf("DownloadSourceArchive error: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "archive" {
		t.Errorf("data = %q, want archive", data)
	}
}

func TestDownloadSourceArchive_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.DownloadSourceArchive(context.Background(), creds(), "PRJ", "repo", "v1.0", scm.ArchiveTarball)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RegisterWebhook
// ---------------------------------------------------------------------------

func TestRegisterWebhook_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     42,
			"url":    "http://registry.example.com/webhook",
			"events": []string{"repo:refs_changed"},
			"active": true,
		})
	})

	info, err := c.RegisterWebhook(context.Background(), creds(), "PRJ", "repo", scm.WebhookSetup{
		CallbackURL:   "http://registry.example.com/webhook",
		SharedSecret:  "secret",
		ActiveOnSetup: true,
	})
	if err != nil {
		t.Fatalf("RegisterWebhook error: %v", err)
	}
	if info.ExternalID != "42" {
		t.Errorf("ExternalID = %q, want 42", info.ExternalID)
	}
}

func TestRegisterWebhook_Error(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.RegisterWebhook(context.Background(), creds(), "PRJ", "repo", scm.WebhookSetup{})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RemoveWebhook
// ---------------------------------------------------------------------------

func TestRemoveWebhook_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.RemoveWebhook(context.Background(), creds(), "PRJ", "repo", "42"); err != nil {
		t.Errorf("RemoveWebhook error: %v", err)
	}
}

func TestRemoveWebhook_NotFound(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := c.RemoveWebhook(context.Background(), creds(), "PRJ", "repo", "99"); err != scm.ErrWebhookNotFound {
		t.Errorf("error = %v, want ErrWebhookNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// ParseDelivery
// ---------------------------------------------------------------------------

func TestParseDelivery_TagEvent(t *testing.T) {
	payload := bbWebhookPayload{
		EventKey: "repo:refs_changed",
		Actor:    bbActor{Name: "alice"},
		Repository: bbWebhookRepository{
			ID: 1, Slug: "myrepo",
			Project: &bbProject{Key: "PRJ"},
		},
		Changes: []bbChange{
			{
				Ref:    bbRef{ID: "refs/tags/v1.0", DisplayID: "v1.0", Type: "TAG"},
				ToHash: "abc123",
			},
		},
	}
	data, _ := json.Marshal(payload)

	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	hook, err := c.ParseDelivery(data, map[string]string{"X-Request-Id": "req-1"})
	if err != nil {
		t.Fatalf("ParseDelivery error: %v", err)
	}
	if hook.Type != scm.WebhookEventTag {
		t.Errorf("Type = %v, want WebhookEventTag", hook.Type)
	}
	if hook.TagName != "v1.0" {
		t.Errorf("TagName = %q, want v1.0", hook.TagName)
	}
	if hook.CommitSHA != "abc123" {
		t.Errorf("CommitSHA = %q, want abc123", hook.CommitSHA)
	}
	if hook.ID != "req-1" {
		t.Errorf("ID = %q, want req-1", hook.ID)
	}
}

func TestParseDelivery_PushEvent(t *testing.T) {
	payload := bbWebhookPayload{
		EventKey: "repo:refs_changed",
		Changes: []bbChange{
			{Ref: bbRef{DisplayID: "feature/x", Type: "BRANCH"}, ToHash: "feedface"},
		},
	}
	data, _ := json.Marshal(payload)

	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	hook, err := c.ParseDelivery(data, nil)
	if err != nil {
		t.Fatalf("ParseDelivery error: %v", err)
	}
	if hook.Type != scm.WebhookEventPush {
		t.Errorf("Type = %v, want WebhookEventPush", hook.Type)
	}
	if hook.Branch != "feature/x" {
		t.Errorf("Branch = %q, want feature/x", hook.Branch)
	}
}

func TestParseDelivery_PingEvent(t *testing.T) {
	payload := bbWebhookPayload{EventKey: "diagnostics:ping"}
	data, _ := json.Marshal(payload)

	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	hook, err := c.ParseDelivery(data, nil)
	if err != nil {
		t.Fatalf("ParseDelivery error: %v", err)
	}
	if hook.Type != scm.WebhookEventPing {
		t.Errorf("Type = %v, want WebhookEventPing", hook.Type)
	}
}

func TestParseDelivery_Malformed(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	_, err := c.ParseDelivery([]byte("not json {{{"), nil)
	if err == nil {
		t.Error("expected error for malformed payload, got nil")
	}
}

// ---------------------------------------------------------------------------
// VerifyDeliverySignature (HMAC-SHA256)
// ---------------------------------------------------------------------------

func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifyDeliverySignature_Valid(t *testing.T) {
	payload := []byte(`{"eventKey":"repo:refs_changed"}`)
	secret := "mysecret"
	sig := computeHMAC(payload, secret)

	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if !c.VerifyDeliverySignature(payload, sig, secret) {
		t.Error("expected true for valid HMAC, got false")
	}
}

func TestVerifyDeliverySignature_Valid_WithoutPrefix(t *testing.T) {
	payload := []byte(`{"eventKey":"test"}`)
	secret := "s3cr3t"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil)) // no "sha256=" prefix

	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if !c.VerifyDeliverySignature(payload, sig, secret) {
		t.Error("expected true for valid HMAC without prefix, got false")
	}
}

func TestVerifyDeliverySignature_Invalid(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if c.VerifyDeliverySignature([]byte("payload"), "sha256=badhash00", "secret") {
		t.Error("expected false for invalid signature, got true")
	}
}

func TestVerifyDeliverySignature_EmptySignature(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if c.VerifyDeliverySignature([]byte("payload"), "", "secret") {
		t.Error("expected false for empty signature, got true")
	}
}

func TestVerifyDeliverySignature_EmptySecret(t *testing.T) {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{InstanceBaseURL: "http://localhost"})
	if c.VerifyDeliverySignature([]byte("payload"), "sha256=abc", "") {
		t.Error("expected false for empty secret, got true")
	}
}

// ---------------------------------------------------------------------------
// SearchRepositories
// ---------------------------------------------------------------------------

func TestSearchRepositories_Success(t *testing.T) {
	repoJSON, _ := json.Marshal(bbRepository{
		ID:   1,
		Slug: "found-repo",
		Name: "Found Repo",
		Project: &bbProject{Key: "PROJ", ID: 1, Name: "Project"},
	})
	body := pagedJSON([]json.RawMessage{repoJSON}, true)

	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	})

	result, err := c.SearchRepositories(context.Background(), creds(), "found", scm.DefaultPagination())
	if err != nil {
		t.Fatalf("SearchRepositories() error: %v", err)
	}
	if len(result.Repos) != 1 {
		t.Errorf("got %d repos, want 1", len(result.Repos))
	}
}

func TestSearchRepositories_HTTPError(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := c.SearchRepositories(context.Background(), creds(), "term", scm.DefaultPagination())
	if err == nil {
		t.Error("SearchRepositories() expected error for non-200, got nil")
	}
}

// Package bitbucket implements the SCM Connector interface for Bitbucket Data Center (self-hosted).
// It uses personal access tokens rather than OAuth, as Bitbucket Data Center's OAuth support varies
// by version. Repository webhooks use Bitbucket's native webhook API.
package bitbucket

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// BitbucketDCConnector implements scm.Connector for Bitbucket Data Center
type BitbucketDCConnector struct {
	baseURL string
}

// NewBitbucketDCConnector creates a Bitbucket Data Center connector
func NewBitbucketDCConnector(settings *scm.ConnectorSettings) (*BitbucketDCConnector, error) {
	baseURL := settings.InstanceBaseURL
	if baseURL == "" {
		return nil, fmt.Errorf("instance base URL is required for Bitbucket Data Center")
	}

	return &BitbucketDCConnector{
		baseURL: strings.TrimRight(baseURL, "/"),
	}, nil
}

func (c *BitbucketDCConnector) Platform() scm.ProviderKind {
	return scm.KindBitbucketDC
}

// AuthorizationEndpoint is not applicable for PAT-based auth
func (c *BitbucketDCConnector) AuthorizationEndpoint(stateParam string, requestedScopes []string) string {
	return ""
}

// CompleteAuthorization is not applicable for PAT-based auth
func (c *BitbucketDCConnector) CompleteAuthorization(ctx context.Context, authCode string) (*scm.AccessToken, error) {
	return nil, scm.ErrPATRequired
}

// RenewToken is not applicable for PATs
func (c *BitbucketDCConnector) RenewToken(ctx context.Context, refreshToken string) (*scm.AccessToken, error) {
	return nil, scm.ErrTokenRefreshFailed
}

// FetchRepositories lists repositories accessible to the authenticated user
func (c *BitbucketDCConnector) FetchRepositories(ctx context.Context, creds *scm.AccessToken, pagination scm.Pagination) (*scm.RepoListResult, error) {
	limit := pagination.PageSize
	if limit < 1 || limit > 100 {
		limit = 25
	}
	start := (pagination.PageNum - 1) * limit
	if start < 0 {
		start = 0
	}

	endpoint := fmt.Sprintf("%s/rest/api/1.0/repos?limit=%d&start=%d", c.baseURL, limit, start)

	var page pagedResponse
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &page); err != nil {
		return nil, err
	}

	repos := make([]*scm.SourceRepo, len(page.Values))
	for i, raw := range page.Values {
		var bbRepo bbRepository
		if err := json.Unmarshal(raw, &bbRepo); err != nil {
			return nil, fmt.Errorf("failed to parse repository: %w", err)
		}
		repos[i] = c.convertRepo(&bbRepo)
	}

	return &scm.RepoListResult{
		Repos:      repos,
		TotalCount: page.Size,
		MorePages:  !page.IsLastPage,
		NextPage:   pagination.PageNum + 1,
	}, nil
}

// FetchRepository gets details for a specific repository
func (c *BitbucketDCConnector) FetchRepository(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string) (*scm.SourceRepo, error) {
	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s", c.baseURL, ownerName, repoName)

	var bbRepo bbRepository
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &bbRepo); err != nil {
		return nil, err
	}

	return c.convertRepo(&bbRepo), nil
}

// SearchRepositories finds repositories matching a query
func (c *BitbucketDCConnector) SearchRepositories(ctx context.Context, creds *scm.AccessToken, searchTerm string, pagination scm.Pagination) (*scm.RepoListResult, error) {
	limit := pagination.PageSize
	if limit < 1 || limit > 100 {
		limit = 25
	}
	start := (pagination.PageNum - 1) * limit
	if start < 0 {
		start = 0
	}

	endpoint := fmt.Sprintf("%s/rest/api/1.0/repos?name=%s&limit=%d&start=%d", c.baseURL, searchTerm, limit, start)

	var page pagedResponse
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &page); err != nil {
		return nil, err
	}

	repos := make([]*scm.SourceRepo, len(page.Values))
	for i, raw := range page.Values {
		var bbRepo bbRepository
		if err := json.Unmarshal(raw, &bbRepo); err != nil {
			return nil, fmt.Errorf("failed to parse repository: %w", err)
		}
		repos[i] = c.convertRepo(&bbRepo)
	}

	return &scm.RepoListResult{
		Repos:      repos,
		TotalCount: page.Size,
		MorePages:  !page.IsLastPage,
		NextPage:   pagination.PageNum + 1,
	}, nil
}

// FetchBranches lists branches in a repository
func (c *BitbucketDCConnector) FetchBranches(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitBranch, error) {
	limit := pagination.PageSize
	if limit < 1 || limit > 100 {
		limit = 25
	}
	start := (pagination.PageNum - 1) * limit
	if start < 0 {
		start = 0
	}

	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/branches?limit=%d&start=%d", c.baseURL, ownerName, repoName, limit, start)

	var page pagedResponse
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &page); err != nil {
		return nil, err
	}

	branches := make([]*scm.GitBranch, len(page.Values))
	for i, raw := range page.Values {
		var bbBranch struct {
			ID           string `json:"id"`
			DisplayID    string `json:"displayId"`
			LatestCommit string `json:"latestCommit"`
			IsDefault    bool   `json:"isDefault"`
		}
		if err := json.Unmarshal(raw, &bbBranch); err != nil {
			return nil, fmt.Errorf("failed to parse branch: %w", err)
		}
		branches[i] = &scm.GitBranch{
			BranchName:   bbBranch.DisplayID,
			HeadCommit:   bbBranch.LatestCommit,
			IsMainBranch: bbBranch.IsDefault,
		}
	}

	return branches, nil
}

// FetchTags lists tags in a repository
func (c *BitbucketDCConnector) FetchTags(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitTag, error) {
	limit := pagination.PageSize
	if limit < 1 || limit > 100 {
		limit = 25
	}
	start := (pagination.PageNum - 1) * limit
	if start < 0 {
		start = 0
	}

	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/tags?limit=%d&start=%d", c.baseURL, ownerName, repoName, limit, start)

	var page pagedResponse
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &page); err != nil {
		return nil, err
	}

	tags := make([]*scm.GitTag, len(page.Values))
	for i, raw := range page.Values {
		var bbTag bbTag
		if err := json.Unmarshal(raw, &bbTag); err != nil {
			return nil, fmt.Errorf("failed to parse tag: %w", err)
		}
		tags[i] = &scm.GitTag{
			TagName:      bbTag.DisplayID,
			TargetCommit: bbTag.LatestCommit,
		}
	}

	return tags, nil
}

// FetchTagByName gets a specific tag
func (c *BitbucketDCConnector) FetchTagByName(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, tagName string) (*scm.GitTag, error) {
	// BB DC doesn't have a direct get-tag-by-name endpoint; use the tags list with filter
	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/tags?filterText=%s&limit=25", c.baseURL, ownerName, repoName, tagName)

	var page pagedResponse
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &page); err != nil {
		return nil, err
	}

	for _, raw := range page.Values {
		var bbTag bbTag
		if err := json.Unmarshal(raw, &bbTag); err != nil {
			continue
		}
		if bbTag.DisplayID == tagName {
			return &scm.GitTag{
				TagName:      bbTag.DisplayID,
				TargetCommit: bbTag.LatestCommit,
			}, nil
		}
	}

	return nil, scm.ErrTagNotFound
}

// FetchCommit gets details for a specific commit
func (c *BitbucketDCConnector) FetchCommit(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, commitHash string) (*scm.GitCommit, error) {
	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/commits/%s", c.baseURL, ownerName, repoName, commitHash)

	var bbCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name         string `json:"name"`
			EmailAddress string `json:"emailAddress"`
		} `json:"author"`
		AuthorTimestamp int64 `json:"authorTimestamp"`
	}
	if err := c.doJSON(ctx, creds, "GET", endpoint, nil, &bbCommit); err != nil {
		return nil, err
	}

	commitURL := fmt.Sprintf("%s/projects/%s/repos/%s/commits/%s", c.baseURL, ownerName, repoName, commitHash)

	return &scm.GitCommit{
		CommitHash:  bbCommit.ID,
		Subject:     bbCommit.Message,
		AuthorName:  bbCommit.Author.Name,
		AuthorEmail: bbCommit.Author.EmailAddress,
		CommittedAt: time.UnixMilli(bbCommit.AuthorTimestamp),
		CommitURL:   commitURL,
	}, nil
}

// DownloadSourceArchive downloads repository contents at a specific ref
func (c *BitbucketDCConnector) DownloadSourceArchive(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, gitRef string, format scm.ArchiveKind) (io.ReadCloser, error) {
	archiveFormat := "tgz"
	if format == scm.ArchiveZipball {
		archiveFormat = "zip"
	}

	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/archive?at=%s&format=%s", c.baseURL, ownerName, repoName, gitRef, archiveFormat)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("bitbucket: create archive request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to download archive", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to download archive", nil)
	}

	return resp.Body, nil
}

// RegisterWebhook creates a webhook on the repository
func (c *BitbucketDCConnector) RegisterWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, hookConfig scm.WebhookSetup) (*scm.WebhookInfo, error) {
	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/webhooks", c.baseURL, ownerName, repoName)

	events := hookConfig.EventTypes
	if len(events) == 0 {
		events = []string{"repo:refs_changed"}
	}

	body := map[string]interface{}{
		"name":          "terraform-registry",
		"url":           hookConfig.CallbackURL,
		"active":        hookConfig.ActiveOnSetup,
		"events":        events,
		"configuration": map[string]string{"secret": hookConfig.SharedSecret},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("bitbucket: marshal webhook body: %w", err)
	}

	var result struct {
		ID     int      `json:"id"`
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Active bool     `json:"active"`
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("bitbucket: create webhook request: %w", err)
	}
	c.setAuthHeaders(req, creds)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to create webhook", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to create webhook", nil)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("bitbucket: decode webhook response: %w", err)
	}

	return &scm.WebhookInfo{
		ExternalID:  fmt.Sprintf("%d", result.ID),
		CallbackURL: result.URL,
		EventTypes:  result.Events,
		IsActive:    result.Active,
	}, nil
}

// RemoveWebhook deletes a webhook from the repository
func (c *BitbucketDCConnector) RemoveWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, hookID string) error {
	endpoint := fmt.Sprintf("%s/rest/api/1.0/projects/%s/repos/%s/webhooks/%s", c.baseURL, ownerName, repoName, hookID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("bitbucket: create delete-webhook request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return scm.WrapRemoteError(0, "failed to delete webhook", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return scm.ErrWebhookNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return scm.WrapRemoteError(resp.StatusCode, "failed to delete webhook", nil)
	}

	return nil
}

// ParseDelivery parses an incoming webhook payload
func (c *BitbucketDCConnector) ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*scm.IncomingHook, error) {
	var payload bbWebhookPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, scm.ErrWebhookPayloadMalformed
	}

	eventType := scm.WebhookEventUnknown
	var tagName, branch, ref, commitSHA string

	switch payload.EventKey {
	case "repo:refs_changed":
		if len(payload.Changes) > 0 {
			change := payload.Changes[0]
			ref = change.Ref.ID
			commitSHA = change.ToHash

			switch change.Ref.Type {
			case "TAG":
				eventType = scm.WebhookEventTag
				tagName = change.Ref.DisplayID
			case "BRANCH":
				eventType = scm.WebhookEventPush
				branch = change.Ref.DisplayID
			}
		}
	case "diagnostics:ping":
		eventType = scm.WebhookEventPing
	}

	repo := c.convertWebhookRepo(&payload.Repository)

	rawPayload := make(map[string]interface{})
	if err := json.Unmarshal(payloadBytes, &rawPayload); err != nil {
		// rawPayload stays empty; this is informational only and callers tolerate a nil Payload
		log.Printf("Warning: failed to unmarshal webhook raw payload: %v", err)
	}

	return &scm.IncomingHook{
		ID:        httpHeaders["X-Request-Id"],
		Type:      eventType,
		Ref:       ref,
		CommitSHA: commitSHA,
		TagName:   tagName,
		Branch:    branch,
		Repo:      repo,
		Sender:    payload.Actor.Name,
		Payload:   rawPayload,
	}, nil
}

// VerifyDeliverySignature validates webhook authenticity using HMAC-SHA256
func (c *BitbucketDCConnector) VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	if signatureHeader == "" || sharedSecret == "" {
		return false
	}

	// BB DC uses "sha256=<hex>" format
	sig, _ := strings.CutPrefix(signatureHeader, "sha256=")

	expectedSig, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write(payloadBytes)
	computedSig := mac.Sum(nil)

	return hmac.Equal(expectedSig, computedSig)
}

// Helper methods

func (c *BitbucketDCConnector) setAuthHeaders(req *http.Request, creds *scm.AccessToken) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))
	req.Header.Set("Accept", "application/json")
}

func (c *BitbucketDCConnector) doJSON(ctx context.Context, creds *scm.AccessToken, method, endpoint string, body io.Reader, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("bitbucket: create request: %w", err)
	}
	c.setAuthHeaders(req, creds)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return scm.WrapRemoteError(0, "request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return scm.ErrRepoNotFound
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return scm.ErrRepoAccessDenied
	}
	if resp.StatusCode != http.StatusOK {
		return scm.WrapRemoteError(resp.StatusCode, "unexpected status", nil)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

func (c *BitbucketDCConnector) convertRepo(bbRepo *bbRepository) *scm.SourceRepo {
	projectKey := ""
	projectName := ""
	if bbRepo.Project != nil {
		projectKey = bbRepo.Project.Key
		projectName = bbRepo.Project.Name
	}

	fullName := fmt.Sprintf("%s/%s", projectKey, bbRepo.Slug)
	htmlURL := fmt.Sprintf("%s/projects/%s/repos/%s/browse", c.baseURL, projectKey, bbRepo.Slug)

	var cloneURL, sshURL string
	if bbRepo.Links != nil {
		for _, link := range bbRepo.Links.Clone {
			if link.Name == "http" || link.Name == "https" {
				cloneURL = link.Href
			}
			if link.Name == "ssh" {
				sshURL = link.Href
			}
		}
	}

	return &scm.SourceRepo{
		ID:          fmt.Sprintf("%d", bbRepo.ID),
		Owner:       projectKey,
		OwnerName:   projectName,
		Name:        bbRepo.Slug,
		RepoName:    bbRepo.Slug,
		FullName:    fullName,
		FullPath:    fullName,
		Description: bbRepo.Description,
		HTMLURL:     htmlURL,
		WebURL:      htmlURL,
		CloneURL:    cloneURL,
		GitCloneURL: cloneURL,
		SSHURL:      sshURL,
		Private:     !bbRepo.Public,
		IsPrivate:   !bbRepo.Public,
	}
}

func (c *BitbucketDCConnector) convertWebhookRepo(bbRepo *bbWebhookRepository) *scm.SourceRepo {
	projectKey := ""
	if bbRepo.Project != nil {
		projectKey = bbRepo.Project.Key
	}

	fullName := fmt.Sprintf("%s/%s", projectKey, bbRepo.Slug)
	htmlURL := fmt.Sprintf("%s/projects/%s/repos/%s/browse", c.baseURL, projectKey, bbRepo.Slug)

	return &scm.SourceRepo{
		ID:       fmt.Sprintf("%d", bbRepo.ID),
		Owner:    projectKey,
		Name:     bbRepo.Slug,
		FullName: fullName,
		HTMLURL:  htmlURL,
		WebURL:   htmlURL,
		Private:  !bbRepo.Public,
	}
}

// Bitbucket DC API types

type pagedResponse struct {
	Size          int               `json:"size"`
	Limit         int               `json:"limit"`
	IsLastPage    bool              `json:"isLastPage"`
	Start         int               `json:"start"`
	NextPageStart int               `json:"nextPageStart"`
	Values        []json.RawMessage `json:"values"`
}

type bbRepository struct {
	ID          int        `json:"id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	State       string     `json:"state"`
	Public      bool       `json:"public"`
	Project     *bbProject `json:"project"`
	Links       *bbLinks   `json:"links"`
}

type bbProject struct {
	Key  string `json:"key"`
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type bbLinks struct {
	Clone []bbLink `json:"clone"`
	Self  []bbLink `json:"self"`
}

type bbLink struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type bbTag struct {
	ID           string `json:"id"`
	DisplayID    string `json:"displayId"`
	LatestCommit string `json:"latestCommit"`
	Hash         string `json:"hash"`
}

type bbWebhookPayload struct {
	EventKey   string              `json:"eventKey"`
	Date       string              `json:"date"`
	Actor      bbActor             `json:"actor"`
	Repository bbWebhookRepository `json:"repository"`
	Changes    []bbChange          `json:"changes"`
}

type bbActor struct {
	Name         string `json:"name"`
	EmailAddress string `json:"emailAddress"`
	DisplayName  string `json:"displayName"`
}

type bbWebhookRepository struct {
	ID      int        `json:"id"`
	Slug    string     `json:"slug"`
	Name    string     `json:"name"`
	Public  bool       `json:"public"`
	Project *bbProject `json:"project"`
}

type bbChange struct {
	Ref      bbRef  `json:"ref"`
	RefID    string `json:"refId"`
	FromHash string `json:"fromHash"`
	ToHash   string `json:"toHash"`
	Type     string `json:"type"`
}

type bbRef struct {
	ID        string `json:"id"`
	DisplayID string `json:"displayId"`
	Type      string `json:"type"`
}

func init() {
	scm.RegisterConnector(scm.KindBitbucketDC, func(settings *scm.ConnectorSettings) (scm.Connector, error) {
		return NewBitbucketDCConnector(settings)
	})
}

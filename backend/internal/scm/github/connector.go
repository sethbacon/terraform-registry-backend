// Package github implements the SCM Connector interface for GitHub (both github.com and GitHub
// Enterprise Server). It uses the GitHub Apps or OAuth App flow for authentication and the GitHub
// REST API v3 for repository operations and webhook management.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

const (
	defaultGitHubURL = "https://github.com"
	defaultAPIURL    = "https://api.github.com"
)

// GitHubConnector implements scm.Connector for GitHub
type GitHubConnector struct {
	clientID     string
	clientSecret string
	callbackURL  string
	baseURL      string
	apiURL       string
}

// NewGitHubConnector creates a GitHub connector
func NewGitHubConnector(settings *scm.ConnectorSettings) (*GitHubConnector, error) {
	baseURL := defaultGitHubURL
	apiURL := defaultAPIURL

	if settings.InstanceBaseURL != "" {
		baseURL = settings.InstanceBaseURL
		apiURL = settings.InstanceBaseURL + "/api/v3"
	}

	return &GitHubConnector{
		clientID:     settings.ClientID,
		clientSecret: settings.ClientSecret,
		callbackURL:  settings.CallbackURL,
		baseURL:      baseURL,
		apiURL:       apiURL,
	}, nil
}

// Platform returns the provider kind
func (c *GitHubConnector) Platform() scm.ProviderKind {
	return scm.KindGitHub
}

// AuthorizationEndpoint returns the OAuth authorization URL
func (c *GitHubConnector) AuthorizationEndpoint(stateParam string, requestedScopes []string) string {
	scopes := "repo,read:user"
	if len(requestedScopes) > 0 {
		scopes = strings.Join(requestedScopes, ",")
	}

	params := url.Values{}
	params.Set("client_id", c.clientID)
	params.Set("redirect_uri", c.callbackURL)
	params.Set("state", stateParam)
	params.Set("scope", scopes)

	return fmt.Sprintf("%s/login/oauth/authorize?%s", c.baseURL, params.Encode())
}

// CompleteAuthorization exchanges an authorization code for an access token
func (c *GitHubConnector) CompleteAuthorization(ctx context.Context, authCode string) (*scm.AccessToken, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("code", authCode)
	data.Set("redirect_uri", c.callbackURL)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/login/oauth/access_token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github: create token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to exchange code", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, scm.WrapRemoteError(resp.StatusCode, "oauth code exchange failed", fmt.Errorf("%s", body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("github: decode token response: %w", err)
	}

	scopes := []string{}
	if result.Scope != "" {
		scopes = strings.Split(result.Scope, ",")
	}

	return &scm.AccessToken{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
		Scopes:      scopes,
	}, nil
}

// RenewToken attempts to refresh an access token (not supported by GitHub OAuth apps)
func (c *GitHubConnector) RenewToken(ctx context.Context, refreshToken string) (*scm.AccessToken, error) {
	return nil, scm.ErrTokenRefreshFailed
}

// FetchRepositories lists repositories the user can access
func (c *GitHubConnector) FetchRepositories(ctx context.Context, creds *scm.AccessToken, pagination scm.Pagination) (*scm.RepoListResult, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/user/repos?page=%d&per_page=%d&sort=updated&affiliation=owner,collaborator", c.apiURL, page, perPage)
	repos, err := c.fetchRepoList(ctx, creds, endpoint)
	if err != nil {
		return nil, fmt.Errorf("github: list repositories: %w", err)
	}

	return &scm.RepoListResult{
		Repos:     repos,
		MorePages: len(repos) == perPage,
		NextPage:  page + 1,
	}, nil
}

// FetchRepository gets details for a specific repository
func (c *GitHubConnector) FetchRepository(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string) (*scm.SourceRepo, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s", c.apiURL, ownerName, repoName)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create fetch-repo request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch repository", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, scm.ErrRepoNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch repository", nil)
	}

	var ghRepo githubRepo
	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return nil, fmt.Errorf("github: decode repository: %w", err)
	}

	return c.convertRepo(&ghRepo), nil
}

// SearchRepositories finds repositories matching a query
func (c *GitHubConnector) SearchRepositories(ctx context.Context, creds *scm.AccessToken, searchTerm string, pagination scm.Pagination) (*scm.RepoListResult, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	query := url.QueryEscape(fmt.Sprintf("%s in:name user:@me", searchTerm))
	endpoint := fmt.Sprintf("%s/search/repositories?q=%s&page=%d&per_page=%d", c.apiURL, query, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create search request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "search failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "search failed", nil)
	}

	var result struct {
		TotalCount int          `json:"total_count"`
		Items      []githubRepo `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("github: decode search results: %w", err)
	}

	repos := make([]*scm.SourceRepo, len(result.Items))
	for i, ghRepo := range result.Items {
		repos[i] = c.convertRepo(&ghRepo)
	}

	return &scm.RepoListResult{
		Repos:      repos,
		TotalCount: result.TotalCount,
		MorePages:  len(result.Items) == perPage,
		NextPage:   page + 1,
	}, nil
}

// FetchBranches lists branches in a repository
func (c *GitHubConnector) FetchBranches(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitBranch, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/branches?page=%d&per_page=%d", c.apiURL, ownerName, repoName, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create branches request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch branches", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch branches", nil)
	}

	var ghBranches []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
		Protected bool `json:"protected"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghBranches); err != nil {
		return nil, fmt.Errorf("github: decode branches: %w", err)
	}

	branches := make([]*scm.GitBranch, len(ghBranches))
	for i, ghBranch := range ghBranches {
		branches[i] = &scm.GitBranch{
			BranchName:  ghBranch.Name,
			HeadCommit:  ghBranch.Commit.SHA,
			IsProtected: ghBranch.Protected,
		}
	}

	return branches, nil
}

// FetchTags lists tags in a repository
func (c *GitHubConnector) FetchTags(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitTag, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/tags?page=%d&per_page=%d", c.apiURL, ownerName, repoName, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create tags request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch tags", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch tags", nil)
	}

	var ghTags []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
			URL string `json:"url"`
		} `json:"commit"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghTags); err != nil {
		return nil, fmt.Errorf("github: decode tags: %w", err)
	}

	tags := make([]*scm.GitTag, len(ghTags))
	for i, ghTag := range ghTags {
		tags[i] = &scm.GitTag{
			TagName:      ghTag.Name,
			TargetCommit: ghTag.Commit.SHA,
		}
	}

	return tags, nil
}

// FetchTagByName gets a specific tag
func (c *GitHubConnector) FetchTagByName(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, tagName string) (*scm.GitTag, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", c.apiURL, ownerName, repoName, tagName)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create tag-ref request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch tag", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, scm.ErrTagNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch tag", nil)
	}

	var ref struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"object"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ref); err != nil {
		return nil, fmt.Errorf("github: decode tag ref: %w", err)
	}

	return &scm.GitTag{
		TagName:      tagName,
		TargetCommit: ref.Object.SHA,
	}, nil
}

// FetchCommit gets details for a specific commit
func (c *GitHubConnector) FetchCommit(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, commitHash string) (*scm.GitCommit, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/commits/%s", c.apiURL, ownerName, repoName, commitHash)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create commit request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch commit", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, scm.ErrCommitNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch commit", nil)
	}

	var ghCommit struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
			Author  struct {
				Name  string    `json:"name"`
				Email string    `json:"email"`
				Date  time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghCommit); err != nil {
		return nil, fmt.Errorf("github: decode commit: %w", err)
	}

	return &scm.GitCommit{
		CommitHash:  ghCommit.SHA,
		Subject:     ghCommit.Commit.Message,
		AuthorName:  ghCommit.Commit.Author.Name,
		AuthorEmail: ghCommit.Commit.Author.Email,
		CommittedAt: ghCommit.Commit.Author.Date,
		CommitURL:   ghCommit.HTMLURL,
	}, nil
}

// DownloadSourceArchive downloads repository contents at a specific ref
func (c *GitHubConnector) DownloadSourceArchive(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, gitRef string, format scm.ArchiveKind) (io.ReadCloser, error) {
	archiveType := "tarball"
	if format == scm.ArchiveZipball {
		archiveType = "zipball"
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/%s/%s", c.apiURL, ownerName, repoName, archiveType, gitRef)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create archive request: %w", err)
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
func (c *GitHubConnector) RegisterWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, hookConfig scm.WebhookSetup) (*scm.WebhookInfo, error) {
	return nil, scm.ErrWebhookSetupFailed
}

// RemoveWebhook deletes a webhook from the repository
func (c *GitHubConnector) RemoveWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, hookID string) error {
	return scm.ErrWebhookNotFound
}

// ParseDelivery parses an incoming webhook payload
func (c *GitHubConnector) ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*scm.IncomingHook, error) {
	return nil, scm.ErrWebhookPayloadMalformed
}

// VerifyDeliverySignature validates webhook authenticity
func (c *GitHubConnector) VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	return false
}

// Helper methods

func (c *GitHubConnector) setAuthHeaders(req *http.Request, creds *scm.AccessToken) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func (c *GitHubConnector) fetchRepoList(ctx context.Context, creds *scm.AccessToken, endpoint string) ([]*scm.SourceRepo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: create repo-list request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch repositories", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch repositories", nil)
	}

	var ghRepos []githubRepo
	if err := json.NewDecoder(resp.Body).Decode(&ghRepos); err != nil {
		return nil, fmt.Errorf("github: decode repo list: %w", err)
	}

	repos := make([]*scm.SourceRepo, len(ghRepos))
	for i, ghRepo := range ghRepos {
		repos[i] = c.convertRepo(&ghRepo)
	}

	return repos, nil
}

func (c *GitHubConnector) convertRepo(ghRepo *githubRepo) *scm.SourceRepo {
	return &scm.SourceRepo{
		Owner:         ghRepo.Owner.Login,
		OwnerName:     ghRepo.Owner.Login,
		Name:          ghRepo.Name,
		RepoName:      ghRepo.Name,
		FullName:      ghRepo.FullName,
		FullPath:      ghRepo.FullName,
		Description:   ghRepo.Description,
		HTMLURL:       ghRepo.HTMLURL,
		WebURL:        ghRepo.HTMLURL,
		CloneURL:      ghRepo.CloneURL,
		GitCloneURL:   ghRepo.CloneURL,
		DefaultBranch: ghRepo.DefaultBranch,
		MainBranch:    ghRepo.DefaultBranch,
		Private:       ghRepo.Private,
		IsPrivate:     ghRepo.Private,
		UpdatedAt:     ghRepo.UpdatedAt,
		LastUpdatedAt: ghRepo.UpdatedAt,
	}
}

type githubRepo struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	Private       bool      `json:"private"`
	HTMLURL       string    `json:"html_url"`
	CloneURL      string    `json:"clone_url"`
	DefaultBranch string    `json:"default_branch"`
	UpdatedAt     time.Time `json:"updated_at"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func init() {
	scm.RegisterConnector(scm.KindGitHub, func(settings *scm.ConnectorSettings) (scm.Connector, error) {
		return NewGitHubConnector(settings)
	})
}

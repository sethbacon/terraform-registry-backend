// Package gitlab implements the SCM Connector interface for GitLab (both gitlab.com and self-hosted
// GitLab CE/EE). It uses GitLab's OAuth 2.0 flow and the GitLab REST API v4 for repository
// listing, webhook registration, and tag/commit resolution.
package gitlab

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
	defaultGitLabURL = "https://gitlab.com"
)

// GitLabConnector implements scm.Connector for GitLab
type GitLabConnector struct {
	clientID     string
	clientSecret string
	callbackURL  string
	baseURL      string
	apiURL       string
}

// NewGitLabConnector creates a GitLab connector
func NewGitLabConnector(settings *scm.ConnectorSettings) (*GitLabConnector, error) {
	baseURL := defaultGitLabURL
	apiURL := defaultGitLabURL + "/api/v4"

	if settings.InstanceBaseURL != "" {
		baseURL = settings.InstanceBaseURL
		apiURL = settings.InstanceBaseURL + "/api/v4"
	}

	return &GitLabConnector{
		clientID:     settings.ClientID,
		clientSecret: settings.ClientSecret,
		callbackURL:  settings.CallbackURL,
		baseURL:      baseURL,
		apiURL:       apiURL,
	}, nil
}

// Platform returns the provider kind
func (c *GitLabConnector) Platform() scm.ProviderKind {
	return scm.KindGitLab
}

// AuthorizationEndpoint returns the OAuth authorization URL
func (c *GitLabConnector) AuthorizationEndpoint(stateParam string, requestedScopes []string) string {
	scopes := "read_api read_repository"
	if len(requestedScopes) > 0 {
		scopes = strings.Join(requestedScopes, " ")
	}

	params := url.Values{}
	params.Set("client_id", c.clientID)
	params.Set("redirect_uri", c.callbackURL)
	params.Set("response_type", "code")
	params.Set("state", stateParam)
	params.Set("scope", scopes)

	return fmt.Sprintf("%s/oauth/authorize?%s", c.baseURL, params.Encode())
}

// CompleteAuthorization exchanges an authorization code for an access token
func (c *GitLabConnector) CompleteAuthorization(ctx context.Context, authCode string) (*scm.AccessToken, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("code", authCode)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", c.callbackURL)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
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
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	scopes := []string{}
	if result.Scope != "" {
		scopes = strings.Split(result.Scope, " ")
	}

	return &scm.AccessToken{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    &expiresAt,
		Scopes:       scopes,
	}, nil
}

// RenewToken refreshes an expired access token
func (c *GitLabConnector) RenewToken(ctx context.Context, refreshToken string) (*scm.AccessToken, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to refresh token", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.ErrTokenRefreshFailed
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return &scm.AccessToken{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    &expiresAt,
	}, nil
}

// FetchRepositories lists projects the user can access
func (c *GitLabConnector) FetchRepositories(ctx context.Context, creds *scm.AccessToken, pagination scm.Pagination) (*scm.RepoListResult, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/projects?membership=true&page=%d&per_page=%d&order_by=last_activity_at", c.apiURL, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch projects", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch projects", nil)
	}

	var glProjects []gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&glProjects); err != nil {
		return nil, err
	}

	repos := make([]*scm.SourceRepo, len(glProjects))
	for i, glProject := range glProjects {
		repos[i] = c.convertProject(&glProject)
	}

	return &scm.RepoListResult{
		Repos:     repos,
		MorePages: len(repos) == perPage,
		NextPage:  page + 1,
	}, nil
}

// FetchRepository gets details for a specific project
func (c *GitLabConnector) FetchRepository(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string) (*scm.SourceRepo, error) {
	// GitLab uses URL-encoded project path
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))
	endpoint := fmt.Sprintf("%s/projects/%s", c.apiURL, projectPath)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeaders(req, creds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to fetch project", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, scm.ErrRepoNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to fetch project", nil)
	}

	var glProject gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&glProject); err != nil {
		return nil, err
	}

	return c.convertProject(&glProject), nil
}

// SearchRepositories searches for projects matching a query
func (c *GitLabConnector) SearchRepositories(ctx context.Context, creds *scm.AccessToken, searchTerm string, pagination scm.Pagination) (*scm.RepoListResult, error) {
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/projects?membership=true&search=%s&page=%d&per_page=%d",
		c.apiURL, url.QueryEscape(searchTerm), page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var glProjects []gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&glProjects); err != nil {
		return nil, err
	}

	repos := make([]*scm.SourceRepo, len(glProjects))
	for i, glProject := range glProjects {
		repos[i] = c.convertProject(&glProject)
	}

	return &scm.RepoListResult{
		Repos:     repos,
		MorePages: len(repos) == perPage,
		NextPage:  page + 1,
	}, nil
}

// FetchBranches lists branches in a project
func (c *GitLabConnector) FetchBranches(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitBranch, error) {
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/projects/%s/repository/branches?page=%d&per_page=%d", c.apiURL, projectPath, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var glBranches []struct {
		Name   string `json:"name"`
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
		Protected bool `json:"protected"`
		Default   bool `json:"default"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glBranches); err != nil {
		return nil, err
	}

	branches := make([]*scm.GitBranch, len(glBranches))
	for i, glBranch := range glBranches {
		branches[i] = &scm.GitBranch{
			BranchName:   glBranch.Name,
			HeadCommit:   glBranch.Commit.ID,
			IsProtected:  glBranch.Protected,
			IsMainBranch: glBranch.Default,
		}
	}

	return branches, nil
}

// FetchTags lists tags in a project
func (c *GitLabConnector) FetchTags(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitTag, error) {
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))
	page := pagination.PageNum
	if page < 1 {
		page = 1
	}
	perPage := pagination.PageSize
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	endpoint := fmt.Sprintf("%s/projects/%s/repository/tags?page=%d&per_page=%d", c.apiURL, projectPath, page, perPage)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var glTags []struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Commit  struct {
			ID          string    `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			AuthorName  string    `json:"author_name"`
			AuthorEmail string    `json:"author_email"`
		} `json:"commit"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glTags); err != nil {
		return nil, err
	}

	tags := make([]*scm.GitTag, len(glTags))
	for i, glTag := range glTags {
		tags[i] = &scm.GitTag{
			TagName:       glTag.Name,
			TargetCommit:  glTag.Commit.ID,
			AnnotationMsg: glTag.Message,
			TaggerName:    glTag.Commit.AuthorName,
			TaggedAt:      glTag.Commit.CreatedAt,
		}
	}

	return tags, nil
}

// FetchTagByName gets a specific tag
func (c *GitLabConnector) FetchTagByName(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, tagName string) (*scm.GitTag, error) {
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))
	endpoint := fmt.Sprintf("%s/projects/%s/repository/tags/%s", c.apiURL, projectPath, url.PathEscape(tagName))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var glTag struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Commit  struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"commit"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glTag); err != nil {
		return nil, err
	}

	return &scm.GitTag{
		TagName:       glTag.Name,
		TargetCommit:  glTag.Commit.ID,
		AnnotationMsg: glTag.Message,
		TaggedAt:      glTag.Commit.CreatedAt,
	}, nil
}

// FetchCommit gets details for a specific commit
func (c *GitLabConnector) FetchCommit(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, commitHash string) (*scm.GitCommit, error) {
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))
	endpoint := fmt.Sprintf("%s/projects/%s/repository/commits/%s", c.apiURL, projectPath, commitHash)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var glCommit struct {
		ID            string    `json:"id"`
		Title         string    `json:"title"`
		Message       string    `json:"message"`
		AuthorName    string    `json:"author_name"`
		AuthorEmail   string    `json:"author_email"`
		CommittedDate time.Time `json:"committed_date"`
		WebURL        string    `json:"web_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&glCommit); err != nil {
		return nil, err
	}

	return &scm.GitCommit{
		CommitHash:  glCommit.ID,
		Subject:     glCommit.Title,
		AuthorName:  glCommit.AuthorName,
		AuthorEmail: glCommit.AuthorEmail,
		CommittedAt: glCommit.CommittedDate,
		CommitURL:   glCommit.WebURL,
	}, nil
}

// DownloadSourceArchive downloads project contents at a specific ref
func (c *GitLabConnector) DownloadSourceArchive(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, gitRef string, format scm.ArchiveKind) (io.ReadCloser, error) {
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", ownerName, repoName))

	// GitLab uses different format names
	archiveFormat := "tar.gz"
	if format == scm.ArchiveZipball {
		archiveFormat = "zip"
	}

	endpoint := fmt.Sprintf("%s/projects/%s/repository/archive.%s?sha=%s", c.apiURL, projectPath, archiveFormat, gitRef)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

// RegisterWebhook creates a webhook on the project
func (c *GitLabConnector) RegisterWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, hookConfig scm.WebhookSetup) (*scm.WebhookInfo, error) {
	return nil, scm.ErrWebhookSetupFailed
}

// RemoveWebhook deletes a webhook from the project
func (c *GitLabConnector) RemoveWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, hookID string) error {
	return scm.ErrWebhookNotFound
}

// ParseDelivery parses an incoming webhook payload
func (c *GitLabConnector) ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*scm.IncomingHook, error) {
	return nil, scm.ErrWebhookPayloadMalformed
}

// VerifyDeliverySignature validates webhook authenticity
func (c *GitLabConnector) VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	return false
}

// Helper methods

func (c *GitLabConnector) setAuthHeaders(req *http.Request, creds *scm.AccessToken) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))
	req.Header.Set("Content-Type", "application/json")
}

func (c *GitLabConnector) convertProject(glProject *gitlabProject) *scm.SourceRepo {
	namespace := ""
	if glProject.Namespace.Path != "" {
		namespace = glProject.Namespace.Path
	}

	isPrivate := glProject.Visibility != "public"

	return &scm.SourceRepo{
		Owner:         namespace,
		OwnerName:     namespace,
		Name:          glProject.Path,
		RepoName:      glProject.Path,
		FullName:      glProject.PathWithNamespace,
		FullPath:      glProject.PathWithNamespace,
		Description:   glProject.Description,
		HTMLURL:       glProject.WebURL,
		WebURL:        glProject.WebURL,
		CloneURL:      glProject.HTTPURLToRepo,
		GitCloneURL:   glProject.HTTPURLToRepo,
		DefaultBranch: glProject.DefaultBranch,
		MainBranch:    glProject.DefaultBranch,
		Private:       isPrivate,
		IsPrivate:     isPrivate,
		UpdatedAt:     glProject.LastActivityAt,
		LastUpdatedAt: glProject.LastActivityAt,
	}
}

type gitlabProject struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Path              string    `json:"path"`
	PathWithNamespace string    `json:"path_with_namespace"`
	Description       string    `json:"description"`
	WebURL            string    `json:"web_url"`
	HTTPURLToRepo     string    `json:"http_url_to_repo"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"`
	LastActivityAt    time.Time `json:"last_activity_at"`
	Namespace         struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Path     string `json:"path"`
		FullPath string `json:"full_path"`
	} `json:"namespace"`
}

func init() {
	scm.RegisterConnector(scm.KindGitLab, func(settings *scm.ConnectorSettings) (scm.Connector, error) {
		return NewGitLabConnector(settings)
	})
}

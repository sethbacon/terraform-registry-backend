// Package azuredevops implements the SCM Connector interface for Azure DevOps. It handles OAuth 2.0
// authorization, repository listing, webhook registration, and commit resolution using the Azure
// DevOps REST API. Azure DevOps uses organization-scoped URLs rather than per-repository URLs,
// which is reflected in its OAuth scope and API endpoint structure.
package azuredevops

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

const (
	defaultAzureDevOpsURL = "https://dev.azure.com"
	// Azure DevOps resource ID for Entra ID OAuth scopes
	azureDevOpsResourceID = "499b84ac-1321-427f-aa17-267ca6975798"
	// Entra ID OAuth 2.0 endpoints (tenant-specific URLs built at runtime)
	entraAuthURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	entraTokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	// maxExtractBytes caps the total uncompressed size of any single archive entry
	// during zip→tar.gz conversion to prevent decompression bomb attacks.
	maxExtractBytes = 500 << 20 // 500 MB
)

// AzureDevOpsConnector implements scm.Connector for Azure DevOps using Microsoft Entra ID OAuth
type AzureDevOpsConnector struct {
	clientID     string
	clientSecret string
	callbackURL  string
	baseURL      string
	tenantID     string
	organization string
}

// NewAzureDevOpsConnector creates an Azure DevOps connector.
// The InstanceBaseURL is expected to include the organization name as the first path segment,
// e.g. https://dev.azure.com/myorg or https://ado.company.com/myorg.
// The constructor splits that into a host base URL and an organization name so all API
// endpoint templates (which reference both separately) produce valid paths.
func NewAzureDevOpsConnector(settings *scm.ConnectorSettings) (*AzureDevOpsConnector, error) {
	baseURL := defaultAzureDevOpsURL
	organization := ""

	if settings.InstanceBaseURL != "" {
		if parsed, err := url.Parse(settings.InstanceBaseURL); err == nil && parsed.Host != "" {
			// Extract the first path segment as the organization name and reconstruct
			// the host-only base URL so endpoint templates produce correct paths.
			parts := strings.SplitN(strings.Trim(parsed.Path, "/"), "/", 2)
			if len(parts) >= 1 && parts[0] != "" {
				scheme := parsed.Scheme
				if scheme == "" {
					scheme = "https"
				}
				baseURL = scheme + "://" + parsed.Host
				organization = parts[0]
			} else {
				baseURL = settings.InstanceBaseURL
			}
		} else {
			baseURL = settings.InstanceBaseURL
		}
	}

	return &AzureDevOpsConnector{
		clientID:     settings.ClientID,
		clientSecret: settings.ClientSecret,
		callbackURL:  settings.CallbackURL,
		baseURL:      baseURL,
		tenantID:     settings.TenantID,
		organization: organization,
	}, nil
}

func (c *AzureDevOpsConnector) Platform() scm.ProviderKind {
	return scm.KindAzureDevOps
}

func (c *AzureDevOpsConnector) AuthorizationEndpoint(stateParam string, requestedScopes []string) string {
	// Use .default to request all Azure DevOps permissions granted to the app registration
	scope := azureDevOpsResourceID + "/.default"
	if len(requestedScopes) > 0 {
		scope = strings.Join(requestedScopes, " ")
	}

	params := url.Values{}
	params.Set("client_id", c.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", c.callbackURL)
	params.Set("scope", scope)
	params.Set("state", stateParam)

	authURL := fmt.Sprintf(entraAuthURLTemplate, c.tenantID)
	return fmt.Sprintf("%s?%s", authURL, params.Encode())
}

func (c *AzureDevOpsConnector) CompleteAuthorization(ctx context.Context, authCode string) (*scm.AccessToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", c.callbackURL)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	tokenURL := fmt.Sprintf(entraTokenURLTemplate, c.tenantID)
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
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

func (c *AzureDevOpsConnector) RenewToken(ctx context.Context, refreshToken string) (*scm.AccessToken, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	tokenURL := fmt.Sprintf(entraTokenURLTemplate, c.tenantID)
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
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

func (c *AzureDevOpsConnector) FetchRepositories(ctx context.Context, creds *scm.AccessToken, pagination scm.Pagination) (*scm.RepoListResult, error) {
	// First, get projects
	projects, err := c.fetchProjects(ctx, creds)
	if err != nil {
		return nil, err
	}

	allRepos := []*scm.SourceRepo{}

	// Fetch repos for each project
	for _, project := range projects {
		endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories?api-version=7.0", c.baseURL, c.organization, project.Name)

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}
		c.setAuthHeaders(req, creds)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

		var result struct {
			Value []adoRepo `json:"value"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			_ = resp.Body.Close()
			continue
		}
		_ = resp.Body.Close()

		for _, adoRepo := range result.Value {
			allRepos = append(allRepos, c.convertRepo(&adoRepo, project.Name))
		}
	}

	return &scm.RepoListResult{
		Repos:     allRepos,
		MorePages: false,
	}, nil
}

func (c *AzureDevOpsConnector) FetchRepository(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string) (*scm.SourceRepo, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s?api-version=7.0", c.baseURL, c.organization, ownerName, repoName)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
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

	var adoRepo adoRepo
	if err := json.NewDecoder(resp.Body).Decode(&adoRepo); err != nil {
		return nil, err
	}

	return c.convertRepo(&adoRepo, ownerName), nil
}

func (c *AzureDevOpsConnector) SearchRepositories(ctx context.Context, creds *scm.AccessToken, searchTerm string, pagination scm.Pagination) (*scm.RepoListResult, error) {
	// Azure DevOps doesn't have direct repo search, so fetch all and filter
	allRepos, err := c.FetchRepositories(ctx, creds, pagination)
	if err != nil {
		return nil, err
	}

	filtered := []*scm.SourceRepo{}
	searchLower := strings.ToLower(searchTerm)
	for _, repo := range allRepos.Repos {
		if strings.Contains(strings.ToLower(repo.RepoName), searchLower) ||
			strings.Contains(strings.ToLower(repo.Description), searchLower) {
			filtered = append(filtered, repo)
		}
	}

	return &scm.RepoListResult{
		Repos:     filtered,
		MorePages: false,
	}, nil
}

func (c *AzureDevOpsConnector) FetchBranches(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitBranch, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/refs?filter=heads/&api-version=7.0", c.baseURL, c.organization, ownerName, repoName)

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

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	branches := make([]*scm.GitBranch, len(result.Value))
	for i, ref := range result.Value {
		branchName := strings.TrimPrefix(ref.Name, "refs/heads/")
		branches[i] = &scm.GitBranch{
			BranchName: branchName,
			HeadCommit: ref.ObjectID,
		}
	}

	return branches, nil
}

func (c *AzureDevOpsConnector) FetchTags(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, pagination scm.Pagination) ([]*scm.GitTag, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/refs?filter=tags/&api-version=7.0", c.baseURL, c.organization, ownerName, repoName)
	fmt.Printf("[FetchTags] GET %s\n", endpoint)

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

	// Azure DevOps returns 203 with an HTML sign-in page when the token is expired
	// instead of a proper 401. Normalise it so retry logic can detect it.
	actualStatus := resp.StatusCode
	if actualStatus == http.StatusNonAuthoritativeInfo {
		actualStatus = http.StatusUnauthorized
	}
	if actualStatus != http.StatusOK {
		body := readErrorBody(resp)
		return nil, scm.WrapRemoteError(actualStatus, fmt.Sprintf("failed to fetch tags: HTTP %d: %s", resp.StatusCode, body), nil)
	}

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	tags := make([]*scm.GitTag, len(result.Value))
	for i, ref := range result.Value {
		tagName := strings.TrimPrefix(ref.Name, "refs/tags/")
		tags[i] = &scm.GitTag{
			TagName:      tagName,
			TargetCommit: ref.ObjectID,
		}
	}

	return tags, nil
}

func (c *AzureDevOpsConnector) FetchTagByName(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, tagName string) (*scm.GitTag, error) {
	tags, err := c.FetchTags(ctx, creds, ownerName, repoName, scm.DefaultPagination())
	if err != nil {
		return nil, err
	}

	for _, tag := range tags {
		if tag.TagName == tagName {
			return tag, nil
		}
	}

	return nil, scm.ErrTagNotFound
}

func (c *AzureDevOpsConnector) FetchCommit(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, commitHash string) (*scm.GitCommit, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/commits/%s?api-version=7.0", c.baseURL, c.organization, ownerName, repoName, commitHash)

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

	var adoCommit struct {
		CommitID string `json:"commitId"`
		Comment  string `json:"comment"`
		Author   struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"author"`
		RemoteURL string `json:"remoteUrl"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&adoCommit); err != nil {
		return nil, err
	}

	return &scm.GitCommit{
		CommitHash:  adoCommit.CommitID,
		Subject:     adoCommit.Comment,
		AuthorName:  adoCommit.Author.Name,
		AuthorEmail: adoCommit.Author.Email,
		CommittedAt: adoCommit.Author.Date,
		CommitURL:   adoCommit.RemoteURL,
	}, nil
}

// commitSHARegexp matches a full 40-character hex commit SHA.
var commitSHARegexp = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func (c *AzureDevOpsConnector) DownloadSourceArchive(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, gitRef string, format scm.ArchiveKind) (io.ReadCloser, error) {
	// Determine the versionType based on the gitRef format.
	// Azure DevOps defaults to "branch" if versionType is omitted, so commit SHAs
	// must be explicitly typed as "commit" or the API returns a 400/404.
	versionType := "branch"
	if commitSHARegexp.MatchString(gitRef) {
		versionType = "commit"
	}

	// Azure DevOps only supports zip format for repository item downloads.
	// We download as zip and convert to tar.gz so callers get a consistent stream.
	// Note: must use "scopePath" (not "path") when recursionLevel != None.
	endpoint := fmt.Sprintf(
		"%s/%s/%s/_apis/git/repositories/%s/items?scopePath=/&recursionLevel=full&versionDescriptor.version=%s&versionDescriptor.versionType=%s&$format=zip&download=true&api-version=7.0",
		c.baseURL, c.organization, ownerName, repoName, gitRef, versionType,
	)

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
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, scm.WrapRemoteError(resp.StatusCode, fmt.Sprintf("failed to download archive: %s", string(body)), nil)
	}

	// Read the entire zip response into memory so we can use zip.NewReader (which needs io.ReaderAt).
	zipData, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read zip response: %w", err)
	}

	// Convert zip → tar.gz in memory and return a ReadCloser.
	tgzData, err := zipToTarGz(zipData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert zip to tar.gz: %w", err)
	}

	return io.NopCloser(bytes.NewReader(tgzData)), nil
}

// zipToTarGz converts a zip archive (in-memory) to a tar.gz byte slice.
func zipToTarGz(zipData []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, f := range zr.File {
		hdr := &tar.Header{
			Name:     f.Name,
			Size:     int64(f.UncompressedSize64),
			Mode:     int64(f.Mode()),
			ModTime:  f.Modified,
			Typeflag: tar.TypeReg,
		}
		if f.FileInfo().IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
			continue
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}

		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		_, copyErr := io.Copy(tw, io.LimitReader(rc, maxExtractBytes))
		_ = rc.Close()
		if copyErr != nil {
			return nil, copyErr
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Stub methods for webhooks
func (c *AzureDevOpsConnector) RegisterWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, hookConfig scm.WebhookSetup) (*scm.WebhookInfo, error) {
	return nil, scm.ErrWebhookSetupFailed
}

func (c *AzureDevOpsConnector) RemoveWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, hookID string) error {
	return scm.ErrWebhookNotFound
}

func (c *AzureDevOpsConnector) ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*scm.IncomingHook, error) {
	return nil, scm.ErrWebhookPayloadMalformed
}

func (c *AzureDevOpsConnector) VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	return false
}

// Helper methods

func (c *AzureDevOpsConnector) setAuthHeaders(req *http.Request, creds *scm.AccessToken) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))
	req.Header.Set("Content-Type", "application/json")
}

// readErrorBody reads up to 512 bytes from an error response body for inclusion in error messages.
func readErrorBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

func (c *AzureDevOpsConnector) fetchProjects(ctx context.Context, creds *scm.AccessToken) ([]adoProject, error) {
	endpoint := fmt.Sprintf("%s/%s/_apis/projects?api-version=7.0", c.baseURL, c.organization)

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
		// Azure DevOps / Entra ID returns HTTP 203 Non-Authoritative when the
		// bearer token is expired or invalid rather than the expected 401.
		// Normalise 203 to 401 so that callers' token-refresh logic triggers.
		reportedStatus := resp.StatusCode
		if reportedStatus == http.StatusNonAuthoritativeInfo {
			reportedStatus = http.StatusUnauthorized
		}
		return nil, scm.WrapRemoteError(reportedStatus, fmt.Sprintf("failed to fetch projects (HTTP %d)", resp.StatusCode), nil)
	}

	var result struct {
		Value []adoProject `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, scm.WrapRemoteError(0, "failed to parse project list", err)
	}

	return result.Value, nil
}

func (c *AzureDevOpsConnector) convertRepo(adoRepo *adoRepo, projectName string) *scm.SourceRepo {
	return &scm.SourceRepo{
		Owner:         projectName,
		OwnerName:     projectName,
		Name:          adoRepo.Name,
		RepoName:      adoRepo.Name,
		FullName:      fmt.Sprintf("%s/%s", projectName, adoRepo.Name),
		FullPath:      fmt.Sprintf("%s/%s", projectName, adoRepo.Name),
		HTMLURL:       adoRepo.WebURL,
		WebURL:        adoRepo.WebURL,
		CloneURL:      adoRepo.RemoteURL,
		GitCloneURL:   adoRepo.RemoteURL,
		DefaultBranch: adoRepo.DefaultBranch,
		MainBranch:    adoRepo.DefaultBranch,
	}
}

type adoProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type adoRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	WebURL        string `json:"webUrl"`
	RemoteURL     string `json:"remoteUrl"`
	DefaultBranch string `json:"defaultBranch"`
}

// Register the Azure DevOps connector
func init() {
	scm.RegisterConnector(scm.KindAzureDevOps, func(settings *scm.ConnectorSettings) (scm.Connector, error) {
		return NewAzureDevOpsConnector(settings)
	})
}

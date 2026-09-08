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
	"errors"
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
	// Entra ID OAuth 2.0 endpoints (tenant-specific URLs built at runtime); %s is the tenant ID placeholder.
	entraAuthURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" // #nosec G101 -- URL template, not a credential
	entraTokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"     // #nosec G101 -- URL template, not a credential
	// maxExtractBytes caps the total uncompressed size of any single archive entry
	// during zip→tar.gz conversion to prevent decompression bomb attacks.
	maxExtractBytes = 500 << 20 // 500 MB
	// maxArchiveDownloadBytes caps the raw (compressed) zip response read into
	// memory before conversion. Unlike the other SCM connectors (github/gitlab/
	// bitbucket), which stream resp.Body straight back to the caller, Azure
	// DevOps only supports zip and zip.NewReader requires an io.ReaderAt, so the
	// response must be fully buffered here — but that buffering must still be
	// size-capped (CWE-400), matching the cap already applied to each extracted
	// entry below.
	maxArchiveDownloadBytes = 500 << 20 // 500 MB
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

// ParseOrganization extracts the Azure DevOps organization name from a
// base URL, e.g. "myorg" from "https://dev.azure.com/myorg" or
// "https://ado.company.com/myorg". Returns "" with no error when
// instanceBaseURL is empty -- an absent URL is a configuration question for
// the caller, not a parse failure -- and an error when a URL IS supplied but
// carries no organization segment, which is never valid: every endpoint this
// connector calls interpolates the organization into the path (#1036).
//
// This is the single source of truth for the parse. CreateProvider and
// UpdateProvider (internal/api/admin/scm_providers.go) call it through
// RequireOrganization to reject a bad base_url before it is ever saved; the
// constructor below calls it to build the connector. One parser means the
// validator and the connector can never disagree about which URLs are valid.
func ParseOrganization(instanceBaseURL string) (org, hostBaseURL string, err error) {
	if instanceBaseURL == "" {
		return "", "", nil
	}
	parsed, parseErr := url.Parse(instanceBaseURL)
	if parseErr != nil || parsed.Host == "" {
		return "", "", fmt.Errorf(
			"base_url %q is not a valid URL", instanceBaseURL)
	}
	parts := strings.SplitN(strings.Trim(parsed.Path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", "", fmt.Errorf(
			"base_url %q has no organization: an Azure DevOps base_url must include "+
				"the organization as the first path segment, e.g. https://dev.azure.com/<org>",
			instanceBaseURL)
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return parts[0], scheme + "://" + parsed.Host, nil
}

// RequireOrganization is ParseOrganization plus the "must be present at all"
// half of the check: nil or empty is rejected too, which ParseOrganization
// alone cannot do because the constructor legitimately wants "" to mean
// "fall back to the default host" for an empty settings struct in tests.
// Called from CreateProvider and UpdateProvider (#1036); "" there is a
// caller who never set base_url at all, which is the exact hole this closes.
func RequireOrganization(baseURL *string) error {
	if baseURL == nil || *baseURL == "" {
		return fmt.Errorf(
			"base_url is required for Azure DevOps and must include the organization, " +
				"e.g. https://dev.azure.com/<org>")
	}
	_, _, err := ParseOrganization(*baseURL)
	return err
}

// NewAzureDevOpsConnector creates an Azure DevOps connector.
// The InstanceBaseURL is expected to include the organization name as the first path segment,
// e.g. https://dev.azure.com/myorg or https://ado.company.com/myorg.
// The constructor splits that into a host base URL and an organization name so all API
// endpoint templates (which reference both separately) produce valid paths.
//
// Returns an error rather than an empty organization when InstanceBaseURL IS
// supplied but has no org segment (#1036): every endpoint template below
// interpolates baseURL and organization together
// ("%s/%s/_apis/..."), so a silently empty organization used to produce a
// double-slash URL that failed far from here, with no indication why. A
// caller with the empty-settings shape RequireOrganization would reject
// (nil/empty InstanceBaseURL) still gets the pre-existing default-host
// fallback: that shape is used deliberately by callers -- tests among them
// -- that want a bare connector, and CreateProvider/UpdateProvider close that
// door before a row can be saved with it.
func NewAzureDevOpsConnector(settings *scm.ConnectorSettings) (*AzureDevOpsConnector, error) {
	baseURL := defaultAzureDevOpsURL
	organization := ""

	if settings.InstanceBaseURL != "" {
		org, hostBaseURL, err := ParseOrganization(settings.InstanceBaseURL)
		if err != nil {
			return nil, fmt.Errorf("azuredevops: %w", err)
		}
		baseURL = hostBaseURL
		organization = org
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
	return scm.ProviderAzureDevOps
}

func (c *AzureDevOpsConnector) AuthorizationEndpoint(stateParam string, requestedScopes []string) string {
	// Use .default to request all Azure DevOps permissions granted to the app registration.
	// offline_access is required for Microsoft Entra ID to issue a refresh token alongside
	// the access token. Without it only a short-lived access token (~1 h) is returned and
	// automatic renewal is impossible once it expires.
	scope := azureDevOpsResourceID + "/.default offline_access"
	if len(requestedScopes) > 0 {
		// Caller-supplied scopes override the default; ensure offline_access is always present
		// so that a refresh token is always issued.
		scopes := requestedScopes
		hasOfflineAccess := false
		for _, s := range scopes {
			if s == "offline_access" {
				hasOfflineAccess = true
				break
			}
		}
		if !hasOfflineAccess {
			scopes = append(scopes, "offline_access")
		}
		scope = strings.Join(scopes, " ")
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

	var result struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	tokenURL := fmt.Sprintf(entraTokenURLTemplate, c.tenantID)
	if err := scm.ExchangeOAuthForm(ctx, tokenURL, data, "", &result); err != nil {
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
		return nil, fmt.Errorf("azuredevops: create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := scm.HTTPClient.Do(req)
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

	if err := json.NewDecoder(scm.LimitBody(resp.Body)).Decode(&result); err != nil {
		return nil, fmt.Errorf("azuredevops: decode refresh response: %w", err)
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
		return nil, fmt.Errorf("azuredevops: list projects: %w", err)
	}

	allRepos := []*scm.SourceRepo{}

	// Fetch repos for each project
	for _, project := range projects {
		endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories?api-version=7.0", c.baseURL, c.organization, project.Name)

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("azuredevops: create repositories request for project %q: %w", project.Name, err)
		}
		c.setAuthHeaders(req, creds)

		var result struct {
			Value []adoRepo `json:"value"`
		}

		// A failure here used to `continue`, which returned the repositories gathered so
		// far with a nil error — an expired token (ADO answers 203 with an HTML sign-in
		// page) produced a silently short listing that every caller read as a complete,
		// successful result. Fail the whole call instead.
		if err := doJSON(req, "failed to fetch repositories", nil, &result); err != nil {
			return nil, err
		}

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
		return nil, fmt.Errorf("azuredevops: create repo request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	var adoRepo adoRepo
	if err := doJSON(req, "failed to fetch repository", scm.ErrRepoNotFound, &adoRepo); err != nil {
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
		return nil, fmt.Errorf("azuredevops: create branches request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}

	if err := doJSON(req, "failed to fetch branches", nil, &result); err != nil {
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
	// peelTags=true causes ADO to include peeledObjectId for annotated tags,
	// which is the actual commit SHA (objectId for annotated tags is the tag object SHA, not the commit).
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/refs?filter=tags/&peelTags=true&api-version=7.0", c.baseURL, c.organization, ownerName, repoName)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("azuredevops: create tags request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	var result struct {
		Value []struct {
			Name           string `json:"name"`
			ObjectID       string `json:"objectId"`
			PeeledObjectID string `json:"peeledObjectId"` // commit SHA for annotated tags; absent for lightweight tags
		} `json:"value"`
	}

	if err := doJSON(req, "failed to fetch tags", nil, &result); err != nil {
		return nil, err
	}

	tags := make([]*scm.GitTag, len(result.Value))
	for i, ref := range result.Value {
		tagName := strings.TrimPrefix(ref.Name, "refs/tags/")
		// For annotated tags peeledObjectId holds the commit SHA; objectId is the tag object SHA.
		// For lightweight tags peeledObjectId is absent, so objectId is already the commit SHA.
		commitSHA := ref.ObjectID
		if ref.PeeledObjectID != "" {
			commitSHA = ref.PeeledObjectID
		}
		tags[i] = &scm.GitTag{
			TagName:      tagName,
			TargetCommit: commitSHA,
		}
	}

	return tags, nil
}

func (c *AzureDevOpsConnector) FetchTagByName(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, tagName string) (*scm.GitTag, error) {
	tags, err := c.FetchTags(ctx, creds, ownerName, repoName, scm.DefaultPagination())
	if err != nil {
		return nil, fmt.Errorf("azuredevops: fetch tags for lookup: %w", err)
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
		return nil, fmt.Errorf("azuredevops: create commit request: %w", err)
	}
	c.setAuthHeaders(req, creds)

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

	if err := doJSON(req, "failed to fetch commit", scm.ErrCommitNotFound, &adoCommit); err != nil {
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
		return nil, fmt.Errorf("azuredevops: create archive request: %w", err)
	}
	c.setAuthHeaders(req, creds)
	// #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := scm.HTTPClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to download archive", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(scm.LimitErrorBody(resp.Body))
		_ = resp.Body.Close()
		return nil, scm.WrapRemoteError(resp.StatusCode, fmt.Sprintf("failed to download archive: %s", string(body)), nil)
	}

	// Read the entire zip response into memory so we can use zip.NewReader (which
	// needs io.ReaderAt). Capped at maxArchiveDownloadBytes to bound memory use
	// against an oversized or slow-trickle response (CWE-400); +1 lets us detect
	// and report the overflow with a clear error rather than silently truncating
	// into a corrupt zip that would otherwise fail with an opaque "not a valid
	// zip file" error.
	zipData, err := io.ReadAll(io.LimitReader(resp.Body, maxArchiveDownloadBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read zip response: %w", err)
	}
	if int64(len(zipData)) > maxArchiveDownloadBytes {
		return nil, fmt.Errorf("archive exceeds size cap (%d bytes)", maxArchiveDownloadBytes)
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

// fetchRepoAndProjectIDs retrieves the ADO project GUID and repository GUID required
// by the service-hooks subscriptions API. ownerName is the ADO project name.
func (c *AzureDevOpsConnector) fetchRepoAndProjectIDs(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string) (projectID, repoID string, err error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s?api-version=7.0",
		c.baseURL, c.organization, url.PathEscape(ownerName), url.PathEscape(repoName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	var result struct {
		ID      string `json:"id"`
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}
	if err := doJSON(req, "failed to fetch repository IDs", nil, &result); err != nil {
		return "", "", err
	}
	return result.Project.ID, result.ID, nil
}

// RegisterWebhook creates an Azure DevOps service-hook subscription for git.push events
// on the specified repository. ownerName is the ADO project name; repoName is the repository name.
func (c *AzureDevOpsConnector) RegisterWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName string, hookConfig scm.WebhookSetup) (*scm.WebhookInfo, error) {
	projectID, repoID, err := c.fetchRepoAndProjectIDs(ctx, creds, ownerName, repoName)
	if err != nil {
		return nil, fmt.Errorf("azuredevops: register webhook: %w", err)
	}

	endpoint := fmt.Sprintf("%s/%s/_apis/hooks/subscriptions?api-version=7.1", c.baseURL, c.organization)
	body := map[string]interface{}{
		"publisherId": "tfs",
		"eventType":   "git.push",
		"publisherInputs": map[string]string{
			"projectId":  projectID,
			"repository": repoID,
			"branch":     "",
			"pushedBy":   "",
		},
		"consumerId":       "webHooks",
		"consumerActionId": "httpRequest",
		"consumerInputs": map[string]string{
			"url":                    hookConfig.CallbackURL,
			"httpHeaders":            "",
			"resourceDetailsToSend":  "all",
			"messagesToSend":         "all",
			"detailedMessagesToSend": "all",
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("azuredevops: marshal webhook body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("azuredevops: create subscription request: %w", err)
	}
	c.setAuthHeaders(req, creds)
	// #nosec G107 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := scm.HTTPClient.Do(req)
	if err != nil {
		return nil, scm.WrapRemoteError(0, "failed to create service hook subscription", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, scm.WrapRemoteError(resp.StatusCode, "failed to create service hook subscription", nil)
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(scm.LimitBody(resp.Body)).Decode(&result); err != nil {
		return nil, fmt.Errorf("azuredevops: decode subscription response: %w", err)
	}
	return &scm.WebhookInfo{
		ExternalID:  result.ID,
		CallbackURL: hookConfig.CallbackURL,
		EventTypes:  []string{"git.push"},
		IsActive:    true,
	}, nil
}

// RemoveWebhook deletes an Azure DevOps service-hook subscription by its subscription ID.
func (c *AzureDevOpsConnector) RemoveWebhook(ctx context.Context, creds *scm.AccessToken, ownerName, repoName, hookID string) error {
	endpoint := fmt.Sprintf("%s/%s/_apis/hooks/subscriptions/%s?api-version=7.1", c.baseURL, c.organization, hookID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("azuredevops: create delete subscription request: %w", err)
	}
	c.setAuthHeaders(req, creds)
	// #nosec G107 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := scm.HTTPClient.Do(req)
	if err != nil {
		return scm.WrapRemoteError(0, "failed to delete service hook subscription", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return scm.ErrWebhookNotFound
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return scm.WrapRemoteError(resp.StatusCode, "failed to delete service hook subscription", nil)
	}
	return nil
}

// adoPushPayload is the minimal subset of an ADO git.push service-hook payload
// that the registry needs to extract tag information.
type adoPushPayload struct {
	EventType string `json:"eventType"`
	ID        string `json:"id"`
	Resource  struct {
		RefUpdates []struct {
			Name        string `json:"name"`
			NewObjectID string `json:"newObjectId"`
			OldObjectID string `json:"oldObjectId"`
		} `json:"refUpdates"`
		Repository struct {
			RemoteURL string `json:"remoteUrl"`
			WebURL    string `json:"webUrl"`
		} `json:"repository"`
	} `json:"resource"`
}

const zeroOID = "0000000000000000000000000000000000000000"

// ParseDelivery parses an Azure DevOps git.push service-hook payload.
// ADO fires a git.push event for every ref update, including tag creation.
// A new tag is identified by a refUpdate whose name starts with "refs/tags/"
// and whose oldObjectId is all zeros (indicating a newly created ref).
func (c *AzureDevOpsConnector) ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*scm.IncomingHook, error) {
	if len(payloadBytes) == 0 {
		return nil, scm.ErrWebhookPayloadMalformed
	}

	var p adoPushPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, scm.ErrWebhookPayloadMalformed
	}

	if p.EventType != "git.push" {
		// Non-push events (e.g. pull_request_merged) are not used for auto-publish.
		return &scm.IncomingHook{
			ID:   p.ID,
			Type: scm.WebhookEventUnknown,
		}, nil
	}

	// Find the first newly-created tag ref in this push.
	for _, ref := range p.Resource.RefUpdates {
		if !strings.HasPrefix(ref.Name, "refs/tags/") {
			continue
		}
		if ref.OldObjectID != zeroOID {
			// Tag already existed — not a new publish event.
			continue
		}
		tagName := strings.TrimPrefix(ref.Name, "refs/tags/")
		return &scm.IncomingHook{
			ID:        p.ID,
			Type:      scm.WebhookEventTag,
			Ref:       ref.Name,
			CommitSHA: ref.NewObjectID,
			TagName:   tagName,
		}, nil
	}

	// Push contained no new tag refs — treat as a plain branch push.
	return &scm.IncomingHook{
		ID:   p.ID,
		Type: scm.WebhookEventPush,
	}, nil
}

// VerifyDeliverySignature always returns true for Azure DevOps.
// ADO service hooks do not include an HMAC payload signature; the shared
// secret is embedded in the webhook callback URL and is validated by the
// registry's HandleWebhook handler before this method is called.
func (c *AzureDevOpsConnector) VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool {
	return true
}

// Helper methods

func (c *AzureDevOpsConnector) setAuthHeaders(req *http.Request, creds *scm.AccessToken) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", creds.AccessToken))
	req.Header.Set("Content-Type", "application/json")
}

// doJSON is the single entry point for every Azure DevOps JSON API call. It delegates to
// scm.DoJSON — the shared SSRF-safe send/status-check/size-capped-decode helper — and then
// applies the one status quirk that is specific to this provider: Azure DevOps and Microsoft
// Entra ID answer an expired or invalid bearer token with HTTP 203 Non-Authoritative
// Information carrying an HTML sign-in page, not the expected 401. Callers
// (internal/api/admin/scm_oauth.go) decide whether to refresh the OAuth token by comparing
// APIError.StatusCode, so the code is normalised here, once, rather than in each method that
// happens to remember to do it.
func doJSON(req *http.Request, reason string, notFound error, out any) error {
	err := scm.DoJSON(req, reason, notFound, out)
	var apiErr *scm.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNonAuthoritativeInfo {
		apiErr.StatusCode = http.StatusUnauthorized
	}
	return err
}

// VerifyOrganizationReachable proves the credential and the organization
// together, which minting an Entra token alone cannot: Azure DevOps has its
// own permission model separate from Entra, so a service principal can hold a
// perfectly valid Entra token and still get a 401/203 from dev.azure.com if
// it was never added under Organization settings -> Users (#1036). This is
// the cheapest call that proves both: list projects, and only look at
// whether the request succeeded.
func (c *AzureDevOpsConnector) VerifyOrganizationReachable(ctx context.Context, creds *scm.AccessToken) error {
	if c.organization == "" {
		// Reachable from a pre-#1036 row whose base_url predates the
		// CreateProvider/UpdateProvider guard. Name the real problem rather
		// than letting the request below produce a double-slash 404 that
		// looks like an org-membership failure.
		return fmt.Errorf("no organization configured: base_url must include the organization, e.g. https://dev.azure.com/<org>")
	}
	if _, err := c.fetchProjects(ctx, creds); err != nil {
		return fmt.Errorf("organization %q is not reachable with this credential "+
			"(a valid Entra token does not by itself grant Azure DevOps access -- "+
			"the service principal must be added under Organization settings -> Users): %w",
			c.organization, err)
	}
	return nil
}

func (c *AzureDevOpsConnector) fetchProjects(ctx context.Context, creds *scm.AccessToken) ([]adoProject, error) {
	endpoint := fmt.Sprintf("%s/%s/_apis/projects?api-version=7.0", c.baseURL, c.organization)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("azuredevops: create projects request: %w", err)
	}
	c.setAuthHeaders(req, creds)

	var result struct {
		Value []adoProject `json:"value"`
	}

	if err := doJSON(req, "failed to fetch projects", nil, &result); err != nil {
		return nil, err
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
	scm.RegisterConnector(scm.ProviderAzureDevOps, func(settings *scm.ConnectorSettings) (scm.Connector, error) {
		return NewAzureDevOpsConnector(settings)
	})
}

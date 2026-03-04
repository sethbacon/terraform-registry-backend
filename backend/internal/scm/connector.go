// Package scm defines the SCM (Source Control Manager) provider interface and the factory for
// instantiating provider implementations. Supported providers include GitHub, GitLab, Azure DevOps,
// and Bitbucket Data Center. New providers are added by implementing the Connector interface and
// registering with the factory — no changes to the core registry logic are required.
package scm

import (
	"context"
	"io"
)

// ArchiveKind specifies the download format
type ArchiveKind string

const (
	ArchiveTarball ArchiveKind = "tarball"
	ArchiveZipball ArchiveKind = "zipball"
)

// Connector defines operations available on an SCM platform
type Connector interface {
	// Platform returns the provider kind
	Platform() ProviderKind

	// AuthorizationEndpoint returns the URL to redirect users for OAuth
	AuthorizationEndpoint(stateParam string, requestedScopes []string) string

	// CompleteAuthorization exchanges an auth code for tokens
	CompleteAuthorization(ctx context.Context, authCode string) (*AccessToken, error)

	// RenewToken refreshes an expired access token
	RenewToken(ctx context.Context, refreshToken string) (*AccessToken, error)

	// FetchRepositories lists repositories the user can access
	FetchRepositories(ctx context.Context, creds *AccessToken, pagination Pagination) (*RepoListResult, error)

	// FetchRepository gets details for a specific repository
	FetchRepository(ctx context.Context, creds *AccessToken, ownerName, repoName string) (*SourceRepo, error)

	// SearchRepositories finds repositories matching a query
	SearchRepositories(ctx context.Context, creds *AccessToken, searchTerm string, pagination Pagination) (*RepoListResult, error)

	// FetchBranches lists branches in a repository
	FetchBranches(ctx context.Context, creds *AccessToken, ownerName, repoName string, pagination Pagination) ([]*GitBranch, error)

	// FetchTags lists tags in a repository
	FetchTags(ctx context.Context, creds *AccessToken, ownerName, repoName string, pagination Pagination) ([]*GitTag, error)

	// FetchTagByName gets a specific tag
	FetchTagByName(ctx context.Context, creds *AccessToken, ownerName, repoName, tagName string) (*GitTag, error)

	// FetchCommit gets details for a specific commit
	FetchCommit(ctx context.Context, creds *AccessToken, ownerName, repoName, commitHash string) (*GitCommit, error)

	// DownloadSourceArchive downloads repository contents at a specific ref
	DownloadSourceArchive(ctx context.Context, creds *AccessToken, ownerName, repoName, gitRef string, format ArchiveKind) (io.ReadCloser, error)

	// RegisterWebhook creates a webhook on the repository
	RegisterWebhook(ctx context.Context, creds *AccessToken, ownerName, repoName string, hookConfig WebhookSetup) (*WebhookInfo, error)

	// RemoveWebhook deletes a webhook from the repository
	RemoveWebhook(ctx context.Context, creds *AccessToken, ownerName, repoName, hookID string) error

	// ParseDelivery parses an incoming webhook payload
	ParseDelivery(payloadBytes []byte, httpHeaders map[string]string) (*IncomingHook, error)

	// VerifyDeliverySignature validates webhook authenticity
	VerifyDeliverySignature(payloadBytes []byte, signatureHeader, sharedSecret string) bool
}

// Pagination holds page navigation parameters
type Pagination struct {
	PageNum  int
	PageSize int
}

// DefaultPagination returns standard pagination settings
func DefaultPagination() Pagination {
	return Pagination{PageNum: 1, PageSize: 30}
}

// RepoListResult contains paginated repository results
type RepoListResult struct {
	Repos      []*SourceRepo
	TotalCount int
	MorePages  bool
	NextPage   int
}

// WebhookSetup contains parameters for creating a webhook
type WebhookSetup struct {
	CallbackURL   string
	SharedSecret  string
	EventTypes    []string
	ActiveOnSetup bool
	PayloadFormat string
}

// WebhookInfo describes a registered webhook
type WebhookInfo struct {
	ExternalID  string
	CallbackURL string
	EventTypes  []string
	IsActive    bool
}

// ConnectorSettings holds configuration for creating a connector
type ConnectorSettings struct {
	Kind            ProviderKind
	InstanceBaseURL string
	ClientID        string
	ClientSecret    string
	CallbackURL     string
	TenantID        string // Required for Azure DevOps with Microsoft Entra ID OAuth
}

// Validate checks if the settings are complete
func (s *ConnectorSettings) Validate() error {
	if !s.Kind.IsValid() {
		return ErrUnknownProviderKind
	}
	// PAT-based providers don't require OAuth credentials
	if s.Kind.IsPATBased() {
		return nil
	}
	if s.ClientID == "" {
		return ErrClientIDRequired
	}
	if s.ClientSecret == "" {
		return ErrClientSecretRequired
	}
	if s.CallbackURL == "" {
		return ErrCallbackURLRequired
	}
	return nil
}

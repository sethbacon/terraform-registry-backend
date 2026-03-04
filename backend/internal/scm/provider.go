// provider.go defines the Provider interface that all SCM implementations must satisfy,
// along with the ProviderType constants for the supported SCM platforms.
package scm

import (
	"context"
	"io"
)

// Provider defines the interface for SCM provider implementations
type Provider interface {
	// GetType returns the provider type
	GetType() ProviderType

	// OAuth 2.0 flow methods
	GetAuthorizationURL(state string, scopes []string) string
	ExchangeCode(ctx context.Context, code string) (*OAuthToken, error)
	RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error)

	// Repository operations
	ListRepositories(ctx context.Context, token *OAuthToken, opts *ListOptions) (*RepositoryList, error)
	GetRepository(ctx context.Context, token *OAuthToken, owner, repo string) (*Repository, error)
	SearchRepositories(ctx context.Context, token *OAuthToken, query string, opts *ListOptions) (*RepositoryList, error)

	// Branch operations
	ListBranches(ctx context.Context, token *OAuthToken, owner, repo string, opts *ListOptions) ([]*Branch, error)
	GetBranch(ctx context.Context, token *OAuthToken, owner, repo, branch string) (*Branch, error)

	// Tag and commit operations
	ListTags(ctx context.Context, token *OAuthToken, owner, repo string, opts *ListOptions) ([]*Tag, error)
	GetTag(ctx context.Context, token *OAuthToken, owner, repo, tagName string) (*Tag, error)
	GetCommit(ctx context.Context, token *OAuthToken, owner, repo, sha string) (*Commit, error)

	// Archive download (for building release packages)
	DownloadArchive(ctx context.Context, token *OAuthToken, owner, repo, ref string, format ArchiveFormat) (io.ReadCloser, error)

	// Webhook management
	CreateWebhook(ctx context.Context, token *OAuthToken, owner, repo string, config *WebhookConfig) (*Webhook, error)
	UpdateWebhook(ctx context.Context, token *OAuthToken, owner, repo, webhookID string, config *WebhookConfig) (*Webhook, error)
	DeleteWebhook(ctx context.Context, token *OAuthToken, owner, repo, webhookID string) error
	ListWebhooks(ctx context.Context, token *OAuthToken, owner, repo string) ([]*Webhook, error)

	// Webhook validation
	ParseWebhookEvent(payload []byte, headers map[string]string) (*WebhookEvent, error)
	ValidateWebhookSignature(payload []byte, signature, secret string) bool
}

// ListOptions contains pagination options for list operations
type ListOptions struct {
	Page    int
	PerPage int
}

// DefaultListOptions returns sensible default pagination options
func DefaultListOptions() *ListOptions {
	return &ListOptions{
		Page:    1,
		PerPage: 30,
	}
}

// RepositoryList contains a paginated list of repositories
type RepositoryList struct {
	Repositories []*Repository
	TotalCount   int
	HasMore      bool
	NextPage     int
}

// WebhookConfig contains configuration for creating/updating webhooks
type WebhookConfig struct {
	URL         string
	Secret      string
	Events      []string
	Active      bool
	ContentType string // "json" or "form"
}

// Webhook represents a configured webhook
type Webhook struct {
	ID        string
	URL       string
	Events    []string
	Active    bool
	CreatedAt string
	UpdatedAt string
}

// ProviderConfig holds configuration for creating a provider
type ProviderConfig struct {
	Type         ProviderType
	BaseURL      string // For self-hosted instances (empty for cloud versions)
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Validate validates the provider configuration
func (c *ProviderConfig) Validate() error {
	if !c.Type.Valid() {
		return ErrInvalidProviderType
	}
	if c.ClientID == "" {
		return ErrMissingClientID
	}
	if c.ClientSecret == "" {
		return ErrMissingClientSecret
	}
	if c.RedirectURL == "" {
		return ErrMissingRedirectURL
	}
	return nil
}

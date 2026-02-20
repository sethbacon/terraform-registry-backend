// types.go declares the shared data structures used across the scm package, including
// repository info, OAuth tokens, webhook event payloads, and commit metadata.
package scm

import (
	"time"

	"github.com/google/uuid"
)

// ProviderType represents the type of SCM provider
type ProviderType string

const (
	ProviderGitHub      ProviderType = "github"
	ProviderAzureDevOps ProviderType = "azuredevops"
	ProviderGitLab      ProviderType = "gitlab"
	ProviderBitbucketDC ProviderType = "bitbucket_dc"
)

// Valid returns true if the provider type is valid
func (p ProviderType) Valid() bool {
	switch p {
	case ProviderGitHub, ProviderAzureDevOps, ProviderGitLab, ProviderBitbucketDC:
		return true
	default:
		return false
	}
}

// IsPATBased returns true if the provider uses Personal Access Tokens instead of OAuth
func (p ProviderType) IsPATBased() bool {
	return p == ProviderBitbucketDC
}

// IsValid is an alias for Valid()
func (p ProviderType) IsValid() bool {
	return p.Valid()
}

// String returns the string representation of the provider type
func (p ProviderType) String() string {
	return string(p)
}

// Repository represents a source code repository
type Repository struct {
	ID            string    `json:"id"`
	Owner         string    `json:"owner"`
	OwnerName     string    `json:"owner_name"` // Alias for Owner
	Name          string    `json:"name"`
	RepoName      string    `json:"repo_name"` // Alias for Name
	FullName      string    `json:"full_name"`
	FullPath      string    `json:"full_path"` // Alias for FullName
	Description   string    `json:"description"`
	HTMLURL       string    `json:"html_url"`
	WebURL        string    `json:"web_url"` // Alias for HTMLURL
	CloneURL      string    `json:"clone_url"`
	GitCloneURL   string    `json:"git_clone_url"` // Alias for CloneURL
	SSHURL        string    `json:"ssh_url"`
	DefaultBranch string    `json:"default_branch"`
	MainBranch    string    `json:"main_branch"` // Alias for DefaultBranch
	Private       bool      `json:"private"`
	IsPrivate     bool      `json:"is_private"` // Alias for Private
	Archived      bool      `json:"archived"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastUpdatedAt time.Time `json:"last_updated_at"` // Alias for UpdatedAt
}

// Tag represents a Git tag
type Tag struct {
	Name      string    `json:"name"`
	CommitSHA string    `json:"commit_sha"`
	Message   string    `json:"message"`
	Tagger    string    `json:"tagger"`
	CreatedAt time.Time `json:"created_at"`
}

// Commit represents a Git commit
type Commit struct {
	SHA       string    `json:"sha"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
	URL       string    `json:"url"`
}

// Branch represents a Git branch
type Branch struct {
	Name      string `json:"name"`
	CommitSHA string `json:"commit_sha"`
	Protected bool   `json:"protected"`
	Default   bool   `json:"default"`
}

// OAuthToken represents an OAuth 2.0 access token
type OAuthToken struct {
	AccessToken  string     `json:"access_token"`
	Token        string     `json:"token"` // Alias for AccessToken
	RefreshToken string     `json:"refresh_token,omitempty"`
	TokenType    string     `json:"token_type"`
	TokenKind    string     `json:"token_kind"` // Alias for TokenType
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	ValidUntil   *time.Time `json:"valid_until,omitempty"` // Alias for ExpiresAt
	Scopes       []string   `json:"scopes,omitempty"`
	Permissions  []string   `json:"permissions,omitempty"` // Alias for Scopes
}

// IsExpired checks if the token is expired
func (t *OAuthToken) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// WebhookEventType represents the type of webhook event
type WebhookEventType string

const (
	WebhookEventPush    WebhookEventType = "push"
	WebhookEventTag     WebhookEventType = "tag"
	WebhookEventPing    WebhookEventType = "ping"
	WebhookEventUnknown WebhookEventType = "unknown"
)

// WebhookEvent represents a parsed webhook event from SCM provider
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      WebhookEventType       `json:"type"`
	Ref       string                 `json:"ref"`
	CommitSHA string                 `json:"commit_sha"`
	TagName   string                 `json:"tag_name,omitempty"`
	Branch    string                 `json:"branch,omitempty"`
	Repo      *Repository            `json:"repository"`
	Sender    string                 `json:"sender"`
	Payload   map[string]interface{} `json:"payload"`
}

// IsTagEvent returns true if this is a tag-related event
func (e *WebhookEvent) IsTagEvent() bool {
	return e.Type == WebhookEventTag || (e.Type == WebhookEventPush && len(e.TagName) > 0)
}

// ArchiveFormat represents the format for repository archives
type ArchiveFormat string

const (
	ArchiveFormatTarGz ArchiveFormat = "tarball"
	ArchiveFormatZip   ArchiveFormat = "zipball"
)

// SCMProvider represents a configured SCM provider in the database
type SCMProvider struct {
	ID                    uuid.UUID    `json:"id" db:"id"`
	OrganizationID        uuid.UUID    `json:"organization_id" db:"organization_id"`
	ProviderType          ProviderType `json:"provider_type" db:"provider_type"`
	Name                  string       `json:"name" db:"name"`
	BaseURL               *string      `json:"base_url,omitempty" db:"base_url"`
	TenantID              *string      `json:"tenant_id,omitempty" db:"tenant_id"`
	ClientID              string       `json:"client_id" db:"client_id"`
	ClientSecretEncrypted string       `json:"-" db:"client_secret_encrypted"`
	WebhookSecret         string       `json:"-" db:"webhook_secret"`
	IsActive              bool         `json:"is_active" db:"is_active"`
	CreatedAt             time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at" db:"updated_at"`
}

// SCMOAuthToken represents a user's OAuth token for an SCM provider
type SCMOAuthToken struct {
	ID                    uuid.UUID  `json:"id" db:"id"`
	UserID                uuid.UUID  `json:"user_id" db:"user_id"`
	SCMProviderID         uuid.UUID  `json:"scm_provider_id" db:"scm_provider_id"`
	AccessTokenEncrypted  string     `json:"-" db:"access_token_encrypted"`
	RefreshTokenEncrypted *string    `json:"-" db:"refresh_token_encrypted"`
	TokenType             string     `json:"token_type" db:"token_type"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	Scopes                *string    `json:"scopes,omitempty" db:"scopes"`
	CreatedAt             time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at" db:"updated_at"`
}

// ModuleSCMRepo represents a link between a module and an SCM repository
type ModuleSCMRepo struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	ModuleID        uuid.UUID  `json:"module_id" db:"module_id"`
	SCMProviderID   uuid.UUID  `json:"scm_provider_id" db:"scm_provider_id"`
	RepositoryOwner string     `json:"repository_owner" db:"repository_owner"`
	RepositoryName  string     `json:"repository_name" db:"repository_name"`
	RepositoryURL   *string    `json:"repository_url,omitempty" db:"repository_url"`
	DefaultBranch   string     `json:"default_branch" db:"default_branch"`
	ModulePath      string     `json:"module_path" db:"module_path"`
	TagPattern      string     `json:"tag_pattern" db:"tag_pattern"`
	AutoPublish     bool       `json:"auto_publish_enabled" db:"auto_publish"`
	WebhookID       *string    `json:"webhook_id,omitempty" db:"webhook_id"`
	WebhookURL      *string    `json:"webhook_url,omitempty" db:"webhook_url"`
	WebhookEnabled  bool       `json:"webhook_enabled" db:"webhook_enabled"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastSyncCommit  *string    `json:"last_sync_commit,omitempty" db:"last_sync_commit"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// SCMWebhookEvent represents a webhook event received from an SCM provider
type SCMWebhookEvent struct {
	ID                  uuid.UUID              `json:"id" db:"id"`
	ModuleSCMRepoID     uuid.UUID              `json:"module_scm_repo_id" db:"module_scm_repo_id"`
	EventID             *string                `json:"event_id,omitempty" db:"event_id"`
	EventType           WebhookEventType       `json:"event_type" db:"event_type"`
	Ref                 *string                `json:"ref,omitempty" db:"ref"`
	CommitSHA           *string                `json:"commit_sha,omitempty" db:"commit_sha"`
	TagName             *string                `json:"tag_name,omitempty" db:"tag_name"`
	Payload             map[string]interface{} `json:"payload" db:"payload"`
	Headers             map[string]interface{} `json:"headers,omitempty" db:"headers"`
	Signature           *string                `json:"signature,omitempty" db:"signature"`
	SignatureValid      *bool                  `json:"signature_valid,omitempty" db:"signature_valid"`
	Processed           bool                   `json:"processed" db:"processed"`
	ProcessingStartedAt *time.Time             `json:"processing_started_at,omitempty" db:"processing_started_at"`
	ProcessedAt         *time.Time             `json:"processed_at,omitempty" db:"processed_at"`
	ResultVersionID     *uuid.UUID             `json:"result_version_id,omitempty" db:"result_version_id"`
	Error               *string                `json:"error,omitempty" db:"error"`
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
}

// VersionImmutabilityViolation represents a detected tag movement
type VersionImmutabilityViolation struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	ModuleVersionID   uuid.UUID  `json:"module_version_id" db:"module_version_id"`
	TagName           string     `json:"tag_name" db:"tag_name"`
	OriginalCommitSHA string     `json:"original_commit_sha" db:"original_commit_sha"`
	DetectedCommitSHA string     `json:"detected_commit_sha" db:"detected_commit_sha"`
	DetectedAt        time.Time  `json:"detected_at" db:"detected_at"`
	AlertSent         bool       `json:"alert_sent" db:"alert_sent"`
	AlertSentAt       *time.Time `json:"alert_sent_at,omitempty" db:"alert_sent_at"`
	Resolved          bool       `json:"resolved" db:"resolved"`
	ResolvedAt        *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy        *uuid.UUID `json:"resolved_by,omitempty" db:"resolved_by"`
	Notes             *string    `json:"notes,omitempty" db:"notes"`
}

// GitTag represents a Git tag
type GitTag struct {
	TagName       string    `json:"tag_name"`
	TargetCommit  string    `json:"target_commit"`
	AnnotationMsg string    `json:"annotation_msg,omitempty"`
	TaggerName    string    `json:"tagger_name,omitempty"`
	TaggedAt      time.Time `json:"tagged_at,omitempty"`
}

// GitBranch represents a Git branch
type GitBranch struct {
	BranchName   string `json:"branch_name"`
	HeadCommit   string `json:"head_commit"`
	IsProtected  bool   `json:"is_protected"`
	IsMainBranch bool   `json:"is_main_branch"`
}

// GitCommit represents a single commit
type GitCommit struct {
	CommitHash  string    `json:"commit_hash"`
	Subject     string    `json:"subject"`
	AuthorName  string    `json:"author_name"`
	AuthorEmail string    `json:"author_email"`
	CommittedAt time.Time `json:"committed_at"`
	CommitURL   string    `json:"commit_url"`
}

// Type aliases for connector interface compatibility
type ProviderKind = ProviderType
type SourceRepo = Repository
type AccessToken = OAuthToken
type IncomingHook = WebhookEvent

// Database record type aliases for repository compatibility
type SCMProviderRecord = SCMProvider
type SCMUserTokenRecord = SCMOAuthToken
type ModuleSourceRepoRecord = ModuleSCMRepo
type SCMWebhookLogRecord = SCMWebhookEvent
type TagImmutabilityAlertRecord = VersionImmutabilityViolation

// KindGitHub, KindAzureDevOps, KindGitLab, KindBitbucketDC are aliases for consistency
const (
	KindGitHub      = ProviderGitHub
	KindAzureDevOps = ProviderAzureDevOps
	KindGitLab      = ProviderGitLab
	KindBitbucketDC = ProviderBitbucketDC
)

// Note: ArchiveKind type and constants (ArchiveTarball, ArchiveZipball) are defined in connector.go

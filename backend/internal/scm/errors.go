// errors.go defines sentinel error values shared across all SCM provider implementations,
// covering configuration, OAuth, PAT, webhook, and repository operation failures.
package scm

import "errors"

var (
	// Configuration errors
	ErrInvalidProviderType  = errors.New("invalid SCM provider type")
	ErrMissingClientID      = errors.New("missing OAuth client ID")
	ErrMissingClientSecret  = errors.New("missing OAuth client secret")
	ErrMissingRedirectURL   = errors.New("missing OAuth redirect URL")
	ErrProviderNotSupported = errors.New("SCM provider not supported")

	// Aliases for connector.go compatibility
	ErrUnknownProviderKind  = ErrInvalidProviderType
	ErrClientIDRequired     = ErrMissingClientID
	ErrClientSecretRequired = ErrMissingClientSecret
	ErrCallbackURLRequired  = ErrMissingRedirectURL
	ErrConnectorUnavailable = ErrProviderNotSupported

	// PAT errors
	ErrPATRequired  = errors.New("this provider requires a Personal Access Token")
	ErrPATAuthNeeded = ErrPATRequired

	// OAuth errors
	ErrOAuthCodeExchange      = errors.New("failed to exchange OAuth code")
	ErrOAuthTokenRefresh      = errors.New("failed to refresh OAuth token")
	ErrOAuthTokenExpired      = errors.New("OAuth token has expired")
	ErrOAuthTokenInvalid      = errors.New("OAuth token is invalid")
	ErrOAuthScopeInsufficient = errors.New("OAuth token lacks required scopes")

	// OAuth error aliases for connector compatibility
	ErrAuthCodeExchangeFailed = ErrOAuthCodeExchange
	ErrTokenRefreshFailed     = ErrOAuthTokenRefresh
	ErrTokenExpired           = ErrOAuthTokenExpired
	ErrTokenInvalid           = ErrOAuthTokenInvalid
	ErrInsufficientScopes     = ErrOAuthScopeInsufficient

	// Repository errors
	ErrRepositoryNotFound  = errors.New("repository not found")
	ErrRepositoryForbidden = errors.New("access to repository forbidden")
	ErrBranchNotFound      = errors.New("branch not found")
	ErrTagNotFound         = errors.New("tag not found")
	ErrCommitNotFound      = errors.New("commit not found")

	// Repository error aliases for connector compatibility
	ErrRepoNotFound     = ErrRepositoryNotFound
	ErrRepoAccessDenied = ErrRepositoryForbidden

	// Webhook errors
	ErrWebhookNotFound         = errors.New("webhook not found")
	ErrWebhookCreationFailed   = errors.New("failed to create webhook")
	ErrWebhookSignatureInvalid = errors.New("webhook signature is invalid")
	ErrWebhookPayloadInvalid   = errors.New("webhook payload is invalid")

	// Webhook error aliases for connector compatibility
	ErrWebhookSetupFailed      = ErrWebhookCreationFailed
	ErrWebhookSignatureBad     = ErrWebhookSignatureInvalid
	ErrWebhookPayloadMalformed = ErrWebhookPayloadInvalid

	// Archive errors
	ErrArchiveDownloadFailed = errors.New("failed to download repository archive")
	ErrArchiveFormatInvalid  = errors.New("invalid archive format")

	// Archive error aliases
	ErrArchiveFormatUnknown = ErrArchiveFormatInvalid

	// Version immutability errors
	ErrVersionAlreadyExists = errors.New("version already exists with different commit")
	ErrTagMovementDetected  = errors.New("tag movement detected - version immutability violated")
	ErrCommitSHAMismatch    = errors.New("commit SHA does not match existing version")

	// Version error aliases
	ErrVersionCommitConflict = ErrVersionAlreadyExists
	ErrTagMovedFromOriginal  = ErrTagMovementDetected
	ErrCommitMismatch        = ErrCommitSHAMismatch

	// Rate limiting
	ErrRateLimitExceeded = errors.New("API rate limit exceeded")

	// Rate limit aliases
	ErrAPIRateLimited = ErrRateLimitExceeded
)

// APIError represents an error from the SCM provider API
type APIError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *APIError) Unwrap() error {
	return e.Err
}

// NewAPIError creates a new API error
func NewAPIError(statusCode int, message string, err error) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
		Err:        err,
	}
}

// WrapRemoteError is an alias for NewAPIError for connector compatibility
func WrapRemoteError(status int, reason string, err error) *APIError {
	return NewAPIError(status, reason, err)
}

// RemoteAPIError is an alias for APIError for connector compatibility
type RemoteAPIError = APIError

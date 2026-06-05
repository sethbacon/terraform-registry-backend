// Package models - api_key.go aliases the APIKey type from the shared identity
// module. A key is usable while it exists and is not past ExpiresAt; revocation
// is a hard delete (no soft-active flag), expiry warnings via
// ExpiryNotificationSentAt.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

// APIKey represents an API key for authentication.
type APIKey = identitymodels.APIKey

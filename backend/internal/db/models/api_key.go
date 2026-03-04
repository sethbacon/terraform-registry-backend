// Package models defines the database model types for the Terraform Registry.
// Each type corresponds to a database table and uses struct tags for both JSON serialization and sqlx row scanning.
// Models are pure data types — business logic belongs in the service layer, query logic belongs in the repositories layer.
package models

import "time"

// APIKey represents an API key for authentication
type APIKey struct {
	ID                       string
	UserID                   *string // Optional: can be service account key
	OrganizationID           string
	Name                     string     // Friendly name (e.g., "CI/CD Pipeline Key")
	Description              *string    // Optional human-friendly description
	KeyHash                  string     // Bcrypt hash of the full key
	KeyPrefix                string     // First 8-10 chars for display (e.g., "tfr_abc123")
	Scopes                   []string   // JSONB array: ["modules:read", "modules:write", "providers:write"]
	ExpiresAt                *time.Time // Optional expiration
	LastUsedAt               *time.Time // Track last usage
	ExpiryNotificationSentAt *time.Time // Set when expiry warning email was sent
	CreatedAt                time.Time
	// Joined fields (not stored in api_keys table)
	UserName *string // User name who created this key (joined from users table)
}

// Package models - audit_log.go defines the AuditLog model for recording security-relevant
// events, capturing actor, action, affected resource, client IP, and arbitrary metadata.
package models

import "time"

// AuditLog represents an audit log entry for tracking user actions
type AuditLog struct {
	ID             string
	UserID         *string // Nullable for system actions
	OrganizationID *string
	Action         string                 // "module.upload", "provider.delete", "user.create"
	ResourceType   *string                // "module", "provider", "user", "api_key"
	ResourceID     *string                // UUID of affected resource
	Metadata       map[string]interface{} // JSONB: additional context
	IPAddress      *string                // Client IP
	CreatedAt      time.Time

	// Transient fields populated via LEFT JOIN with users table (never stored in audit_logs).
	UserEmail *string `json:"user_email,omitempty"`
	UserName  *string `json:"user_name,omitempty"`
}

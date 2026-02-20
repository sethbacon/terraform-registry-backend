// Package models - audit_log.go defines the AuditLog model for recording security-relevant
// events, capturing actor, action, affected resource, client IP, and arbitrary metadata.
package models

import "time"

// AuditLog represents an audit log entry for tracking user actions
type AuditLog struct {
	ID             string
	UserID         *string                // Nullable for system actions
	OrganizationID *string
	Action         string                 // "module.upload", "provider.delete", "user.create"
	ResourceType   *string                // "module", "provider", "user", "api_key"
	ResourceID     *string                // UUID of affected resource
	Metadata       map[string]interface{} // JSONB: additional context
	IPAddress      *string                // Client IP
	CreatedAt      time.Time
}

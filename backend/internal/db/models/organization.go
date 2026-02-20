// Package models - organization.go defines the Organization model representing a tenant
// namespace in the registry with a URL-safe name and human-readable display name.
package models

import "time"

// Organization represents an organization/namespace in the registry
type Organization struct {
	ID          string
	Name        string // URL-safe name (used in namespaces)
	DisplayName string // Human-readable display name
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

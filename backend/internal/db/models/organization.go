// Package models - organization.go defines the Organization model representing a tenant
// namespace in the registry with a URL-safe name and human-readable display name.
package models

import "time"

// Organization represents an organization/namespace in the registry
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`         // URL-safe name (used in namespaces)
	DisplayName string    `json:"display_name"` // Human-readable display name
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

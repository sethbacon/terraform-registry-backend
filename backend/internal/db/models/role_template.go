// Package models - role_template.go defines the RoleTemplate model for named permission sets
// used in RBAC, along with the predefined system role templates (viewer, publisher, etc.).
package models

import (
	"time"

	"github.com/google/uuid"
)

// RoleTemplate represents a predefined set of scopes for common use cases
type RoleTemplate struct {
	ID          uuid.UUID `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description *string   `db:"description" json:"description,omitempty"`
	Scopes      []string  `db:"scopes" json:"scopes"`
	IsSystem    bool      `db:"is_system" json:"is_system"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// PredefinedRoleTemplates returns the default role templates
func PredefinedRoleTemplates() []RoleTemplate {
	viewerDesc := "Read-only access to modules, providers, mirrors, organizations, and SCM configurations"
	publisherDesc := "Can upload and manage modules and providers"
	devOpsDesc := "Can manage SCM integrations and provider mirroring for CI/CD pipelines"
	adminDesc := "Full access to all registry features"

	return []RoleTemplate{
		{
			Name:        "viewer",
			DisplayName: "Viewer",
			Description: &viewerDesc,
			Scopes:      []string{"modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read"},
			IsSystem:    true,
		},
		{
			Name:        "publisher",
			DisplayName: "Publisher",
			Description: &publisherDesc,
			Scopes:      []string{"modules:read", "modules:write", "providers:read", "providers:write", "scm:read"},
			IsSystem:    true,
		},
		{
			Name:        "devops",
			DisplayName: "DevOps",
			Description: &devOpsDesc,
			Scopes:      []string{"modules:read", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "scm:read", "scm:manage"},
			IsSystem:    true,
		},
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: &adminDesc,
			Scopes:      []string{"admin"},
			IsSystem:    true,
		},
	}
}

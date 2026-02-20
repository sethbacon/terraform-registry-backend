// Package models - organization_member.go defines models for user-to-organization membership,
// including role template assignment and enriched views joining user and role details.
package models

import "time"

// OrganizationMember represents a user's membership in an organization
type OrganizationMember struct {
	OrganizationID string
	UserID         string
	RoleTemplateID *string   // Reference to role_templates table
	CreatedAt      time.Time
}

// OrganizationMemberWithUser includes user details and role template info for display
type OrganizationMemberWithUser struct {
	OrganizationID          string    `json:"organization_id"`
	UserID                  string    `json:"user_id"`
	RoleTemplateID          *string   `json:"role_template_id"`
	RoleTemplateName        *string   `json:"role_template_name"`
	RoleTemplateDisplayName *string   `json:"role_template_display_name"`
	RoleTemplateScopes      []string  `json:"role_template_scopes"`
	CreatedAt               time.Time `json:"created_at"`
	UserName                string    `json:"user_name"`
	UserEmail               string    `json:"user_email"`
}

// UserMembership includes organization details for a user's membership
type UserMembership struct {
	OrganizationID          string    `json:"organization_id"`
	OrganizationName        string    `json:"organization_name"`
	RoleTemplateID          *string   `json:"role_template_id"`
	RoleTemplateName        *string   `json:"role_template_name"`
	RoleTemplateDisplayName *string   `json:"role_template_display_name"`
	RoleTemplateScopes      []string  `json:"role_template_scopes"`
	CreatedAt               time.Time `json:"created_at"`
}

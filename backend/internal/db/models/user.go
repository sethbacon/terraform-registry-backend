// Package models - user.go defines the User model for registry accounts with email,
// display name, and OIDC subject, along with helpers for aggregating per-org role scopes.
package models

import "time"

// User represents a user in the system
type User struct {
	ID        string
	Email     string
	Name      string
	OIDCSub   *string // OIDC subject identifier (unique per provider)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserWithOrgRoles represents a user with their per-organization role template information
type UserWithOrgRoles struct {
	User
	Memberships []UserMembership // Per-organization role templates
}

// GetAllowedScopes returns all unique scopes across all organization memberships
func (u *UserWithOrgRoles) GetAllowedScopes() []string {
	scopeSet := make(map[string]bool)
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			scopeSet[scope] = true
		}
	}
	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	return scopes
}

// HasAdminScope returns true if any organization membership has the admin scope
func (u *UserWithOrgRoles) HasAdminScope() bool {
	for _, m := range u.Memberships {
		for _, scope := range m.RoleTemplateScopes {
			if scope == "admin" {
				return true
			}
		}
	}
	return false
}

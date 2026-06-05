// Package models - user.go aliases the User and UserWithOrgRoles types from the
// shared identity module so the identity data model is owned in one place across
// the suite. Methods (GetAllowedScopes, HasAdminScope) come along with the alias.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

type (
	// User is an identity user account.
	User = identitymodels.User
	// UserWithOrgRoles is a user with their per-organization role templates
	// across all memberships (multi-org); scopes aggregate across memberships.
	UserWithOrgRoles = identitymodels.UserWithOrgRoles
)

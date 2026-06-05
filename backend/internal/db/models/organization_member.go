// Package models - organization_member.go aliases the membership types from the
// shared identity module (membership link plus the enriched display views).
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

type (
	// OrganizationMember is a user's membership in an organization.
	OrganizationMember = identitymodels.OrganizationMember
	// OrganizationMemberWithUser includes user details and role template info for display.
	OrganizationMemberWithUser = identitymodels.OrganizationMemberWithUser
	// UserMembership includes organization details for a user's membership.
	UserMembership = identitymodels.UserMembership
)

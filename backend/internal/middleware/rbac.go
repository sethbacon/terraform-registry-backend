// Package middleware (rbac.go) implements scope-based authorization middleware.
//
// Scopes (e.g., "modules:write", "mirrors:manage") are checked at request time
// rather than being embedded in the JWT. This is a deliberate design choice:
// when a user's role template is updated, the change takes effect immediately
// on their next request without needing to invalidate or reissue their token.
// Embedding scopes in the JWT would require token rotation on every permission
// change, which is operationally expensive and error-prone.

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// RequireScope checks if authenticated user has the required scope
func RequireScope(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get scopes from context (set by AuthMiddleware)
		scopesVal, exists := c.Get("scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			return
		}

		userScopes, ok := scopesVal.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid scopes format",
			})
			return
		}

		if !auth.HasScope(userScopes, scope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Missing required scope",
				"details": "Required scope: " + string(scope),
			})
			return
		}

		c.Next()
	}
}

// RequireAnyScope checks if authenticated user has at least one of the required scopes
func RequireAnyScope(scopes ...auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopesVal, exists := c.Get("scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			return
		}

		userScopes, ok := scopesVal.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid scopes format",
			})
			return
		}

		if !auth.HasAnyScope(userScopes, scopes) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Missing required scope",
			})
			return
		}

		c.Next()
	}
}

// RequireAllScopes checks if authenticated user has all of the required scopes
func RequireAllScopes(scopes ...auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopesVal, exists := c.Get("scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			return
		}

		userScopes, ok := scopesVal.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid scopes format",
			})
			return
		}

		if !auth.HasAllScopes(userScopes, scopes) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Missing one or more required scopes",
			})
			return
		}

		c.Next()
	}
}

// RequireOrgMembership checks if user is a member of the specified organization
func RequireOrgMembership(orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context
		userVal, userExists := c.Get("user_id")
		if !userExists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, ok := userVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get organization from context
		orgVal, orgExists := c.Get("organization_id")
		if !orgExists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Organization context not found",
			})
			return
		}

		orgID, ok := orgVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid organization ID format",
			})
			return
		}

		// Check membership
		member, err := orgRepo.GetMember(c.Request.Context(), orgID, userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check organization membership",
			})
			return
		}

		if member == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Not a member of organization",
			})
			return
		}

		// Store role template ID in context for later use
		c.Set("org_role_template_id", member.RoleTemplateID)

		c.Next()
	}
}

// RequireOrgScope checks if user has the required scope for the organization
// This combines org membership check with scope check based on role template
func RequireOrgScope(scope auth.Scope, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context
		userVal, userExists := c.Get("user_id")
		if !userExists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, ok := userVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get organization from context
		orgVal, orgExists := c.Get("organization_id")
		if !orgExists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Organization context not found",
			})
			return
		}

		orgID, ok := orgVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid organization ID format",
			})
			return
		}

		// Get membership with role template
		memberWithRole, err := orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check organization membership",
			})
			return
		}

		if memberWithRole == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Not a member of organization",
			})
			return
		}

		// Check if user has required scope via role template
		if !auth.HasScope(memberWithRole.RoleTemplateScopes, scope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Missing required scope for organization",
				"details": "Required scope: " + string(scope),
			})
			return
		}

		// Store role template info in context for later use
		c.Set("org_role_template_id", memberWithRole.RoleTemplateID)
		c.Set("org_role_template_scopes", memberWithRole.RoleTemplateScopes)

		c.Next()
	}
}

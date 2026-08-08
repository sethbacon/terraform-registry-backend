// Package middleware (rbac.go) implements scope-based authorization middleware.
//
// Scope resolution (issue #559 finding [9] corrected this comment — it
// previously claimed all scopes were re-checked from the DB on every request):
//
//   - RequireScope / RequireAnyScope / RequireAllScopes read the scopes that
//     AuthMiddleware attached to the context. For JWT sessions those scopes
//     were embedded in the token at login (avoiding a DB query per request);
//     for API keys they are the key's stored scopes.
//   - RequireOrgScopeForPathOrg re-resolves the caller's authority for the
//     organization named in the request path from the database on every
//     request, delegating to authorizeOrgAccessWith so an API key's own
//     organization binding is authoritative for that key.
//
// This comment previously also named RequireOrgMembership and RequireOrgScope.
// Both were deleted (issue #748): no route ever wired them, and they read an
// "organization_id" context key that AuthMiddleware sets ONLY for API-key
// principals -- so wiring either one would have 403'd every browser session.
// They were weaker, broken look-alikes of the guard above, sitting in the same
// file under the same naming convention, which is an invitation to reach for
// the wrong one. Their 11 unit tests went with them: a green test suite over
// code no request reaches proves nothing about the request path.
//
// Because JWT-embedded scopes are only refreshed when a token is issued,
// privilege changes are enforced by token revocation instead: changing a
// member's role template, removing a member from an organization, or editing a
// role template's scopes moves the affected users' revoke-all watermark
// (user_token_revocations), which AuthMiddleware and OptionalAuthMiddleware
// check on every JWT request. The change therefore takes effect immediately —
// the user's outstanding tokens stop validating and a fresh login picks up the
// new scopes.

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

// RequireOrgScopeForPathOrg protects routes shaped /organizations/:id* (and any
// other route where the target organization is the path's :id parameter). It
// independently re-derives the caller's scopes for that SPECIFIC organization
// via orgRepo.GetUserScopesForOrg and requires the given scope there, instead
// of trusting the caller's flat/global combined scope set.
//
// This closes a cross-org authorization gap (GHSA-hc25-j576-cqm2):
// GetUserCombinedScopes unions a user's scopes across every organization they
// belong to into one org-less set, so RequireScope(auth.ScopeOrganizationsWrite)
// alone lets a user who holds that scope in just one organization act on any
// OTHER organization by ID. This middleware must run in addition to (after)
// RequireScope, not instead of it -- RequireScope's coarse check still lets
// callers with no organizations scope at all fail fast without a DB round trip.
//
// A caller holding the global "admin" wildcard scope (auth.ScopeAdmin) is
// exempted from the per-org lookup, matching this codebase's existing
// admin-bypass convention (see role_ceiling.go, namespace_authz.go,
// apikeys.go, dev.go): admin is a deliberate, explicitly-named platform-wide
// scope granted via the system "admin" role template, not something that
// should require the holder to also be a member of every organization they
// administer.
//
// This works against the existing flat/global JWT (no OrgID claim) by
// re-deriving per-org membership from the database on every request, rather
// than the org-scoped-token primitives (HasScopeInOrg / GenerateForOrg) the
// identity library also ships -- adopting those requires migrating the JWT
// itself to carry an OrgID claim, tracked separately.
//
// The decision itself is authorizeOrgAccessWith, shared with the namespace and
// per-resource guards, rather than a fourth hand-rolled membership lookup. The
// copy this replaced re-derived authority from the caller's USER record alone
// and never looked at the presenting credential, so an API key bound to
// organization A could administer organization B whenever its owner happened to
// be a member there -- the organization axis of issue #733, and a divergence
// from the two siblings (authorizeOrgAccess, tenantscope.Resolve) that already
// treat a key's organization binding as authoritative for that key. It reads
// the same table through the same query, so the per-org check is unchanged for
// interactive sessions.
func RequireOrgScopeForPathOrg(scope auth.Scope, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")
		if orgID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Organization ID is required",
			})
			return
		}

		if status, msg := authorizeOrgAccessWith(c, orgRepo, orgID, scope); status != 0 {
			c.AbortWithStatusJSON(status, gin.H{"error": msg})
			return
		}

		c.Next()
	}
}

// RequireOrgMembership checks if user is a member of the specified organization

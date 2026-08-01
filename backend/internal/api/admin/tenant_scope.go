// tenant_scope.go provides the single per-request tenant constraint used by
// every admin LIST and CREATE route over an organization-owned table.
//
// Why this exists as shared infrastructure rather than as another copy of the
// same six lines: issues #718/#719 are not one missing check, they are a CLASS
// — organization-owned resource x access axis (list | by-id | export | create |
// update | delete). The per-resource middleware
// (middleware.RequireOrgScopeForResource) already covers the ":id" axes, because
// it can resolve the row's owning organization from the path. It cannot cover
// the list axis (no row named yet) nor the create axis (the row does not exist
// and the organization arrives in the request body). Those two axes were being
// hand-rolled per handler family — SCMProviderHandlers grew callerIsMemberOf,
// AuditLogHandlers grew callerOrgIDs — and each new family re-opened the hole.
//
// TenantScope is that check, once. Its zero value permits nothing.
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// TenantScope is the set of organizations a request may read or write.
//
// The zero value denies everything, so a handler that fails to resolve a scope
// — or resolves one for a principal with no memberships — returns nothing
// rather than the whole estate.
type TenantScope struct {
	// PlatformAdmin marks a caller holding the platform-wide admin wildcard.
	// That scope deliberately crosses organization boundaries, consistently
	// with middleware.authorizeOrgAccess and the per-resource guards.
	PlatformAdmin bool
	// OrgIDs are the organizations the caller is a verified member of.
	OrgIDs []string
}

// Permits reports whether a row owned by orgID is inside the scope. An empty
// orgID means an unowned (NULL organization_id) row: visible only to a platform
// admin, matching RequireOrgScopeForResource's handling of the same case.
func (s TenantScope) Permits(orgID string) bool {
	if s.PlatformAdmin {
		return true
	}
	if orgID == "" {
		return false
	}
	for _, id := range s.OrgIDs {
		if id == orgID {
			return true
		}
	}
	return false
}

// PermitsPtr is Permits for the nullable organization_id columns that most of
// these tables actually use.
func (s TenantScope) PermitsPtr(orgID *string) bool {
	if orgID == nil {
		return s.Permits("")
	}
	return s.Permits(*orgID)
}

// Empty reports whether the scope can select nothing at all.
func (s TenantScope) Empty() bool { return !s.PlatformAdmin && len(s.OrgIDs) == 0 }

// callerTenantScope resolves the caller's tenant scope from the request
// context. It fails closed: a missing principal yields an empty scope, and a
// membership lookup failure is reported so the handler can 500 rather than
// silently widening to every organization.
//
// GUARD tenant-scope-resolver (issues #718/#719).
func callerTenantScope(c *gin.Context, orgRepo *repositories.OrganizationRepository) (TenantScope, error) {
	scope := TenantScope{}

	if scopesVal, exists := c.Get("scopes"); exists {
		if callerScopes, ok := scopesVal.([]string); ok {
			scope.PlatformAdmin = auth.HasScope(callerScopes, auth.ScopeAdmin)
		}
	}
	if scope.PlatformAdmin {
		return scope, nil
	}

	userVal, exists := c.Get("user_id")
	if !exists {
		return scope, nil
	}
	userID, ok := userVal.(string)
	if !ok || userID == "" {
		return scope, nil
	}
	if orgRepo == nil {
		// A handler wired without an organization repository cannot verify
		// membership. Denying is the only safe answer; returning the unfiltered
		// result would be the very defect this file exists to close.
		return scope, nil
	}

	memberships, err := orgRepo.GetUserMemberships(c.Request.Context(), userID)
	if err != nil {
		return TenantScope{}, err
	}
	for _, m := range memberships {
		scope.OrgIDs = append(scope.OrgIDs, m.OrganizationID)
	}
	return scope, nil
}

// resolveTenantScope is the handler-side entry point: it resolves the scope and,
// on a lookup failure, writes the 500 and reports ok=false so the caller can
// simply return.
func resolveTenantScope(c *gin.Context, orgRepo *repositories.OrganizationRepository) (TenantScope, bool) {
	scope, err := callerTenantScope(c, orgRepo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve organization memberships"})
		return TenantScope{}, false
	}
	return scope, true
}

// requireTenantScopeForOrg authorizes a WRITE that names its target
// organization in the request body — the create axis, and any update that
// re-parents a row into a different organization. The per-resource route guard
// cannot do this: it binds the row's CURRENT owner, and says nothing about the
// owner the caller is asking for.
//
// An empty requested organization means "leave it to the server default" and is
// allowed through; the handler is responsible for choosing that default.
//
// GUARD tenant-scope-target-org (issue #719).
func requireTenantScopeForOrg(c *gin.Context, orgRepo *repositories.OrganizationRepository, requestedOrgID string) bool {
	if requestedOrgID == "" {
		return true
	}
	scope, ok := resolveTenantScope(c, orgRepo)
	if !ok {
		return false
	}
	if !scope.Permits(requestedOrgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
		return false
	}
	return true
}

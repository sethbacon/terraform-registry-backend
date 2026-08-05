// Package tenantscope resolves, once, the set of organizations a request is
// allowed to read or write — the check that every LIST, CREATE and bulk-DELETE
// route over an organization-owned table needs and that no per-resource route
// guard can supply.
//
// Why this exists as shared infrastructure rather than as another copy of the
// same six lines: issues #718/#719 are not one missing check, they are a CLASS
// — organization-owned resource x access axis (list | by-id | export | create |
// update | delete). The per-resource middleware
// (middleware.RequireOrgScopeForResource) already covers the ":id" axes,
// because it can resolve the row's owning organization from the path. It cannot
// cover the list axis (no row named yet), the create axis (the row does not
// exist and the organization arrives in the request body), or a delete that
// sweeps rows across every organization at once (SCIM deprovisioning). Those
// axes were being hand-rolled per handler family — SCMProviderHandlers grew
// callerIsMemberOf, AuditLogHandlers grew callerOrgIDs — and each new family
// re-opened the hole.
//
// It lives in its own package, not in internal/api/admin, because the class
// spans packages: internal/api/admin and internal/api/scim both have instances,
// and a resolver only one of them can import is a resolver the other will
// re-implement slightly differently. That divergence is the defect.
//
// AUTHORITY MODEL. Resolve is deliberately the same decision, in the same
// order, as middleware.authorizeOrgAccess:
//
//  1. the wildcard admin scope crosses organization boundaries;
//  2. an API key bound to an organization is authoritative for that key,
//     regardless of the owning user's other memberships;
//  3. otherwise the caller's memberships decide — and only those memberships
//     whose ROLE TEMPLATE grants the scope the route requires.
//
// Step 3 is the part that used to be missing. Resolving on bare membership
// authorized the list/create axes more weakly than the /:id axes of the same
// families, which require the scope in the target organization: a viewer in
// org A could enumerate what an operator in org A may manage. The session JWT
// carries a FLAT, org-less union of scopes across every organization (#652), so
// the caller's token cannot answer "where do you hold mirrors:manage" — only
// the membership rows can, and they are already loaded here.
//
// The zero value permits nothing.
package tenantscope

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// OwnerOrgContextKey is where middleware publishes the organization it resolved
// AND authorized the request against — the namespace's owner on the publish
// guards, the addressed row's owner on the per-resource guards.
const OwnerOrgContextKey = "owner_org_id"

// OwnerOrg returns the organization a route guard has already resolved and
// authorized this request against, or "" when no guard published one.
//
// It belongs next to Resolve because it answers the same question from the
// other end. Resolve derives the organizations a CALLER may write to; OwnerOrg
// reports the single organization a guard has already decided this REQUEST is
// about. Where a guard has decided, that decision is the answer — re-deriving
// it from the caller's memberships can only disagree with it, and issue #778 is
// what disagreement costs: the guard authorized the namespace's owning
// organization while the handler wrote the row into the default organization,
// so the create axis authorized one tenant and wrote to another.
//
// Handlers must treat "" as "nobody has decided", not as "no tenant".
func OwnerOrg(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.GetString(OwnerOrgContextKey))
}

// Scope is the set of organizations a request may read or write.
//
// The zero value denies everything, so a handler that fails to resolve a scope
// — or resolves one for a principal with no qualifying memberships — returns
// nothing rather than the whole estate.
type Scope struct {
	// PlatformAdmin marks a caller holding the platform-wide admin wildcard.
	// That scope deliberately crosses organization boundaries, consistently
	// with middleware.authorizeOrgAccess and the per-resource guards.
	PlatformAdmin bool
	// OrgIDs are the organizations in which the caller was verified to hold the
	// scope the route required — not merely the organizations they belong to.
	OrgIDs []string
}

// Permits reports whether a row owned by orgID is inside the scope.
//
// UNOWNED ROWS. An empty orgID means a row whose organization_id is NULL, and
// it is permitted only for a platform admin. This is the single contract for
// unowned rows across the whole codebase — it is what
// middleware.RequireOrgScopeForResource does for the ":id" axes ("Resource is
// not owned by any organization"), so the list, create and delete axes must not
// answer differently for the same row. A NULL owner on these tables means "no
// tenant has been asserted", not "belongs to everyone": terraform-registry
// resolves a mirror configuration's NULL organization back to the DEFAULT
// organization at sync time (jobs/mirror_sync.go), so treating NULL as public
// would leak exactly the rows the default organization owns.
func (s Scope) Permits(orgID string) bool {
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
func (s Scope) PermitsPtr(orgID *string) bool {
	if orgID == nil {
		return s.Permits("")
	}
	return s.Permits(*orgID)
}

// Empty reports whether the scope can select nothing at all.
func (s Scope) Empty() bool { return !s.PlatformAdmin && len(s.OrgIDs) == 0 }

// Resolve resolves the caller's tenant scope for the scope a route requires.
// It fails closed: a missing or malformed principal yields an empty scope, and
// a membership lookup failure is reported as an error so the handler can 500
// rather than silently widening to every organization.
//
// GUARD tenant-scope-resolver (issues #718/#719).
func Resolve(c *gin.Context, orgRepo *repositories.OrganizationRepository, required auth.Scope) (Scope, error) {
	scope := Scope{}

	if scopesVal, exists := c.Get("scopes"); exists {
		if callerScopes, ok := scopesVal.([]string); ok {
			scope.PlatformAdmin = auth.HasScope(callerScopes, auth.ScopeAdmin)
		}
	}
	if scope.PlatformAdmin {
		return scope, nil
	}

	// GUARD tenant-scope-api-key-principal (issue #719).
	//
	// An API key is bound to exactly one organization at creation time and that
	// binding is authoritative for the key — identically to
	// middleware.authorizeOrgAccess, which the ":id" axes of these same
	// families already go through. Omitting this branch was not merely
	// inconsistent, it was broken in both directions: a USERLESS organization
	// service key (api_keys.user_id IS NULL, the normal shape for CI
	// automation) has no memberships to look up, so it silently received empty
	// lists and 403s on its OWN organization, while a key issued to a user who
	// happens to belong to other organizations would have been scoped to all of
	// them rather than to the one the key names.
	//
	// The key's own scopes were already checked by middleware.RequireScope on
	// the route; an org-bound key is not additionally required to hold the
	// scope via a role template, matching authorizeOrgAccess exactly. That
	// alignment is deliberate: two implementations of one check is the defect
	// tracked in #665.
	if keyVal, exists := c.Get("api_key"); exists {
		apiKey, ok := keyVal.(*models.APIKey)
		if !ok {
			// A principal we cannot interpret is a principal we cannot
			// authorize. Deny rather than fall through to the user branch.
			return Scope{}, nil
		}
		if apiKey.OrganizationID != "" {
			scope.OrgIDs = []string{apiKey.OrganizationID}
			return scope, nil
		}
		// Keys without an organization binding (legacy rows) fall through to
		// the owning user's membership check below, as authorizeOrgAccess does.
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
		// result would be the very defect this package exists to close.
		return scope, nil
	}

	memberships, err := orgRepo.GetUserMemberships(c.Request.Context(), userID)
	if err != nil {
		return Scope{}, err
	}
	for _, m := range memberships {
		// GUARD tenant-scope-role-template (issue #719): membership alone is
		// not authority. RoleTemplateScopes is what authorizeOrgAccess checks
		// for the ":id" axes of these same resources, and GetUserMemberships
		// already returns it, so resolving on bare membership here made the
		// list/create axes strictly weaker than their own siblings.
		if auth.HasScope(m.RoleTemplateScopes, required) {
			scope.OrgIDs = append(scope.OrgIDs, m.OrganizationID)
		}
	}
	return scope, nil
}

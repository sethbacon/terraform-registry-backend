// tenant_scope.go is this package's handler-side entry point to the shared
// tenant constraint in internal/tenantscope. The resolver itself lives there
// because the class spans packages (internal/api/scim has instances too); what
// stays here is the HTTP shape — write the 500, write the 403, tell the handler
// to return.
//
// See internal/tenantscope for the authority model, the unowned-row contract
// and why the check is a required parameter rather than an optional filter.
package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	idtenantscope "github.com/sethbacon/terraform-suite-identity/identity/tenantscope"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
)

// TenantScope is the set of organizations a request may read or write. Alias
// rather than a second type: one definition, one Permits, one unowned-row
// contract.
type TenantScope = tenantscope.Scope

// callerTenantScope resolves the caller's tenant scope for the scope this route
// requires. Thin pass-through to tenantscope.Resolve, kept so the call sites in
// this package read the same as they did.
func callerTenantScope(c *gin.Context, orgRepo *repositories.OrganizationRepository, required auth.Scope) (TenantScope, error) {
	return tenantscope.Resolve(c, orgRepo, required)
}

// resolveTenantScope is the handler-side entry point: it resolves the scope
// and, on a lookup failure, writes the 500 and reports ok=false so the caller
// can simply return.
func resolveTenantScope(c *gin.Context, orgRepo *repositories.OrganizationRepository, required auth.Scope) (TenantScope, bool) {
	scope, err := callerTenantScope(c, orgRepo, required)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve organization memberships"})
		return TenantScope{}, false
	}
	return scope, true
}

// resolveTargetOrganization decides which organization a CREATE — or an UPDATE
// that re-parents a row — is allowed to write to, and is the only sanctioned
// way for a handler in this package to answer that question.
//
// requestedOrgID is what the caller put in the request body, which is one of
// three things, and the previous guard only handled the first:
//
//	a foreign UUID  -> must be an organization the caller actually holds the
//	                   scope in. Checked before and still checked.
//	OMITTED ("")    -> used to fall straight through to GetDefaultOrganization
//	                   with NO membership check, so a non-member of the default
//	                   organization planted rows in it simply by leaving the
//	                   field out. The old guard documented that allow-through as
//	                   intentional; it was the hole, not a simplification.
//	EMPTY STRING    -> on the update axis, nulled organization_id. NULL is not
//	                   "no tenant": jobs/mirror_sync.go resolves a mirror
//	                   configuration's NULL organization back to the DEFAULT
//	                   organization, so an empty string re-parented the row into
//	                   the default org — the exact defect the re-parent guard was
//	                   added to close, reachable by sending "" instead of the
//	                   default org's UUID.
//
// The omitted case is resolved from the CALLER's own tenancy, never from a
// server-side default the caller may not belong to. The rule is the shared
// module's (tenantscope.ActingOrganization, issue #1011): the X-Organization-Id
// header the suite's organization picker sends is consulted next, then a single
// in-scope organization is used automatically, and anything ambiguous is
// refused — a platform admin included. The historical fallback that handed a
// platform admin the DEFAULT organization is gone: it was the one remaining
// place a row could land in a tenant nobody named, and it made this path
// disagree with the state manager's answer to the same question.
//
// A platform admin's scope is "all organizations", so the module cannot check
// that the organization they named EXISTS; this function does, and answers a
// miss with the same 403 a non-member gets, so it discloses nothing.
//
// Returns (orgID, true) on success — orgID is never empty. On failure the
// response has already been written.
//
// GUARD tenant-scope-target-org (issue #719).
func resolveTargetOrganization(
	c *gin.Context,
	orgRepo *repositories.OrganizationRepository,
	required auth.Scope,
	requestedOrgID string,
) (string, bool) {
	scope, ok := resolveTenantScope(c, orgRepo, required)
	if !ok {
		return "", false
	}

	orgID, err := tenantscope.ActingOrganization(c, scope, requestedOrgID)
	switch {
	case err == nil:
	case errors.Is(err, idtenantscope.ErrActingOrganizationNotPermitted):
		c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
		return "", false
	case errors.Is(err, idtenantscope.ErrNoActingOrganization):
		c.JSON(http.StatusForbidden, gin.H{
			"error": "No organization context: you do not hold the required scope in any organization",
		})
		return "", false
	case errors.Is(err, idtenantscope.ErrAmbiguousActingOrganization):
		// Fail closed rather than guess. Guessing is how the default
		// organization became a dumping ground for other tenants' rows.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Ambiguous organization: specify organization_id or send the " +
				idtenantscope.ActingOrganizationHeader +
				" header — you hold the required scope in more than one organization",
		})
		return "", false
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve acting organization"})
		return "", false
	}

	if scope.PlatformAdmin {
		// The module verified nothing for a platform admin (every organization
		// is in scope); the one thing left to verify is that the named
		// organization exists. Answer a miss exactly as a non-member is
		// answered, so the response cannot be used to probe organization ids.
		if orgRepo == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve acting organization"})
			return "", false
		}
		org, err := orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
			return "", false
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve acting organization"})
			return "", false
		}
	}
	return orgID, true
}

// resolveNamespaceCreateOrganization decides which organization a NAMESPACED
// create writes into — a provider record, a module record — on the routes that
// sit behind middleware.NamespaceAuthorizer's publish guards.
//
// Those guards already answer the question, and answer it better than the
// handler can re-derive it: the guard resolves the namespace's owning
// organization (the existing owner, or the organization it just claimed an
// unowned namespace for), authorizes the caller against THAT organization, and
// publishes it as owner_org_id. The handlers ignored it. They took the
// organization from the request body or, when the body named none, from
// GetDefaultOrganization — so the organization the route authorized and the
// organization the row landed in were two independent values. A caller holding
// the scope in organization O therefore created a row owned by the DEFAULT
// organization, in which they need no membership at all, and the existence
// check ahead of the insert queried that same wrong organization, so a genuine
// collision in O went unseen and the write ran into the
// UNIQUE (organization_id, namespace, ...) constraint instead of a clean 409.
//
// INVARIANT: an organization-owned row is created in the organization the
// request was authorized against, and in no other.
//
// So the authorized owner wins, and resolveTargetOrganization is the FALLBACK
// rather than the primary. On this axis it is the weaker answer, because it
// resolves from the CALLER's memberships instead of from the namespace: a
// caller holding the scope in two organizations would be refused as "ambiguous"
// for a namespace whose owner is not ambiguous at all. It is still the right
// fallback for the one path where the guard legitimately publishes no owner (a
// platform admin passing through the ambiguous-ownership branch), because it
// fails closed for every principal — the admin must name the organization, in
// the body or through the picker's header — instead of reaching for the
// default organization.
//
// A body that names an organization other than the authorized owner is REFUSED
// rather than silently overridden. The middleware already refuses that for
// non-admin callers on the owned-namespace path; refusing it here as well means
// the row can never be attributed to an organization the guard did not check,
// whichever principal asked, and no caller is answered 201 for a write that
// quietly discarded the field they sent.
//
// GUARD namespace-create-owner-org (issue #778).
func resolveNamespaceCreateOrganization(
	c *gin.Context,
	orgRepo *repositories.OrganizationRepository,
	required auth.Scope,
	requestedOrgID string,
) (string, bool) {
	requestedOrgID = strings.TrimSpace(requestedOrgID)

	if ownerOrgID := tenantscope.OwnerOrg(c); ownerOrgID != "" {
		if requestedOrgID != "" && requestedOrgID != ownerOrgID {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "organization_id does not match the namespace's owning organization",
			})
			return "", false
		}
		return ownerOrgID, true
	}

	return resolveTargetOrganization(c, orgRepo, required, requestedOrgID)
}

// requireTenantScopeForOrg authorizes a write against an explicitly named
// target organization. Unlike resolveTargetOrganization it has no opinion about
// the omitted case, so it is only for call sites that have already established
// a non-empty target.
//
// GUARD tenant-scope-target-org (issue #719).
func requireTenantScopeForOrg(
	c *gin.Context,
	orgRepo *repositories.OrganizationRepository,
	required auth.Scope,
	requestedOrgID string,
) bool {
	if requestedOrgID == "" {
		// Never silently allowed: a caller reaching this helper with no target
		// has skipped the decision resolveTargetOrganization exists to make.
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization_id is required"})
		return false
	}
	_, ok := resolveTargetOrganization(c, orgRepo, required, requestedOrgID)
	return ok
}

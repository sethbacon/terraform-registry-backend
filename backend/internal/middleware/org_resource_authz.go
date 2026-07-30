package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// ResourceOrgResolver loads the organization that owns the resource addressed
// by a path parameter. It returns (orgID, true, nil) when the resource exists,
// ("", false, nil) when it does not, and a non-nil error only for genuine
// lookup failures.
//
// An existing resource whose organization_id is NULL/empty must return
// ("", true, nil): "found, but unowned". See RequireOrgScopeForResource for how
// that case is handled.
type ResourceOrgResolver func(ctx context.Context, id string) (orgID string, found bool, err error)

// RequireOrgScopeForResource authorizes the caller against the organization
// that owns the resource named by the ":id" path parameter.
//
// This is the resource-keyed counterpart to RequireOrgScopeForPathOrg: that
// middleware works where ":id" *is* an organization ID, while many route
// families address an org-scoped row (an SCM provider, a mirror configuration,
// an approval request) whose owning organization must first be looked up. Both
// exist because the session JWT carries a flat, org-less union of the caller's
// scopes across every organization they belong to (issue #652), so
// RequireScope alone cannot tell "holds scm:manage in org A" apart from
// "may act on org B's provider" — the cross-tenant gap tracked in #718/#719.
//
// It must run in addition to (after) RequireScope, not instead of it, so
// callers lacking the scope entirely still fail fast without a DB round trip.
//
// Authorization itself is delegated to the same authorizeOrgAccess used by the
// namespace/module/provider guards, so admin-wildcard bypass, org-bound API
// key precedence, and per-org role-template scope derivation behave
// identically everywhere. Deliberately not a second implementation: issue #665
// was filed for exactly that kind of divergence between two copies of one
// check.
//
// Two cases deliberately pass through to the handler rather than being
// rejected here:
//   - a malformed (non-UUID) ":id", and
//   - a resource that does not exist,
//
// both so the handler produces its usual 400/404 rather than this middleware
// inventing one — matching moduleAccessByID's existing behaviour. Note this
// means a caller can still distinguish "no such resource" from "exists but
// belongs to another organization"; that is the pre-existing convention in
// this codebase, and closing it would be a separate, product-wide decision.
//
// An existing-but-unowned resource (NULL organization_id — the column is
// nullable on several of these tables) fails closed for everyone except the
// admin wildcard: an empty owner cannot be matched against any membership, so
// only a platform admin may act on such legacy rows.
func (a *NamespaceAuthorizer) RequireOrgScopeForResource(scope auth.Scope, resolve ResourceOrgResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if _, err := uuid.Parse(id); err != nil {
			// Malformed ID: the handler responds.
			c.Next()
			return
		}

		ownerOrgID, found, err := resolve(c.Request.Context(), id)
		if err != nil {
			abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to resolve resource ownership")
			return
		}
		if !found {
			// Missing resource: the handler responds (404).
			c.Next()
			return
		}

		if ownerOrgID == "" {
			// Unowned row (nullable organization_id). Handled explicitly rather
			// than by falling through to the membership lookup: querying
			// membership for an empty organization is meaningless, and leaving
			// the outcome to depend on how the driver answers that query is not
			// a decision worth delegating. Admin only.
			if scopesVal, exists := c.Get("scopes"); exists {
				if callerScopes, ok := scopesVal.([]string); ok && auth.HasScope(callerScopes, auth.ScopeAdmin) {
					c.Set("owner_org_id", "")
					c.Next()
					return
				}
			}
			abortNamespaceAuthz(c, http.StatusForbidden, "Resource is not owned by any organization")
			return
		}

		if status, msg := a.authorizeOrgAccess(c, ownerOrgID, scope); status != 0 {
			abortNamespaceAuthz(c, status, msg)
			return
		}

		// Expose the resolved owner so handlers never re-derive it.
		c.Set("owner_org_id", ownerOrgID)
		c.Next()
	}
}

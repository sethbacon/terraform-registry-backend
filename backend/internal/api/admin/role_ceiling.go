package admin

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/credscope"
)

type roleAssignmentCheck struct {
	allowed bool
	status  int
	// message is what the handler returns to the caller. Empty means the
	// generic refusal; the admin-bearing refusal below sets it, because "role
	// assignment not permitted" would send an operator looking for a role they
	// lack rather than at the route that now grants this.
	message string
}

// adminBearingRefusal is the answer to a request to make an admin-bearing role
// template somebody's organization membership role. It names the replacement
// route, because there IS one now — which is the entire reason this refusal
// became shippable.
const adminBearingRefusal = "the platform-admin role cannot be assigned as an organization membership role; " +
	"grant platform administration through POST /api/v1/admin/platform-admins"

func (h *OrganizationHandlers) checkRoleAssignment(c *gin.Context, roleTemplateID *string) roleAssignmentCheck {
	if roleTemplateID == nil || *roleTemplateID == "" {
		return roleAssignmentCheck{allowed: true}
	}

	id, err := uuid.Parse(*roleTemplateID)
	if err != nil {
		return roleAssignmentCheck{allowed: false, status: http.StatusBadRequest}
	}

	// REGISTRY's own table (terraform-suite-identity#206, phase 3b). This asks
	// "what will this template confer once it is assigned", and since the read
	// cutover the answer is `registry_role_templates`. Reading the shared table
	// would compute the ceiling — and the platform-admin refusal below — from a
	// scope set the product does not actually enforce, so a template registry
	// treats as admin-bearing could be waved through on the strength of what
	// identity says it carries.
	var scopesJSON []byte
	err = h.db.QueryRowContext(c.Request.Context(),
		`SELECT scopes FROM registry_role_templates WHERE id = $1`, id).Scan(&scopesJSON)
	if err == sql.ErrNoRows {
		return roleAssignmentCheck{allowed: false, status: http.StatusBadRequest}
	}
	if err != nil {
		return roleAssignmentCheck{allowed: false, status: http.StatusInternalServerError}
	}

	var roleScopes []string
	if err := json.Unmarshal(scopesJSON, &roleScopes); err != nil {
		return roleAssignmentCheck{allowed: false, status: http.StatusInternalServerError}
	}

	// GUARD platform-admin-carrier (issue #766). NO membership may carry the
	// platform-wide wildcard, whoever is asking.
	//
	// This is #766's headline recommendation, and PR #850 was right to decline
	// it then: `organization_members.role_template_id` was the only carrier for
	// scopes, so refusing it here would have left a deployment unable to have a
	// platform administrator at all. `platform_admins` is that carrier now
	// (migration 000051), the management API grants through it (PR #862), and
	// migration 000054 has taken `admin` off the templates — so the refusal
	// costs nobody anything and closes the route by which an org-scoped grant
	// silently conferred cross-tenant reach.
	//
	// AHEAD OF THE CEILING, not folded into it. RoleScopesPermittedBy answers
	// TRUE for a caller who already holds `admin`, so a platform administrator
	// would sail past it — and a platform administrator granting the template
	// to a colleague is exactly how the state PR #850 tolerated used to arise.
	// The point of this release is that it can no longer arise at all.
	if err := auth.ValidateProvisionableScopes(roleScopes); err != nil {
		return roleAssignmentCheck{allowed: false, status: http.StatusForbidden, message: adminBearingRefusal}
	}

	// Vacuous case: skip deriving caller scopes entirely. This matches
	// auth.RoleScopesPermittedBy's own short-circuit and avoids an
	// unnecessary per-org DB round trip when there's nothing to permit.
	if len(roleScopes) == 0 {
		return roleAssignmentCheck{allowed: true}
	}

	globalScopesVal, _ := c.Get("scopes")
	globalScopes, _ := globalScopesVal.([]string)

	// A global admin can assign any role without a per-org lookup. Otherwise,
	// the caller's assignment ceiling must be derived from their scopes
	// WITHIN the target organization (c.Param("id")), not their global union
	// scopes across every org they belong to -- using the union here would let
	// a user who holds organizations:write via membership in ONE organization
	// assign roles in an entirely different organization they have no
	// relationship with (the same class of cross-org escalation as
	// GHSA-hc25-j576-cqm2, mirrored here via RequireOrgScopeForPathOrg).
	callerScopes := globalScopes
	if !auth.HasScope(globalScopes, auth.ScopeAdmin) {
		userIDVal, _ := c.Get("user_id")
		callerUserID, _ := userIDVal.(string)
		orgScopes, err := h.orgRepo.GetUserScopesForOrg(c.Request.Context(), callerUserID, c.Param("id"))
		if err != nil {
			return roleAssignmentCheck{allowed: false, status: http.StatusInternalServerError}
		}
		callerScopes = orgScopes
	}

	// GUARD credential-scope-binding (issue #733). The per-org branch above
	// reads the caller's USER record, so on an API-key request it hands back an
	// authority the presenting credential may not hold: a key scoped to
	// organizations:write, owned by an org owner, could assign that owner's
	// admin role template to any member — minting through role assignment the
	// same escalation #733 closed on key creation. Intersecting with the
	// credential's own scopes leaves the admin branch and every interactive
	// session untouched (Bound is identity for both).
	callerScopes = credscope.Bound(c, callerScopes)

	if !auth.RoleScopesPermittedBy(callerScopes, roleScopes) {
		return roleAssignmentCheck{allowed: false, status: http.StatusForbidden}
	}
	return roleAssignmentCheck{allowed: true}
}

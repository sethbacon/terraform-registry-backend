package admin

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/auth"
)

type roleAssignmentCheck struct {
	allowed bool
	status  int
}

func (h *OrganizationHandlers) checkRoleAssignment(c *gin.Context, roleTemplateID *string) roleAssignmentCheck {
	if roleTemplateID == nil || *roleTemplateID == "" {
		return roleAssignmentCheck{allowed: true}
	}

	id, err := uuid.Parse(*roleTemplateID)
	if err != nil {
		return roleAssignmentCheck{allowed: false, status: http.StatusBadRequest}
	}

	var scopesJSON []byte
	err = h.db.QueryRowContext(c.Request.Context(),
		`SELECT scopes FROM role_templates WHERE id = $1`, id).Scan(&scopesJSON)
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

	if !auth.RoleScopesPermittedBy(callerScopes, roleScopes) {
		return roleAssignmentCheck{allowed: false, status: http.StatusForbidden}
	}
	return roleAssignmentCheck{allowed: true}
}

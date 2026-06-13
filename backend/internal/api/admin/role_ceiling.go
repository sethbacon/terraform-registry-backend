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

func roleScopesPermittedBy(callerScopes, roleScopes []string) bool {
	if len(roleScopes) == 0 {
		return true
	}
	if auth.HasScope(callerScopes, auth.ScopeAdmin) {
		return true
	}
	for _, s := range roleScopes {
		if s == string(auth.ScopeAdmin) {
			return false
		}
		if !auth.HasScope(callerScopes, auth.Scope(s)) {
			return false
		}
	}
	return true
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

	scopesVal, _ := c.Get("scopes")
	callerScopes, _ := scopesVal.([]string)

	if !roleScopesPermittedBy(callerScopes, roleScopes) {
		return roleAssignmentCheck{allowed: false, status: http.StatusForbidden}
	}
	return roleAssignmentCheck{allowed: true}
}

// group_mapping_guard.go guards reconcileGroupMemberships against an
// IdP-driven group mapping resolving to a role_template that carries
// auth.ScopeAdmin, the grant-all wildcard scope.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// guardProvisionableRole rejects a group mapping's resolved role_template when
// its scopes carry auth.ScopeAdmin ("admin"), and returns those scopes on
// acceptance. Call this in reconcileGroupMemberships immediately before
// trusting a mapped Role for an automatic, IdP-driven membership write
// (UpdateMemberRole / AddMemberWithParams) — never on a role read back for an
// already-trusted, direct admin action (e.g. the manual "make this user an
// admin" endpoints in organizations.go/setup/handlers.go, which intentionally
// grant "admin" and must not be affected by this guard).
//
// The returned scopes are exactly what the member will hold in the organization
// once the write commits, which makes them the retention filter for the
// credential sweep on the reassignment branch (see credlifecycle.Sweeper). They
// are returned rather than re-read so the reassignment costs one role_templates
// lookup, not two.
//
// This is defense-in-depth, not a fix for an active exploit: the group-mapping
// CONFIG that names a Role is itself only reachable by a caller who already
// holds ScopeAdmin (see internal/api/router.go's oidcAdminGroup gate), so an
// unprivileged actor cannot plant Role: "admin" in a mapping today. But nothing
// in reconcileGroupMemberships itself refuses to auto-apply a role_template
// carrying ScopeAdmin once a mapping names one — this guards against that
// changing in the future (e.g. a lower-privileged, org-scoped mapping-writer
// API), per terraform-suite-identity's ValidateProvisionableScopes doc and
// this repo's issue #604.
//
// A role_template name that does not resolve to a row returns (nil, nil): the
// caller's own UpdateMemberRole/AddMemberWithParams performs the authoritative
// name lookup immediately afterward and surfaces a clear "role template not
// found" error there, so this guard does not need to duplicate that failure
// mode — and the caller therefore never reaches the sweep with the empty scope
// set this returns. Any other lookup/parse failure is returned (fails closed)
// — a transient DB error here should not silently let an unverified role's
// scopes through.
func (h *AuthHandlers) guardProvisionableRole(ctx context.Context, roleTemplateName string) ([]string, error) {
	var scopesJSON []byte
	err := h.db.QueryRowContext(ctx,
		`SELECT scopes FROM role_templates WHERE name = $1`, roleTemplateName).Scan(&scopesJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up role template %q scopes: %w", roleTemplateName, err)
	}
	var scopes []string
	if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
		return nil, fmt.Errorf("parse role template %q scopes: %w", roleTemplateName, err)
	}
	if err := auth.ValidateProvisionableScopes(scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

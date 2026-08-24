package admin

import (
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// buildMeResponse assembles the /auth/me body.
//
// # Why this is a function and not inline in the handler
//
// MeHandler used to build an ad-hoc gin.H while its swagger annotation claimed
// `admin.MeResponse`. Neither MeResponse nor MeMembershipEntry was constructed
// anywhere -- the only reference to either was the annotation itself -- so the
// two drifted, and the published contract described a flat
// `role_template_name` that no client has ever received (#892).
//
// Pulling the assembly out here makes the struct load-bearing: the handler now
// returns a MeResponse, so the compiler keeps the emitted shape and the
// documented shape in step. It also makes the shape testable without a database,
// which is what actually pins the wire format.
func buildMeResponse(
	user *models.User,
	memberships []models.UserMembership,
	allowedScopes []string,
	sessionExpiresAt *time.Time,
) MeResponse {
	resp := MeResponse{
		User: MeUserInfo{
			ID:        user.ID,
			Email:     user.Email,
			Name:      user.Name,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
		// Non-nil so an empty membership list marshals as [] rather than null.
		Memberships:      make([]MeMembershipEntry, 0, len(memberships)),
		AllowedScopes:    allowedScopes,
		SessionExpiresAt: sessionExpiresAt,
	}

	for i := range memberships {
		m := memberships[i]
		entry := MeMembershipEntry{
			OrganizationID:   m.OrganizationID,
			OrganizationName: m.OrganizationName,
			CreatedAt:        m.CreatedAt,
		}
		// Keyed on RoleTemplateID, matching the handler: a membership whose
		// template id is nil emits `"role_template": null` even if some other
		// template field happened to be set.
		if m.RoleTemplateID != nil {
			entry.RoleTemplate = &MeRoleTemplate{
				ID:          m.RoleTemplateID,
				Name:        m.RoleTemplateName,
				DisplayName: m.RoleTemplateDisplayName,
				Scopes:      m.RoleTemplateScopes,
			}
		}
		resp.Memberships = append(resp.Memberships, entry)
	}

	// TOP-LEVEL role_template: the FIRST membership's, and only two of its
	// fields. Retained for backward compatibility -- a multi-organization client
	// should read the per-membership entries instead.
	if len(memberships) > 0 && memberships[0].RoleTemplateID != nil {
		resp.RoleTemplate = &MeRoleTemplateSummary{
			Name:        memberships[0].RoleTemplateName,
			DisplayName: memberships[0].RoleTemplateDisplayName,
		}
	}

	return resp
}

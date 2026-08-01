// tenant_scope.go scopes SCIM deprovisioning to the organizations the calling
// provisioner is actually entitled to act in.
//
// This is the DELETE axis of the same class as #718/#719, on the same
// organization_members table the rest of the batch reads from. Every
// deactivation path in this package — DELETE /Users/:id, PUT with active=false,
// and both PATCH replace forms — called RemoveAllMembershipsForUser, one
// statement with a WHERE on user_id and no organization predicate anywhere. So
// a holder of scim:provision, a scope granted through membership in a single
// organization, could delete a target's membership rows in EVERY organization
// on the platform by naming their user id: a cross-tenant write with no read
// required, and the most destructive instance in the batch.
package scim

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
)

// deprovisionUser removes the target user's organization memberships, limited
// to the organizations the caller may act in.
//
// A platform admin keeps the single-statement sweep: an IdP integration wired
// with an admin-scoped credential is the normal deployment and must still be
// able to fully deprovision a leaver. Everyone else removes memberships only
// where they themselves hold scim:provision, resolved through the same
// tenantscope.Resolve every other axis in this batch uses.
//
// Errors are logged and swallowed, matching this package's existing
// best-effort deactivation behaviour; the caller decides its own status code.
//
// GUARD scim-deprovision-tenant-scope (issue #719).
func (h *Handlers) deprovisionUser(c *gin.Context, userID string) error {
	scope, err := tenantscope.Resolve(c, h.orgRepo, auth.ScopeSCIMProvision)
	if err != nil {
		return err
	}

	if scope.PlatformAdmin {
		return h.orgRepo.RemoveAllMembershipsForUser(c.Request.Context(), userID)
	}

	ctx := c.Request.Context()
	memberships, err := h.orgRepo.GetUserMemberships(ctx, userID)
	if err != nil {
		return err
	}
	for _, m := range memberships {
		if !scope.Permits(m.OrganizationID) {
			// Another tenant's membership row. Left alone, and said out loud:
			// a partial deprovision that looks total is its own hazard, and an
			// operator seeing this line knows to escalate rather than assume
			// the user is gone everywhere.
			slog.Info("scim: skipping out-of-scope membership during deprovision",
				"user_id", userID, "organization_id", m.OrganizationID)
			continue
		}
		if err := h.orgRepo.RemoveMember(ctx, m.OrganizationID, userID); err != nil {
			return err
		}
	}
	return nil
}

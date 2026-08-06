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
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
)

// deprovisionUser removes the target user's organization memberships, limited
// to the organizations the caller may act in, and then invalidates every
// credential family the user holds, logging the sweep under reason.
//
// This helper owns BOTH halves of a SCIM deprovision on purpose. Memberships
// are only the stored half of a user's authority: their JWT sessions and API
// keys carry a snapshot of it (issue #736), so a path that removed the former
// without sweeping the latter would leave working credentials behind. When the
// two were separate calls, every caller had to remember the pairing; housing
// the sweep here makes it structural — no caller can reduce authority without
// it.
//
// A platform admin keeps the single-statement sweep: an IdP integration wired
// with an admin-scoped credential is the normal deployment and must still be
// able to fully deprovision a leaver. Everyone else removes memberships only
// where they themselves hold scim:provision, resolved through the same
// tenantscope.Resolve every other axis in this batch uses.
//
// If membership removal fails the error is returned and the credential sweep
// does not run, preserving the caller-visible ordering from when the sweep was
// a separate call; sweep failures are best-effort and logged by deprovision
// itself. The caller decides its own status code.
//
// GUARD scim-deprovision-tenant-scope (issue #719): membership removal is
// scoped to the caller's tenancy.
// GUARD scim-deprovision-credential-sweep (issue #736): every path that
// removes memberships also sweeps JWT sessions and API keys.
func (h *Handlers) deprovisionUser(c *gin.Context, userID, reason string) error {
	scope, err := tenantscope.Resolve(c, h.orgRepo, auth.ScopeSCIMProvision)
	if err != nil {
		return err
	}

	ctx := c.Request.Context()
	if scope.PlatformAdmin {
		// A bulk sweep reports a COUNT, not ErrNotFound: removing zero rows is
		// the ordinary answer for a user who holds no memberships (already
		// deprovisioned, or provisioned but never added to an organization),
		// and it must not stop the credential sweep below — the sessions and
		// API keys outlive the membership rows and are the half that still
		// grants access.
		removed, err := h.orgRepo.RemoveAllMembershipsForUser(ctx, userID)
		if err != nil {
			return err
		}
		slog.Info("scim: removed all memberships during platform-admin deprovision",
			"user_id", userID, "memberships_removed", removed)
		h.deprovision(ctx, userID, reason)
		return nil
	}

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
		// store.ErrNotFound here means the row this loop just read is already
		// gone — a concurrent deprovision, or a retry of this one. That is the
		// DESIRED end state, not a failure, and aborting on it would skip both
		// the remaining organizations and the credential sweep, leaving working
		// sessions and API keys behind for a user the caller believes is
		// deprovisioned. Treat it as "already removed" and keep going.
		if err := h.orgRepo.RemoveMember(ctx, m.OrganizationID, userID); err != nil &&
			!identityerr.IsNotFound(err) {
			return err
		}
	}
	h.deprovision(ctx, userID, reason)
	return nil
}

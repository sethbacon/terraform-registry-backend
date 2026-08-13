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
//
// THE OTHER SCIM AXES ARE DELIBERATELY PLATFORM-WIDE, and say so at each call
// site with store.OrgScopeAllOrganizations(). GET/POST/PUT/PATCH on
// /scim/v2/Users and the /Groups reads address every user and organization, as
// they did before the mandatory tenant parameter existed: an IdP feed is
// expected to see and reconcile the population it provisions, and narrowing
// those reads would turn a 200 into a shorter list and a 404 for a user the
// caller can already legitimately create. Narrowing them is a product decision
// about what a per-tenant SCIM feed should see, not a mechanical consequence of
// the parameter, so it is not made here.
package scim

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
)

// deprovisionOrganizations translates the caller's OrgScope into the
// organization list the admin floor should evaluate.
//
// A scope naming specific organizations gives the floor exactly the rows the
// DELETE will match. An ALL-organizations scope gives it nothing, which the
// floor reads as "every organization this principal belongs to" — the same set,
// spelled the way the floor spells it, and the only spelling that stays correct
// when the principal joins an organization between the two reads.
func deprovisionOrganizations(scope repositories.OrgScope) []string {
	if scope.IsAllOrganizations() {
		return nil
	}
	return scope.OrganizationIDs()
}

// respondDeprovisionFailure writes the SCIM error for a deprovision that did
// not happen (issue #766).
//
// 409 for an administrator-floor refusal, so an IdP feed can tell "this
// deactivation is impossible until you appoint somebody else" apart from "the
// registry is broken, retry". A SCIM client retries a 500 forever and reports
// nothing to the operator; a 409 with a message is the difference between a
// deactivation an administrator can act on and one that disappears into a sync
// log.
//
// 500 for everything else, unchanged.
func respondDeprovisionFailure(c *gin.Context, userID string, err error) {
	switch {
	case errors.Is(err, adminfloor.ErrLastPlatformAdmin):
		slog.Error("scim: deprovision refused — it would leave the deployment with no platform administrator",
			"id", userID)
		scimError(c, http.StatusConflict,
			"Cannot deactivate the deployment's last platform administrator; grant platform-admin to another user first")
	case errors.Is(err, adminfloor.ErrLastOrganizationAdmin):
		slog.Error("scim: deprovision refused — it would leave an organization with no administrator",
			"id", userID, "error", err)
		scimError(c, http.StatusConflict,
			"Cannot deactivate an organization's last administrator; give another member a role carrying organizations:write first")
	default:
		slog.Error("scim: deactivate user failed", "id", userID, "error", err)
		scimError(c, http.StatusInternalServerError, "Failed to deactivate user")
	}
}

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
// A platform admin still deprovisions the leaver everywhere: an IdP integration
// wired with an admin-scoped credential is the normal deployment. Everyone else
// removes memberships only where they themselves hold scim:provision, resolved
// through the same tenantscope.Resolve every other axis in this batch uses.
// Both are now the SAME statement — the difference is the OrgScope handed to it,
// not a second code path — because the tenant predicate lives in the query
// rather than in a read-then-filter loop over rows the caller was never entitled
// to see. The read-back of every membership, and the per-row Permits check that
// followed it, are gone with it.
//
// The credential sweep inherits the scope the strip ACTUALLY applied, so a key
// is revoked exactly where the authority behind it was just withdrawn: no
// membership removed in an organization means nothing was reduced there and its
// keys stand (identity #160), and every organization where a membership WAS
// removed is in the sweep by construction, so nothing is stranded (#736).
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
	// A bulk sweep reports a COUNT, not ErrNotFound: removing zero rows is the
	// ordinary answer for a user who holds no memberships in scope (already
	// deprovisioned, provisioned but never added to an organization, or a member
	// only of organizations this caller has no authority in), and it must not
	// stop the credential sweep below — the sessions outlive the membership rows
	// and are the half that still grants access.
	//
	// GUARD admin-floor (issue #766). The strip runs inside the floor's lock,
	// with the SAME organizations the OrgScope will actually match, so the
	// invariants are evaluated over exactly the rows about to be deleted rather
	// than over the whole platform. A platform-wide caller passes nothing,
	// which the floor reads as "every organization this principal belongs to" —
	// the same set that statement will empty.
	//
	// DestroysPrincipal is FALSE, and that is the distinction from a user
	// delete: SCIM leaves the users row intact, so a deprovisioned
	// administrator holding a platform_admins grant can still authenticate and
	// still exercise it. Marking the principal destroyed here would refuse
	// deprovisions that take nothing away.
	var removed repositories.OrgScope
	err = h.floor.Protect(ctx, adminfloor.Change{
		UserID:            userID,
		OrganizationIDs:   deprovisionOrganizations(scope.OrgScope()),
		RemovesMembership: true,
	}, func(ctx context.Context) error {
		var stripErr error
		removed, stripErr = h.orgRepo.RemoveAllMembershipsForUser(ctx, userID, scope.OrgScope())
		return stripErr
	})
	if err != nil {
		return err
	}
	slog.Info("scim: removed memberships during deprovision",
		"user_id", userID, "organizations_removed", removed.OrganizationIDs(),
		"caller_scope", scope.OrgScope().String())
	h.deprovision(ctx, userID, removed, reason)
	return nil
}

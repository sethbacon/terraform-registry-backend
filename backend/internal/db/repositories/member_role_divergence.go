// member_role_divergence.go is the answer to "how would we know the read
// cutover was wrong" (sethbacon/terraform-suite-identity#206, phase 3b).
//
// # The hazard this exists for
//
// A gap in the dual-write does not surface as an error. It surfaces as a
// principal holding the WRONG ROLE -- denied something they should have, or
// allowed something they should not -- and every layer above reports success.
// The drift check (member_role_drift.go) gates the cutover on that being zero
// BEFORE reads flip. This file is what keeps it from going silent AFTER.
//
// # The mechanism, and why it costs nothing
//
// Every accessor in organization_repository.go already holds BOTH answers. It
// asks the shared identity store for the membership -- which still carries
// `organization_members.role_template_id` and the joined `role_templates`
// columns, because phase 4 has not dropped them -- and then overlays the role
// from registry's own tables. So the comparison is between two values already
// in hand: no extra query, no shadow read, no sampling.
//
// That is only true while the old columns still exist. When phase 4 drops
// them the store's answer becomes empty and this comparison stops meaning
// anything; it must be removed in the same change, not left reporting
// "identity says no role" for every request.
//
// # What it catches, stated as limits rather than claims
//
//   - A membership registry has no row for, or holds a different template for,
//     ON THE REQUESTS THAT ACTUALLY READ IT. A dormant principal nobody
//     authenticates as is invisible here; the periodic drift check is what
//     covers them.
//   - It does NOT catch a mirrored row with no membership. Every accessor asks
//     the store first, so a mirror row for a non-member is never reached --
//     which is also why it confers nothing today. It becomes reachable only
//     when phase 4 moves the membership fact itself, and the drift check
//     reports it now.
//   - It does NOT catch two templates that agree by id but differ in SCOPES.
//     The id is what is compared here because it is what both sides carry per
//     membership; scope equality is a property of the template tables and is
//     the drift check's second half.
package repositories

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Divergence kinds. Values, not free strings, so the metric's label set is
// closed and a dashboard cannot be broken by a typo at a new call site.
const (
	// DivergenceMissingMirror: identity has the membership, registry's own
	// tables have no row for it. The principal LOSES whatever the role
	// conferred, because a missing row fails closed.
	DivergenceMissingMirror = "missing_mirror"
	// DivergenceRoleDiffers: both sides have a row and they name different
	// role templates (including one naming none). The direction is not
	// knowable from the kind alone -- it may grant or withhold -- so the log
	// carries both ids.
	DivergenceRoleDiffers = "role_differs"
)

// RoleReadDivergenceTotal counts reads where registry's own authorization
// tables disagreed with the identity tables they were derived from.
//
// STEADY STATE IS ZERO, and that is the point: this is not a rate to watch
// trend, it is a counter that should never leave zero. Alert on
// `increase(...) > 0`, not on a threshold.
//
// Labelled by accessor so the report names which read path saw it -- the
// accessors have different blast radii, and "GetUserCombinedScopes disagreed"
// (a token being minted) is a different page from "ListMembers disagreed" (an
// admin screen).
var RoleReadDivergenceTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "registry_role_read_divergence_total",
		Help: "Reads where registry's own role tables disagreed with the identity columns they were once copied from (terraform-suite-identity#206). kind=missing_mirror is a DEFECT and its steady state is zero; kind=role_differs is INFORMATIONAL since #1056 -- registry decides its own roles, so on a coupled deployment a non-zero rate is expected. Alert on missing_mirror, and on a step change in role_differs.",
	},
	[]string{"accessor", "kind"},
)

// compareRole reports a disagreement between the identity role the store
// returned and the role registry's own tables hold for the same membership.
//
// It NEVER changes the answer. The caller has already decided that registry's
// tables are authoritative; making this function able to override that would
// give the product two answers to one question and put the choice between them
// inside a diagnostic.
//
// identityRoleID is the value the shared store read from
// `organization_members.role_template_id`. registryRole is what
// MemberRoleReader found, nil when there is no mirrored row.
func compareRole(ctx context.Context, accessor, orgID, userID string, identityRoleID *string, registryRole *MirroredRole) {
	if registryRole == nil {
		RoleReadDivergenceTotal.WithLabelValues(accessor, DivergenceMissingMirror).Inc()
		// STILL AN ERROR. This one did not become expected: the boot reconcile
		// confirms every identity membership with at least a NULL-role row, so a
		// missing row means the confirmation did not run or did not reach this
		// pair -- and the principal is being served no role at all.
		slog.ErrorContext(ctx, "registry has no role row for a membership that exists in identity; "+
			"the principal is being served NO role here",
			"accessor", accessor, "organization_id", orgID, "user_id", userID,
			"identity_role_template_id", derefRole(identityRoleID),
			"remedy", "run `role-drift` (cmd/role-drift); restarting the backend confirms every membership")
		return
	}
	// IDENTITY EXPRESSES NO ROLE, WHICH IS NOT A DISAGREEMENT
	// (sethbacon/terraform-suite-identity#206).
	//
	// Registry stopped writing `organization_members.role_template_id`: the
	// identity leg of every membership write now carries nil, and identity holds
	// the membership FACT alone. So a NULL here is the intended end state, not
	// two applications answering differently -- there is only one answer, and it
	// is the one being served.
	//
	// Counting it would be worse than noise. The metric's whole use is stated
	// below: "alert on a step change, not on non-zero". Once new memberships all
	// read NULL on this side, role_differs would climb toward every read and the
	// rate would stop meaning what the alert was built on -- while a deployment
	// still carrying pre-#206 rows kept a genuine, and now invisible, signal
	// mixed into it.
	//
	// Rows written before this change still carry a role and are still compared,
	// so the mixed state during a rollout reports exactly the disagreements that
	// were already there and nothing else.
	if identityRoleID == nil {
		return
	}
	if sameRole(identityRoleID, registryRole.RoleTemplateID) {
		return
	}
	// INFORMATIONAL SINCE #1056, and the level is the point.
	//
	// Registry decides its own roles. A registry role that differs from
	// identity's column is what a coupled deployment looks like when it is
	// WORKING: the sibling granted its own role in its own application and
	// registry did not adopt it. Logging that at ERROR on every such read would
	// make a healthy deployment loud, which is how a signal gets filtered out
	// and then stops being read at all.
	//
	// The metric is KEPT, and still incremented, because the rate is the useful
	// thing: it says how much of this deployment's authorization the two
	// applications disagree about. Alert on a step change, not on non-zero.
	RoleReadDivergenceTotal.WithLabelValues(accessor, DivergenceRoleDiffers).Inc()
	slog.DebugContext(ctx, "registry's own role assignment differs from the identity column it used to be copied from; "+
		"registry's answer is the one being served, which is the intended behaviour since #1056",
		"accessor", accessor, "organization_id", orgID, "user_id", userID,
		"identity_role_template_id", derefRole(identityRoleID),
		"registry_role_template_id", derefRole(registryRole.RoleTemplateID),
		"note", "`role-drift` lists these under advisory differences")
}

// derefRole renders an optional role template id for a log field. "none" rather
// than an empty string, because an empty string in a structured log is
// indistinguishable from a field the writer forgot to populate -- and here the
// difference between "no role" and "not recorded" is the whole subject.
func derefRole(id *string) string {
	if id == nil {
		return "none"
	}
	return *id
}

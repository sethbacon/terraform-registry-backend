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
		Help: "Reads where registry's own role tables disagreed with the identity tables they mirror (terraform-suite-identity#206). Steady state is zero; alert on any increase.",
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
		slog.ErrorContext(ctx, "registry has no mirrored role for a membership that exists in identity; "+
			"the principal is being served NO role here",
			"accessor", accessor, "organization_id", orgID, "user_id", userID,
			"identity_role_template_id", derefRole(identityRoleID),
			"remedy", "run `role-drift` (cmd/role-drift); restarting the backend re-derives the mirror")
		return
	}
	if sameRole(identityRoleID, registryRole.RoleTemplateID) {
		return
	}
	RoleReadDivergenceTotal.WithLabelValues(accessor, DivergenceRoleDiffers).Inc()
	slog.ErrorContext(ctx, "registry's own role assignment disagrees with the identity tables it mirrors; "+
		"registry's answer is the one being served",
		"accessor", accessor, "organization_id", orgID, "user_id", userID,
		"identity_role_template_id", derefRole(identityRoleID),
		"registry_role_template_id", derefRole(registryRole.RoleTemplateID),
		"remedy", "run `role-drift` (cmd/role-drift); restarting the backend re-derives the mirror")
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

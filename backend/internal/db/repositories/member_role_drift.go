// member_role_drift.go compares registry's own authorization tables against the
// identity tables they were derived from, and reports every way they disagree.
//
// THIS IS THE GATE ON THE READ CUTOVER (sethbacon/terraform-suite-identity#206,
// phase 3b). The estate's precedent is `bind-secrets verify`: it exits non-zero
// while any row is unreconciled, and zero is what permits the next step. The
// runnable verb is cmd/role-drift; this file is the comparison, kept in the
// library so the same code answers the pre-flip gate, the post-flip check, and
// the tests.
//
// # Why it is Go and not the SQL query phase 3a shipped
//
// docs/identity-schema.md carried a FULL OUTER JOIN that compared the two
// copies in one statement. It is correct as far as it reaches, and it cannot
// reach far enough for a gate:
//
//   - It requires both copies on ONE connection. Under TFR_IDENTITY_DATABASE_*
//     they are in different databases and no statement can join them. That is
//     exactly the topology whose dual-write phase 3a could not perform, i.e.
//     the one most likely to have drifted.
//   - It compares role template SCOPES but not NAMES. Registry resolves
//     templates by name (GetRoleTemplateByName, and the group-mapping
//     reconciliation), so two rows that agree on id and scopes but disagree on
//     name resolve to different templates for the same request.
//   - It cannot see a membership whose role_template_id names a template that
//     does not exist at the SOURCE. The reconcile mirrors those with no role by
//     design, so the pair renders as an ordinary "roles disagree" with no
//     indication that the identity data is what is malformed.
//   - It cannot see a row whose organization_id or user_id is not a UUID. Those
//     are skipped by the reconcile and can never be mirrored, so they are
//     permanently unreconciled and a gate that does not count them can return
//     zero forever while a membership stays invisible.
//
// Each of those is a case where a principal ends up with the wrong role and
// nothing says so, which is the failure this phase is engineered against.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Drift kinds. Ordered here by blast radius, worst first, which is also the
// order DriftReport sorts them into: an operator reading a long report should
// meet the rows that grant authority before the rows that withhold it.
const (
	// DriftMirrorWithoutMembership: registry holds a role for a principal who
	// is not a member. Inert while the membership fact still comes from
	// identity -- every accessor asks the store first -- and it GRANTS
	// authority the product never issued the moment phase 4 moves that fact.
	DriftMirrorWithoutMembership = "mirror_without_membership"
	// DriftRoleDiffers: both copies have the membership and name different
	// role templates. May grant or withhold; the report carries both ids.
	DriftRoleDiffers = "role_differs"
	// DriftMembershipNotMirrored: identity has the membership, registry has no
	// row. The principal is served no role at all after the cutover.
	DriftMembershipNotMirrored = "membership_not_mirrored"
	// DriftTemplateScopesDiffer: same template id on both sides, different
	// scope sets. Every holder's effective authority differs.
	DriftTemplateScopesDiffer = "template_scopes_differ"
	// DriftTemplateNameDiffers: same id, different name. Registry resolves
	// templates by name in the group-mapping reconciliation and the admin API,
	// so the two copies answer a name lookup with different rows.
	DriftTemplateNameDiffers = "template_name_differs"
	// DriftTemplateNotMirrored: a source template with no registry copy. Any
	// membership naming it resolves to no role.
	DriftTemplateNotMirrored = "template_not_mirrored"
	// DriftMirroredTemplateOrphaned: a registry template the source no longer
	// has. Left behind by a delete whose mirror write failed.
	DriftMirroredTemplateOrphaned = "mirrored_template_orphaned"
	// DriftMembershipRoleMissingTemplate: an identity membership naming a
	// template that does not exist in identity's own role_templates. The
	// inconsistency is in the SOURCE; the reconcile mirrors it with no role
	// rather than inventing an assignment, so it can never reconcile to zero
	// until an operator decides what the role should be.
	DriftMembershipRoleMissingTemplate = "membership_role_missing_template"
	// DriftUnparseableRow: a source row whose organization_id or user_id is not
	// a UUID. It can never be mirrored, so it is permanently unreconciled.
	DriftUnparseableRow = "unparseable_row"
)

// driftKindOrder ranks the kinds for the report's ordering. A kind missing from
// this map sorts last rather than panicking -- a report that omitted a row
// because its kind was new would be the worst possible failure of a gate.
var driftKindOrder = map[string]int{
	DriftMirrorWithoutMembership:       0,
	DriftRoleDiffers:                   1,
	DriftMembershipNotMirrored:         2,
	DriftTemplateScopesDiffer:          3,
	DriftTemplateNameDiffers:           4,
	DriftTemplateNotMirrored:           5,
	DriftMirroredTemplateOrphaned:      6,
	DriftMembershipRoleMissingTemplate: 7,
	DriftUnparseableRow:                8,
}

// DriftRow is one disagreement.
type DriftRow struct {
	Kind string
	// OrganizationID / UserID identify the membership, empty for a
	// template-level row.
	OrganizationID string
	UserID         string
	// RoleTemplateID identifies the template, empty for a membership-level row
	// that is not about one particular template.
	RoleTemplateID string
	// Identity / Registry are the two disagreeing values, rendered for a human.
	// "none" means the side had no value; "absent" means it had no row at all.
	Identity string
	Registry string
}

// String renders one row for the verb's output.
func (d DriftRow) String() string {
	var where string
	switch {
	case d.OrganizationID != "" || d.UserID != "":
		where = fmt.Sprintf("organization=%s user=%s", d.OrganizationID, d.UserID)
	default:
		where = fmt.Sprintf("role_template=%s", d.RoleTemplateID)
	}
	return fmt.Sprintf("%-33s %s  identity=%s  registry=%s", d.Kind, where, d.Identity, d.Registry)
}

// DriftReport is the whole comparison.
type DriftReport struct {
	// Rows is every disagreement found, worst first.
	Rows []DriftRow
	// SourceMemberships / SourceRoleTemplates / MirroredMemberships /
	// MirroredRoleTemplates are what was actually compared.
	//
	// They are reported because a gate that passes MUST be able to prove it
	// looked at something. Two empty databases agree perfectly, and a check
	// that answers "no drift" without saying it compared zero rows to zero rows
	// is how a cutover gets certified against nothing at all.
	SourceMemberships     int
	SourceRoleTemplates   int
	MirroredMemberships   int
	MirroredRoleTemplates int
}

// Clean reports whether the two copies agree.
func (r DriftReport) Clean() bool { return len(r.Rows) == 0 }

// CheckMemberRoleDrift compares registry's own authorization tables against the
// identity tables, through the two connections the application itself uses.
//
// identityDB MUST be the connection the application resolves identity reads
// through and registryDB the one migration 000055 created the tables on --
// the same pair ReconcileMemberRoles takes, and for the same reason: which
// schema and which database hold the live rows is a decision made at process
// start, and this function inherits it rather than inferring it.
//
// It returns an error for STRUCTURAL failures only. A disagreement is data, not
// an error: the caller decides what a non-empty report means, and cmd/role-drift
// turns it into an exit code.
func CheckMemberRoleDrift(ctx context.Context, identityDB, registryDB *sql.DB) (DriftReport, error) {
	var report DriftReport

	// Refuse against a source or a destination that is not there. An
	// unreachable table and an empty one are indistinguishable from a row
	// count, and a gate that cannot tell them apart reports "no drift" for the
	// deployment whose tables it never found.
	if err := verifyIdentitySource(ctx, identityDB); err != nil {
		return report, err
	}
	if err := NewMemberRoleMirror(registryDB).Verify(ctx); err != nil {
		return report, fmt.Errorf("registry role tables unusable: %w", err)
	}

	sourceTemplates, err := identitystore.NewRoleTemplateRepository(identityDB).ListRoleTemplates(ctx)
	if err != nil {
		return report, fmt.Errorf("read effective role templates: %w", err)
	}
	mirroredTemplates, err := NewMemberRoleReader(registryDB).ListRoleTemplates(ctx)
	if err != nil {
		return report, fmt.Errorf("read mirrored role templates: %w", err)
	}
	report.SourceRoleTemplates = len(sourceTemplates)
	report.MirroredRoleTemplates = len(mirroredTemplates)

	sourceMembers, unparseable, err := readEffectiveMemberships(ctx, identityDB)
	if err != nil {
		return report, err
	}
	mirroredMembers, err := readMirroredMemberships(ctx, registryDB)
	if err != nil {
		return report, err
	}
	report.SourceMemberships = len(sourceMembers)
	report.MirroredMemberships = len(mirroredMembers)

	rows := driftInTemplates(sourceTemplates, mirroredTemplates)
	rows = append(rows, driftInMemberships(sourceMembers, mirroredMembers, sourceTemplates)...)
	if unparseable > 0 {
		// No identifiers: they are precisely the rows whose identifiers could
		// not be represented. readEffectiveMemberships logs each one with its
		// raw value as it skips it.
		rows = append(rows, DriftRow{
			Kind:     DriftUnparseableRow,
			Identity: fmt.Sprintf("%d row(s) with a non-UUID organization_id or user_id", unparseable),
			Registry: "absent",
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Kind != rows[j].Kind {
			return driftKindOrder[rows[i].Kind] < driftKindOrder[rows[j].Kind]
		}
		if rows[i].OrganizationID != rows[j].OrganizationID {
			return rows[i].OrganizationID < rows[j].OrganizationID
		}
		if rows[i].UserID != rows[j].UserID {
			return rows[i].UserID < rows[j].UserID
		}
		return rows[i].RoleTemplateID < rows[j].RoleTemplateID
	})
	report.Rows = rows
	return report, nil
}

// driftInTemplates compares the two role-template sets by id.
//
// By id, not by name, because the id is what a membership stores: two rows that
// share a name and differ in id are two DIFFERENT templates as far as every
// assignment is concerned. The name is then compared as a property of the
// matched pair, which is how DriftTemplateNameDiffers can exist at all.
func driftInTemplates(source, mirrored []*models.RoleTemplate) []DriftRow {
	byID := make(map[uuid.UUID]*models.RoleTemplate, len(mirrored))
	for _, t := range mirrored {
		byID[t.ID] = t
	}

	var rows []DriftRow
	seen := make(map[uuid.UUID]bool, len(source))
	for _, want := range source {
		seen[want.ID] = true
		got, ok := byID[want.ID]
		if !ok {
			rows = append(rows, DriftRow{
				Kind:           DriftTemplateNotMirrored,
				RoleTemplateID: want.ID.String(),
				Identity:       want.Name,
				Registry:       "absent",
			})
			continue
		}
		if want.Name != got.Name {
			rows = append(rows, DriftRow{
				Kind:           DriftTemplateNameDiffers,
				RoleTemplateID: want.ID.String(),
				Identity:       want.Name,
				Registry:       got.Name,
			})
		}
		if !sameScopes(want.Scopes, got.Scopes) {
			rows = append(rows, DriftRow{
				Kind:           DriftTemplateScopesDiffer,
				RoleTemplateID: want.ID.String(),
				Identity:       renderScopes(want.Scopes),
				Registry:       renderScopes(got.Scopes),
			})
		}
	}
	for _, got := range mirrored {
		if seen[got.ID] {
			continue
		}
		rows = append(rows, DriftRow{
			Kind:           DriftMirroredTemplateOrphaned,
			RoleTemplateID: got.ID.String(),
			Identity:       "absent",
			Registry:       got.Name,
		})
	}
	return rows
}

// driftInMemberships compares the two assignment sets both ways.
func driftInMemberships(source, mirrored map[memberKey]*string, sourceTemplates []*models.RoleTemplate) []DriftRow {
	live := make(map[string]bool, len(sourceTemplates))
	for _, t := range sourceTemplates {
		live[t.ID.String()] = true
	}

	var rows []DriftRow
	for key, sourceRole := range source {
		// A membership naming a template the source itself does not have is
		// reported on its own terms. The reconcile mirrors it with NO role, so
		// without this it would surface as an ordinary role_differs and an
		// operator would go looking for a broken dual-write instead of the
		// broken identity row that actually caused it.
		if sourceRole != nil && !live[*sourceRole] {
			rows = append(rows, DriftRow{
				Kind:           DriftMembershipRoleMissingTemplate,
				OrganizationID: key.orgID,
				UserID:         key.userID,
				RoleTemplateID: *sourceRole,
				Identity:       *sourceRole,
				Registry:       "none (mirrored with no role, deliberately)",
			})
			continue
		}
		mirroredRole, ok := mirrored[key]
		if !ok {
			rows = append(rows, DriftRow{
				Kind:           DriftMembershipNotMirrored,
				OrganizationID: key.orgID,
				UserID:         key.userID,
				Identity:       derefRole(sourceRole),
				Registry:       "absent",
			})
			continue
		}
		if !sameRole(sourceRole, mirroredRole) {
			rows = append(rows, DriftRow{
				Kind:           DriftRoleDiffers,
				OrganizationID: key.orgID,
				UserID:         key.userID,
				Identity:       derefRole(sourceRole),
				Registry:       derefRole(mirroredRole),
			})
		}
	}
	for key, mirroredRole := range mirrored {
		if _, ok := source[key]; ok {
			continue
		}
		rows = append(rows, DriftRow{
			Kind:           DriftMirrorWithoutMembership,
			OrganizationID: key.orgID,
			UserID:         key.userID,
			Identity:       "absent",
			Registry:       derefRole(mirroredRole),
		})
	}
	return rows
}

// sameScopes compares two scope sets as SETS: order and duplicates do not
// change what a template confers, and reporting a reordering as drift would
// make the gate un-passable for a deployment that is in fact correct.
func sameScopes(a, b []string) bool {
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
		delete(seen, s)
	}
	return len(seen) == 0
}

// renderScopes formats a scope set for the report, sorted so two renderings of
// the same set read the same.
func renderScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "[]"
	}
	out := append([]string(nil), scopes...)
	sort.Strings(out)
	return "[" + strings.Join(out, " ") + "]"
}

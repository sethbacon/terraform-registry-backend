// group_mapping_drift.go compares registry's own group_mappings table against
// the oidc_config.extra_config lists it was derived from, and reports every
// way they disagree.
//
// THIS IS THE GATE ON THE GROUP-MAPPING READ CUTOVER
// (sethbacon/terraform-suite-identity#206, phase 2 -- migration 000059), the
// same role CheckMemberRoleDrift plays for the role tables. The runnable verb
// is cmd/role-drift, which runs both checks and exits non-zero while either
// reports a row.
//
// It is Go rather than SQL for the same reason the member-role check is: the
// two sides may live in different DATABASES (TFR_IDENTITY_DATABASE_*), where
// no statement can join them -- and the source here is not even a table but a
// JSON list inside a JSONB column, whose decoding rules belong to the shared
// library. Comparing decoded values through the library's own decoder is what
// makes "agrees" mean "the read cutover would resolve the same mappings".
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// Group-mapping drift kinds. Ordered by blast radius, worst first, which is
// also the order GroupMappingDriftReport sorts them into.
const (
	// GroupMappingDriftMirrorOrphaned: registry holds mapping rows for an
	// oidc_config the source no longer has, or more rows than the source list.
	// Inert today; the moment the read cutover ships it GRANTS memberships the
	// configured policy never issued -- the one direction that grants.
	GroupMappingDriftMirrorOrphaned = "group_mapping_mirror_orphaned"
	// GroupMappingDriftFieldsDiffer: both sides have a mapping at this position
	// and disagree on group, organization or role. May grant or withhold.
	GroupMappingDriftFieldsDiffer = "group_mapping_fields_differ"
	// GroupMappingDriftNotMirrored: the source has a mapping registry has no
	// row for. That group's members are served no membership after the cutover.
	GroupMappingDriftNotMirrored = "group_mapping_not_mirrored"
	// GroupMappingDriftRoleRefStale: the mirrored role_template_id is not what
	// the mapped role name currently resolves to in registry_role_templates --
	// a template was created, renamed or deleted after the row was written and
	// no dual-write or reconcile has re-resolved it yet.
	GroupMappingDriftRoleRefStale = "group_mapping_role_ref_stale"
)

// groupMappingDriftKindOrder ranks the kinds for the report's ordering. A kind
// missing from this map sorts last rather than panicking.
var groupMappingDriftKindOrder = map[string]int{
	GroupMappingDriftMirrorOrphaned: 0,
	GroupMappingDriftFieldsDiffer:   1,
	GroupMappingDriftNotMirrored:    2,
	GroupMappingDriftRoleRefStale:   3,
}

// GroupMappingDriftRow is one disagreement.
type GroupMappingDriftRow struct {
	Kind string
	// OIDCConfigID / Position locate the mapping.
	OIDCConfigID string
	Position     int
	// Identity / Registry are the two disagreeing values, rendered for a
	// human. "absent" means the side had no row at all.
	Identity string
	Registry string
}

// String renders one row for the verb's output.
func (d GroupMappingDriftRow) String() string {
	return fmt.Sprintf("%-33s oidc_config=%s position=%d  identity=%s  registry=%s",
		d.Kind, d.OIDCConfigID, d.Position, d.Identity, d.Registry)
}

// GroupMappingDriftReport is the whole comparison.
type GroupMappingDriftReport struct {
	// Rows is every disagreement found, worst first.
	Rows []GroupMappingDriftRow
	// What was actually compared -- reported because a gate that passes MUST be
	// able to prove it looked at something. Two empty databases agree
	// perfectly.
	SourceConfigs    int
	SourceMappings   int
	MirroredMappings int
	// UnparseableExtraConfigs counts oidc_config rows whose extra_config is not
	// a JSON object. Not drift -- the library's decoder reads "no mappings" out
	// of such a row and the mirror faithfully holds none -- but a gate that hid
	// a corrupt stored provider config would be lying about what it compared.
	UnparseableExtraConfigs int
}

// Clean reports whether the two copies agree.
func (r GroupMappingDriftReport) Clean() bool { return len(r.Rows) == 0 }

// CheckGroupMappingDrift compares registry's own group_mappings table against
// the oidc_config.extra_config lists, through the two connections the
// application itself uses.
//
// identityDB MUST be the connection the application resolves oidc_config reads
// through and registryDB the one migration 000059 created the table on -- the
// same pair ReconcileGroupMappings takes, and for the same reason.
func CheckGroupMappingDrift(ctx context.Context, identityDB, registryDB *sql.DB) (GroupMappingDriftReport, error) {
	var report GroupMappingDriftReport

	if err := NewGroupMappingMirror(registryDB).Verify(ctx); err != nil {
		return report, fmt.Errorf("registry group-mapping table unusable: %w", err)
	}
	if err := verifyGroupMappingSource(ctx, identityDB); err != nil {
		return report, err
	}

	nameToID, err := registryRoleTemplateNames(ctx, registryDB)
	if err != nil {
		return report, err
	}
	sourceLists, unparseable, err := readEffectiveGroupMappings(ctx, identityDB)
	if err != nil {
		return report, err
	}
	mirrored, err := readMirroredGroupMappings(ctx, registryDB)
	if err != nil {
		return report, err
	}

	report.SourceConfigs = len(sourceLists)
	report.UnparseableExtraConfigs = unparseable
	for _, rows := range mirrored {
		report.MirroredMappings += len(rows)
	}

	renderRole := func(name string, id *string) string {
		if id == nil {
			return fmt.Sprintf("role=%q (unresolved)", name)
		}
		return fmt.Sprintf("role=%q id=%s", name, *id)
	}

	for configID, mappings := range sourceLists {
		report.SourceMappings += len(mappings)
		have := mirrored[configID]
		for i, m := range mappings {
			var wantID *string
			if id, ok := nameToID[m.Role]; ok {
				idCopy := id
				wantID = &idCopy
			}
			source := fmt.Sprintf("group=%q organization=%q role=%q", m.Group, m.Organization, m.Role)
			if i >= len(have) {
				report.Rows = append(report.Rows, GroupMappingDriftRow{
					Kind: GroupMappingDriftNotMirrored, OIDCConfigID: configID.String(), Position: i,
					Identity: source, Registry: "absent",
				})
				continue
			}
			h := have[i]
			if h.Position != i || h.Group != m.Group || h.Organization != m.Organization || h.RoleName != m.Role {
				report.Rows = append(report.Rows, GroupMappingDriftRow{
					Kind: GroupMappingDriftFieldsDiffer, OIDCConfigID: configID.String(), Position: i,
					Identity: source,
					Registry: fmt.Sprintf("position=%d group=%q organization=%q role=%q", h.Position, h.Group, h.Organization, h.RoleName),
				})
				continue
			}
			if !sameRole(h.RoleTemplateID, wantID) {
				report.Rows = append(report.Rows, GroupMappingDriftRow{
					Kind: GroupMappingDriftRoleRefStale, OIDCConfigID: configID.String(), Position: i,
					Identity: renderRole(m.Role, wantID), Registry: renderRole(h.RoleName, h.RoleTemplateID),
				})
			}
		}
		for i := len(mappings); i < len(have); i++ {
			report.Rows = append(report.Rows, GroupMappingDriftRow{
				Kind: GroupMappingDriftMirrorOrphaned, OIDCConfigID: configID.String(), Position: have[i].Position,
				Identity: "absent",
				Registry: fmt.Sprintf("group=%q organization=%q role=%q", have[i].Group, have[i].Organization, have[i].RoleName),
			})
		}
	}
	for configID, rows := range mirrored {
		if _, ok := sourceLists[configID]; ok {
			continue
		}
		for _, h := range rows {
			report.Rows = append(report.Rows, GroupMappingDriftRow{
				Kind: GroupMappingDriftMirrorOrphaned, OIDCConfigID: configID.String(), Position: h.Position,
				Identity: "absent (no such oidc_config)",
				Registry: fmt.Sprintf("group=%q organization=%q role=%q", h.Group, h.Organization, h.RoleName),
			})
		}
	}

	sort.SliceStable(report.Rows, func(i, j int) bool {
		a, aOK := groupMappingDriftKindOrder[report.Rows[i].Kind]
		b, bOK := groupMappingDriftKindOrder[report.Rows[j].Kind]
		if !aOK {
			a = len(groupMappingDriftKindOrder)
		}
		if !bOK {
			b = len(groupMappingDriftKindOrder)
		}
		if a != b {
			return a < b
		}
		if report.Rows[i].OIDCConfigID != report.Rows[j].OIDCConfigID {
			return report.Rows[i].OIDCConfigID < report.Rows[j].OIDCConfigID
		}
		return report.Rows[i].Position < report.Rows[j].Position
	})
	return report, nil
}

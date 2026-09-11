// member_role_reconcile.go keeps registry's own authorization tables in step
// with the identity source (sethbacon/terraform-suite-identity#206, migration
// 000055) -- and, since #1056, in step with the MEMBERSHIP FACTS only.
//
// # What changed in #1056, and why
//
// This function used to copy `organization_members.role_template_id` into
// `organization_member_roles` on every boot. In a coupled deployment that
// column is written by BOTH applications: the state manager grants `editor`,
// the shared library writes identity's `editor` id there, and registry's next
// boot found the id live, assigned it, and handed the principal registry's
// `editor` scopes -- granted by nobody in registry. The state manager's
// reconcile refuses role opinions for exactly this reason, so the propagation
// ran one way, into registry.
//
// So the copy is gone. Identity owns the membership FACT; registry owns the
// ROLE. A membership identity has and registry has no row for is confirmed with
// NO role, which is the fail-closed direction: the principal is a member and
// holds nothing here until somebody grants it here. An existing row's role is
// never touched.
//
// # The one-time adoption, which is not an exception to that
//
// A deployment upgrading from before migration 000055 -- supported, see
// docs/upgrade-guide.md on skip-version upgrades -- arrives with an EMPTY
// `organization_member_roles`. Confirming facts alone would strip every
// principal of every role on the first boot. So when the mirror is empty and
// the source is not, this adopts the source's assignments once, exactly as the
// old behaviour did, and says so in the log.
//
// That is today's first-boot behaviour, not new behaviour. In a coupled
// deployment it imports the sibling's role opinions ONCE, and the upgrade note
// says so; every boot after it, registry decides.
//
// # Role templates are registry's too, since #1057
//
// This function used to list the shared `role_templates`, upsert every row into
// `registry_role_templates` (scopes included) and prune anything not in that
// set. It no longer reads them at all. `registry_role_templates` is written by
// registry's own seed -- unconditionally, in every topology, from
// models.PredefinedRoleTemplates() -- and by registry's admin API, and by
// nothing else.
//
// THE SEED RUNS BEFORE THIS FUNCTION, and that ordering is load-bearing rather
// than tidy. The one-time adoption below validates each membership's role
// against the template set; that set is now REGISTRY's, so it has to exist
// before the adoption reads it. Seeding afterwards would leave a fresh install's
// adoption checking an empty table and mirroring every assignment as "no role".
//
// What this does NOT allow yet: retiring the identity-side seed. Registry's dual
// write is name-based, and the shared library resolves that name in IDENTITY's
// `role_templates` (`lookupRoleTemplateID`), erroring when it is absent -- so an
// unseeded identity table would fail every grant at the identity leg. That goes
// when `organization_members.role_template_id` does, in #206's final phase.
//
// # Why Go and not SQL in the migration
//
// Spelled out at length in 000055_registry_role_tables.up.sql: the EFFECTIVE
// source is chosen at process start by the identity pool's search_path and by
// which database that pool dials, and neither is visible to a migration running
// on the registry connection. Reading through the very *sql.DB the application
// resolves `organization_members` and `role_templates` through makes the
// effective source identical BY CONSTRUCTION.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

// ReconcileReport is what one reconcile did, for the boot log.
type ReconcileReport struct {
	// SourceMemberships is the membership row count read from the effective
	// identity source. Membership is the only thing this function reads there.
	SourceMemberships int
	// RegistryRoleTemplates is how many templates REGISTRY defines, read from
	// its own table after its own seed has run. Reported because an adoption
	// validating against an empty set would mirror every assignment as "no
	// role", and the count is where that shows.
	RegistryRoleTemplates int
	// MembershipsAdopted counts assignments copied from the source by the
	// ONE-TIME adoption -- non-zero only on the first boot after the mirror
	// tables are created, and zero forever after. See the header.
	MembershipsAdopted int
	// MembershipsConfirmed counts memberships recorded here with NO role
	// because identity has them and registry had no row. Steady state 0.
	MembershipsConfirmed int

	// MembershipsRemoved counts mirrored rows deleted because identity no
	// longer has the membership.
	MembershipsRemoved int
	// OrphanedRoleRefs counts memberships whose role_template_id names a
	// template that does not exist in the source at all. These are mirrored
	// with a NULL role rather than skipped, and they are the inconsistency the
	// divergence query in docs/identity-schema.md reports on.
	OrphanedRoleRefs int
	// UnparseableRows counts source rows this reconcile could not represent --
	// an organization_id or user_id that is not a UUID. Counted and logged, not
	// fatal: one malformed legacy row must not stop a deployment from booting.
	UnparseableRows int
}

// LogValue renders the report for slog without a field per counter.
func (r ReconcileReport) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("source_memberships", r.SourceMemberships),
		slog.Int("registry_role_templates", r.RegistryRoleTemplates),
		slog.Int("memberships_adopted", r.MembershipsAdopted),
		slog.Int("memberships_confirmed", r.MembershipsConfirmed),
		slog.Int("memberships_removed", r.MembershipsRemoved),
		slog.Int("orphaned_role_refs", r.OrphanedRoleRefs),
		slog.Int("unparseable_rows", r.UnparseableRows),
	)
}

// memberKey identifies one mirrored assignment.
type memberKey struct {
	orgID  string
	userID string
}

// ReconcileMemberRoles makes registry's own authorization tables equal the
// effective identity source, and returns what it did.
//
// identityDB MUST be the connection the application resolves identity reads
// through -- the same handle NewRouter hands the organization repository. That
// is the whole correctness argument: this function never decides which schema
// or which database holds the live rows, it inherits that decision.
//
// registryDB is the connection migration 000055 created the tables on.
//
// It runs on every boot, not once. Steady state is three SELECTs and no writes:
// it confirms membership facts identity has that registry does not, prunes rows
// for memberships identity no longer has, and leaves every role alone.
//
// It returns an error for STRUCTURAL failures -- tables that do not resolve, a
// query that fails -- and counts per-row problems into the report instead.
func ReconcileMemberRoles(ctx context.Context, identityDB, registryDB *sql.DB) (ReconcileReport, error) {
	var report ReconcileReport

	mirror := NewMemberRoleMirror(registryDB)
	if err := mirror.Verify(ctx); err != nil {
		return report, fmt.Errorf("registry role tables unusable: %w", err)
	}
	if err := verifyIdentitySource(ctx, identityDB); err != nil {
		return report, err
	}

	// 1. Role templates first: organization_member_roles.role_template_id has a
	//    real FK to registry_role_templates, so an assignment cannot be written
	//    before the template it names.
	// The template ids registry itself defines. This is what an adopted
	// assignment is validated against, and it replaces the source's list: a
	// membership naming a template REGISTRY does not have cannot be written,
	// because 000055's foreign key refuses it.
	live, err := readRegistryRoleTemplateIDs(ctx, registryDB)
	if err != nil {
		return report, err
	}
	report.RegistryRoleTemplates = len(live)

	sourceMembers, unparseable, err := readEffectiveMemberships(ctx, identityDB)
	if err != nil {
		return report, err
	}
	report.SourceMemberships = len(sourceMembers)
	report.UnparseableRows = unparseable

	// The mirror as it stands, read ONCE. Everything below is a diff against
	// this map rather than a statement per row: the reconcile runs on every
	// boot, and a deployment with a hundred thousand memberships would
	// otherwise pay a hundred thousand round trips to discover nothing changed.
	mirrored, err := readMirroredMemberships(ctx, registryDB)
	if err != nil {
		return report, err
	}

	// THE ONE-TIME ADOPTION. Empty mirror, non-empty source: this deployment has
	// just gained the tables, and confirming facts alone would leave every
	// principal with no role. See the header for why this is not an exception to
	// "registry decides".
	if len(mirrored) == 0 && len(sourceMembers) > 0 {
		adopted, orphaned, err := adoptSourceAssignments(ctx, mirror, sourceMembers, live)
		if err != nil {
			return report, err
		}
		report.MembershipsAdopted = adopted
		report.OrphanedRoleRefs = orphaned
		slog.WarnContext(ctx, "registry's role assignments were adopted from the identity source, once",
			"adopted", adopted, "orphaned_role_refs", orphaned,
			"why", "organization_member_roles was empty, so this deployment has no role decisions of its own yet",
			"note", "in a coupled deployment these include roles the sibling application granted; "+
				"every boot after this one, registry decides its own roles and the source is read for "+
				"membership facts alone")
	} else {
		// STEADY STATE: facts in, opinions out. A membership identity has that
		// registry has no row for is confirmed with NO role.
		for key := range sourceMembers {
			if _, ok := mirrored[key]; ok {
				// Registry already has a decision for this pair. It is
				// registry's, and identity does not get to change it -- this is
				// the line the sibling's grants used to cross.
				continue
			}
			if err := mirror.ConfirmMembership(ctx, key.orgID, key.userID); err != nil {
				return report, fmt.Errorf("confirm membership (%s, %s): %w", key.orgID, key.userID, err)
			}
			report.MembershipsConfirmed++
		}
	}

	// 3. Remove mirrored rows the source no longer has. Membership is still
	//    identity's fact, so a membership it no longer has confers nothing here.
	//    Without this the mirror only ever grows, and a deprovision leaves
	//    authority behind -- the one divergence direction that GRANTS.
	for key := range mirrored {
		if _, ok := sourceMembers[key]; ok {
			continue
		}
		if err := mirror.ClearMember(ctx, key.orgID, key.userID); err != nil {
			return report, fmt.Errorf("prune mirrored membership (%s, %s): %w", key.orgID, key.userID, err)
		}
		report.MembershipsRemoved++
	}

	// 4. Role templates last, so a template deleted at the source cannot null a
	//    mirrored assignment that step 2 has just written.
	return report, nil
}

// adoptSourceAssignments copies the source's role assignments into the mirror,
// for the ONE boot on which registry has no role decisions of its own.
//
// SEPARATE FUNCTION, and deliberately the only place AssignRole is reached from
// this file -- a class guard requires that (member_role_adoption_class_test.go).
// Inlining it would put an unconditional-looking `AssignRole` in the reconcile
// body, which is exactly the shape #1056 removed and exactly what a future
// reader would restore by moving one `if`.
//
// The orphan handling is the old behaviour, kept: a membership naming a template
// the source does not have is adopted with NO role rather than aborting the
// whole reconcile on 000055's foreign key.
func adoptSourceAssignments(ctx context.Context, mirror *MemberRoleMirror, source map[memberKey]*string, live map[uuid.UUID]bool) (adopted, orphaned int, err error) {
	for key, roleTemplateID := range source {
		effective := roleTemplateID
		if effective != nil {
			id, parseErr := uuid.Parse(*effective)
			if parseErr != nil || !live[id] {
				slog.WarnContext(ctx, "membership names a role template registry does not define; adopting it with no role",
					"organization_id", key.orgID, "user_id", key.userID, "role_template_id", *effective)
				orphaned++
				effective = nil
			}
		}
		if err := mirror.AssignRole(ctx, key.orgID, key.userID, effective); err != nil {
			return adopted, orphaned, fmt.Errorf("adopt membership (%s, %s): %w", key.orgID, key.userID, err)
		}
		adopted++
	}
	return adopted, orphaned, nil
}

// readRegistryRoleTemplateIDs reads the template ids REGISTRY defines.
//
// Replaces the list the reconcile used to take from the shared schema (#1057).
// Read AFTER registry's own seed has run, which is why the seed moved ahead of
// the reconcile: on a fresh install this table is empty until the seed writes
// it, and an adoption validating against an empty set mirrors every assignment
// as "no role".
func readRegistryRoleTemplateIDs(ctx context.Context, registryDB *sql.DB) (map[uuid.UUID]bool, error) {
	rows, err := registryDB.QueryContext(ctx, `SELECT id FROM registry_role_templates`)
	if err != nil {
		return nil, fmt.Errorf("read registry's own role templates: %w", err)
	}
	defer rows.Close()
	live := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan a registry role template id: %w", err)
		}
		live[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read registry's own role templates: %w", err)
	}
	return live, nil
}

// identitySourceTables are the tables the reconcile reads through the identity
// connection. Named once so the probe and its failure message agree.
// `role_templates` came off this list in #1057: the reconcile no longer reads
// the shared templates at all, so probing for them would refuse to boot over a
// table nothing here touches. The identity-side SEED still writes them, and its
// own failure is reported where it happens.
var identitySourceTables = []string{"organization_members"}

// verifyIdentitySource refuses to reconcile from a connection that does not
// resolve the tables the application reads roles from.
//
// Refusing loudly is the point. A reconcile that quietly found nothing would
// leave the mirror empty and report success, and the next phase would cut reads
// over onto an empty table -- which revokes everybody's access at once. An
// empty source and an unreachable source are indistinguishable from the row
// count alone, so they are distinguished here instead.
func verifyIdentitySource(ctx context.Context, identityDB *sql.DB) error {
	for _, table := range identitySourceTables {
		var resolved sql.NullString
		if err := identityDB.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&resolved); err != nil {
			return fmt.Errorf("probe effective %s: %w", table, err)
		}
		if !resolved.Valid {
			return fmt.Errorf("effective %s does not resolve on the identity connection; "+
				"refusing to reconcile registry's role tables from a source that is not there", table)
		}
		slog.DebugContext(ctx, "reconcile source resolved", "table", table, "resolved_to", resolved.String)
	}
	return nil
}

// readEffectiveMemberships loads every membership the identity connection can
// see, keyed by (organization_id, user_id).
//
// Loaded into memory rather than streamed into a set-based statement because
// the source and the destination may be different DATABASES
// (TFR_IDENTITY_DATABASE_*), where no single statement can join them. One boot,
// one pass, and a membership row is three identifiers.
func readEffectiveMemberships(ctx context.Context, identityDB *sql.DB) (map[memberKey]*string, int, error) {
	rows, err := identityDB.QueryContext(ctx,
		`SELECT organization_id, user_id, role_template_id FROM organization_members`)
	if err != nil {
		return nil, 0, fmt.Errorf("read effective memberships: %w", err)
	}
	defer rows.Close()

	members := map[memberKey]*string{}
	var unparseable int
	for rows.Next() {
		var orgID, userID string
		var roleTemplateID sql.NullString
		if err := rows.Scan(&orgID, &userID, &roleTemplateID); err != nil {
			return nil, 0, fmt.Errorf("scan effective membership: %w", err)
		}
		if _, err := uuid.Parse(orgID); err != nil {
			unparseable++
			slog.WarnContext(ctx, "skipping membership with a non-UUID organization_id", "organization_id", orgID)
			continue
		}
		if _, err := uuid.Parse(userID); err != nil {
			unparseable++
			slog.WarnContext(ctx, "skipping membership with a non-UUID user_id", "user_id", userID)
			continue
		}
		var role *string
		if roleTemplateID.Valid {
			v := roleTemplateID.String
			role = &v
		}
		members[memberKey{orgID: orgID, userID: userID}] = role
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read effective memberships: %w", err)
	}
	return members, unparseable, nil
}

// readMirroredMemberships loads registry's own assignments, keyed the same way
// as the source, so the reconcile can diff the two sets in memory.
func readMirroredMemberships(ctx context.Context, registryDB *sql.DB) (map[memberKey]*string, error) {
	rows, err := registryDB.QueryContext(ctx,
		`SELECT organization_id, user_id, role_template_id FROM organization_member_roles`)
	if err != nil {
		return nil, fmt.Errorf("read mirrored memberships: %w", err)
	}
	defer rows.Close()

	out := map[memberKey]*string{}
	for rows.Next() {
		var key memberKey
		var role sql.NullString
		if err := rows.Scan(&key.orgID, &key.userID, &role); err != nil {
			return nil, fmt.Errorf("scan mirrored membership: %w", err)
		}
		if role.Valid {
			v := role.String
			out[key] = &v
		} else {
			out[key] = nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read mirrored memberships: %w", err)
	}
	return out, nil
}

// sameRole compares two optional role-template ids by VALUE.
//
// Comparing the *pointers* would report every row as changed and undo the point
// of the diff, and treating nil and "" alike would hide a real difference: a
// membership with no role and a membership whose role is an empty string are
// not the same row.
func sameRole(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// readMirroredRoleTemplateIDs loads the ids registry's own template table holds.
//
// Reading is a separate step from deleting, exactly as it is for memberships:
// the deletes must not be issued while this result set is still open, since on a
// small pool the writing statement would wait for a connection the scan is
// holding. Returning the ids first makes that ordering structural instead of a
// hand-placed Close nobody can see the reason for.
func readMirroredRoleTemplateIDs(ctx context.Context, registryDB *sql.DB) ([]uuid.UUID, error) {
	rows, err := registryDB.QueryContext(ctx, `SELECT id FROM registry_role_templates`)
	if err != nil {
		return nil, fmt.Errorf("read mirrored role templates: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan mirrored role template: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read mirrored role templates: %w", err)
	}
	return ids, nil
}

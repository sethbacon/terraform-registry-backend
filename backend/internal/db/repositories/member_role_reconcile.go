// member_role_reconcile.go derives registry's own authorization tables from
// whatever registry resolves role reads through TODAY
// (sethbacon/terraform-suite-identity#206, migration 000055).
//
// This is the backfill. It is Go rather than SQL inside the migration for one
// reason, spelled out at length in 000055_registry_role_tables.up.sql: the
// EFFECTIVE source is chosen at process start by the identity pool's
// search_path and by which database that pool dials, and neither is visible to
// a migration running on the registry connection. Reading through the very
// *sql.DB the application resolves `organization_members` and `role_templates`
// through makes the effective source identical BY CONSTRUCTION -- there is
// nothing to infer and nothing to get wrong.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"
)

// ReconcileReport is what one reconcile did, for the boot log.
type ReconcileReport struct {
	// SourceMemberships / SourceRoleTemplates are the row counts read from the
	// effective identity source.
	SourceMemberships   int
	SourceRoleTemplates int
	// MembershipsWritten / RoleTemplatesWritten count rows upserted into
	// registry's tables. Steady state is 0 for both: the upserts only fire when
	// something actually differs, so a quiet boot writes nothing.
	MembershipsWritten   int
	RoleTemplatesWritten int
	// MembershipsRemoved / RoleTemplatesRemoved count mirrored rows deleted
	// because the source no longer has them.
	MembershipsRemoved   int
	RoleTemplatesRemoved int
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
		slog.Int("source_role_templates", r.SourceRoleTemplates),
		slog.Int("memberships_written", r.MembershipsWritten),
		slog.Int("role_templates_written", r.RoleTemplatesWritten),
		slog.Int("memberships_removed", r.MembershipsRemoved),
		slog.Int("role_templates_removed", r.RoleTemplatesRemoved),
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
// It runs on every boot, not once. Re-deriving is cheap when nothing changed
// (the upserts are no-ops), it repairs a mirror that a transient write failure
// left behind, and it converges a deployment that upgraded before the tables
// existed. That standing behaviour is correct only while the identity tables
// are still authoritative; the read cutover must remove this call, because
// after it the mirror is the source and re-deriving it from identity would
// overwrite the app's own decisions.
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
	templates, err := identitystore.NewRoleTemplateRepository(identityDB).ListRoleTemplates(ctx)
	if err != nil {
		return report, fmt.Errorf("read effective role templates: %w", err)
	}
	report.SourceRoleTemplates = len(templates)
	live := make(map[uuid.UUID]bool, len(templates))
	for _, t := range templates {
		live[t.ID] = true
		if err := mirror.UpsertRoleTemplate(ctx, t); err != nil {
			return report, fmt.Errorf("mirror role template %q: %w", t.Name, err)
		}
		report.RoleTemplatesWritten++
	}

	// 2. Memberships. Bare table name, so the identity pool's search_path picks
	//    the effective one -- exactly as every read in the shared store does.
	sourceMembers, unparseable, err := readEffectiveMemberships(ctx, identityDB)
	if err != nil {
		return report, err
	}
	report.SourceMemberships = len(sourceMembers)
	report.UnparseableRows = unparseable

	// The mirror as it stands, read ONCE. Everything below is a diff against
	// this map rather than an unconditional upsert per row: the reconcile runs
	// on every boot, and a deployment with a hundred thousand memberships would
	// otherwise pay a hundred thousand round trips to discover that nothing
	// changed. Steady state is now two SELECTs and no writes at all.
	mirrored, err := readMirroredMemberships(ctx, registryDB)
	if err != nil {
		return report, err
	}

	for key, roleTemplateID := range sourceMembers {
		effective := roleTemplateID
		if effective != nil {
			id, parseErr := uuid.Parse(*effective)
			if parseErr != nil || !live[id] {
				// The membership names a template that is not in the source's
				// role_templates. Writing it would violate 000055's FK and
				// abort the whole reconcile over one bad row, so the assignment
				// is mirrored as "no role" and counted. It is reported, not
				// repaired: deciding what a dangling role assignment should
				// become is an operator's call, and the divergence query in
				// docs/identity-schema.md is how they find them.
				slog.WarnContext(ctx, "membership names a role template that does not exist; mirroring it with no role",
					"organization_id", key.orgID, "user_id", key.userID, "role_template_id", *effective)
				report.OrphanedRoleRefs++
				effective = nil
			}
		}
		if current, ok := mirrored[key]; ok && sameRole(current, effective) {
			continue
		}
		if err := mirror.AssignRole(ctx, key.orgID, key.userID, effective); err != nil {
			return report, fmt.Errorf("mirror membership (%s, %s): %w", key.orgID, key.userID, err)
		}
		report.MembershipsWritten++
	}

	// 3. Remove mirrored rows the source no longer has. Without this the mirror
	//    only ever grows, and a deprovision whose mirror write failed would
	//    leave authority behind in the table the read cutover switches onto --
	//    the one divergence direction that GRANTS rather than withholds.
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
	removedTemplates, err := pruneMirroredRoleTemplates(ctx, registryDB, mirror, live)
	if err != nil {
		return report, err
	}
	report.RoleTemplatesRemoved = removedTemplates

	return report, nil
}

// identitySourceTables are the tables the reconcile reads through the identity
// connection. Named once so the probe and its failure message agree.
var identitySourceTables = []string{"organization_members", "role_templates"}

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

// pruneMirroredRoleTemplates deletes mirrored templates with no source row.
func pruneMirroredRoleTemplates(ctx context.Context, registryDB *sql.DB, mirror *MemberRoleMirror, live map[uuid.UUID]bool) (int, error) {
	ids, err := readMirroredRoleTemplateIDs(ctx, registryDB)
	if err != nil {
		return 0, err
	}
	var removed int
	for _, id := range ids {
		if live[id] {
			continue
		}
		if err := mirror.DeleteRoleTemplate(ctx, id); err != nil {
			return 0, fmt.Errorf("prune mirrored role template %s: %w", id, err)
		}
		removed++
	}
	return removed, nil
}

package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// systemRoleTemplateExecer is the minimal database surface SeedSystemRoleTemplates
// needs. *sql.DB satisfies it; tests substitute a fake.
type systemRoleTemplateExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// upsertSystemRoleTemplateSQL builds the idempotent "insert or update by name"
// statement for a role-template table. The conflict update only fires when
// something actually changed, so steady-state restarts perform no writes.
//
// Parameterised by table because there are now TWO of them and their bodies
// must not drift apart: registry's own `registry_role_templates`, which is what
// registry READS since the cutover, and the shared `role_templates`, which the
// state manager and the rollback path still read. A table name cannot be a bind
// parameter, so it is interpolated -- from the two constants below and nothing
// else, never from input.
//
// Both deliberately bypass the identity module's RoleTemplateRepository.Update,
// which refuses to modify is_system rows (`WHERE is_system = false`). Seeding the
// system role→scope mapping is a privileged bootstrap write owned by the app, not
// a user-facing edit, so it must reach the protected system rows directly.
//
// ON CONFLICT (name), not (id), and that is what makes the ordering in
// internal/api/router.go work: the reconcile has already inserted each template
// under the id the IDENTITY copy carries, and conflicting on the name updates
// that row in place rather than creating a second one under a fresh uuid. The
// id is therefore still the one every mirrored membership names.
func upsertSystemRoleTemplateSQL(table string) string {
	return `
INSERT INTO ` + table + ` (id, name, display_name, description, scopes, is_system, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, true, NOW(), NOW())
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description  = EXCLUDED.description,
    scopes       = EXCLUDED.scopes,
    is_system    = true,
    updated_at   = NOW()
WHERE ` + table + `.scopes       IS DISTINCT FROM EXCLUDED.scopes
   OR ` + table + `.display_name IS DISTINCT FROM EXCLUDED.display_name
   OR ` + table + `.description  IS DISTINCT FROM EXCLUDED.description
   OR ` + table + `.is_system    IS DISTINCT FROM true`

}

// The two tables, spelled once each.
const (
	registryRoleTemplateTable = "registry_role_templates"
	sharedRoleTemplateTable   = "role_templates"
)

// SeedSystemRoleTemplates idempotently upserts the given system role templates,
// by name, into REGISTRY'S OWN `registry_role_templates`
// (sethbacon/terraform-suite-identity#206, phase 3b).
//
// That table is what every authorization decision now reads, so registry's
// role→scope mapping has to be written there by registry. Before the read
// cutover this function targeted the shared `role_templates`, which is the table
// two applications collide on and which `TFR_SUITE_ROLE_SEED_OWNER` exists to
// arbitrate; registry's own table has no such contention, because no other
// application writes it.
//
// IT MUST RUN AFTER ReconcileMemberRoles, not before. The reconcile derives
// registry's table from the identity source, including the template scopes; a
// seed that ran first would be overwritten by it on the same boot. router.go
// orders the two and says so.
//
// The connection's search_path determines which schema is written, exactly as
// before.
func SeedSystemRoleTemplates(ctx context.Context, db systemRoleTemplateExecer, templates []models.RoleTemplate) error {
	return seedRoleTemplates(ctx, db, registryRoleTemplateTable, templates)
}

// SeedSharedIdentityRoleTemplates idempotently upserts the same templates into
// the SHARED `role_templates`.
//
// Registry no longer reads that table, and it keeps writing it for two reasons
// that both outlive this phase:
//
//   - The state manager still reads it. It has not done its own phase 3, so
//     removing registry's seed here would change another application's roles
//     from a registry-side change.
//   - It is the rollback surface. The rollback for a bad read cutover is to
//     deploy the previous image, and that image reads this table; it has to
//     still be current when it does.
//
// This is the call `TFR_SUITE_ROLE_SEED_OWNER` gates, and the only one -- see
// the note on the flag in docs/configuration.md for why it cannot retire until
// phase 4.
func SeedSharedIdentityRoleTemplates(ctx context.Context, db systemRoleTemplateExecer, templates []models.RoleTemplate) error {
	return seedRoleTemplates(ctx, db, sharedRoleTemplateTable, templates)
}

// seedRoleTemplates is the shared body of the two seeds above.
func seedRoleTemplates(ctx context.Context, db systemRoleTemplateExecer, table string, templates []models.RoleTemplate) error {
	query := upsertSystemRoleTemplateSQL(table)
	for i := range templates {
		t := templates[i]
		scopesJSON, err := json.Marshal(t.Scopes)
		if err != nil {
			return fmt.Errorf("marshal scopes for role template %q: %w", t.Name, err)
		}
		if _, err := db.ExecContext(ctx, query,
			t.Name, t.DisplayName, t.Description, scopesJSON); err != nil {
			return fmt.Errorf("upsert role template %q into %s: %w", t.Name, table, err)
		}
	}
	return nil
}

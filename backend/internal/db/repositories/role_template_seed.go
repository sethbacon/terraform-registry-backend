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

// upsertSystemRoleTemplateQuery idempotently inserts or updates a system role
// template by its (unique) name. The conflict update only fires when something
// actually changed, so steady-state restarts perform no writes.
//
// This deliberately bypasses the identity module's RoleTemplateRepository.Update,
// which refuses to modify is_system rows (`WHERE is_system = false`). Seeding the
// system role→scope mapping is a privileged bootstrap write owned by the app, not
// a user-facing edit, so it must reach the protected system rows directly.
const upsertSystemRoleTemplateQuery = `
INSERT INTO role_templates (id, name, display_name, description, scopes, is_system, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, true, NOW(), NOW())
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description  = EXCLUDED.description,
    scopes       = EXCLUDED.scopes,
    is_system    = true,
    updated_at   = NOW()
WHERE role_templates.scopes       IS DISTINCT FROM EXCLUDED.scopes
   OR role_templates.display_name IS DISTINCT FROM EXCLUDED.display_name
   OR role_templates.description  IS DISTINCT FROM EXCLUDED.description
   OR role_templates.is_system    IS DISTINCT FROM true`

// SeedSystemRoleTemplates idempotently upserts the given system role templates by
// name against the supplied connection.
//
// It is used under the identity-schema cutover (TFR_IDENTITY_SCHEMA_ENABLED): the
// shared identity module seeds these roles with identity-core scopes only, so the
// registry layers its own domain scopes onto them here ("identity-core +
// app-extended"). In the default public-schema configuration the role templates
// are already seeded with the full app scopes by migration 000001, so this is not
// invoked.
//
// The connection's search_path determines which schema is written: under cutover
// it resolves the unqualified role_templates to the shared identity schema.
func SeedSystemRoleTemplates(ctx context.Context, db systemRoleTemplateExecer, templates []models.RoleTemplate) error {
	for i := range templates {
		t := templates[i]
		scopesJSON, err := json.Marshal(t.Scopes)
		if err != nil {
			return fmt.Errorf("marshal scopes for role template %q: %w", t.Name, err)
		}
		if _, err := db.ExecContext(ctx, upsertSystemRoleTemplateQuery,
			t.Name, t.DisplayName, t.Description, scopesJSON); err != nil {
			return fmt.Errorf("upsert role template %q: %w", t.Name, err)
		}
	}
	return nil
}

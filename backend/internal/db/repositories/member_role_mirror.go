// member_role_mirror.go writes registry's own per-app authorization tables --
// `registry_role_templates` and `organization_member_roles`, migration 000055.
//
// Design: sethbacon/terraform-suite-identity#206. Identity is shared,
// authorization is per-app. `organization_members` becomes the membership FACT
// and the role a member holds IN REGISTRY moves here.
//
// NOTHING READS THESE TABLES YET. This file exists so that the read cutover has
// a populated, continuously reconciled copy to switch onto. Every write below
// happens AFTER the authoritative write to the existing location has succeeded,
// and a failure here is logged rather than returned -- see mirrorFailed.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ErrMirrorUnreachable is returned by (*MemberRoleMirror).Verify when the
// connection it was built on does not resolve registry's own authorization
// tables.
//
// The only supported topology where this happens is a SEPARATE IDENTITY
// DATABASE (TFR_IDENTITY_DATABASE_* pointing at another database with
// TFR_IDENTITY_SCHEMA_ENABLED=true): migration 000055 creates these tables on
// REGISTRY's connection, so an identity pool dialled at a different database
// cannot see them. It is a sentinel rather than a bare error because the
// startup check has to be able to say WHICH failure it hit -- "the tables are
// not there" is an operator action, any other error is an outage.
var ErrMirrorUnreachable = errors.New("registry role tables are not reachable on this connection")

// MemberRoleMirror writes registry's own copy of the authorization data that
// currently lives in the identity tables.
//
// It deliberately exposes no reads beyond Verify. A read method here would be
// the first step of the cutover, and the cutover is a separate, separately
// reviewable change; leaving the type write-only makes "nothing observable
// changes" checkable by looking at the type rather than at every caller.
type MemberRoleMirror struct {
	db *sql.DB
}

// NewMemberRoleMirror builds a mirror over the given connection.
func NewMemberRoleMirror(db *sql.DB) *MemberRoleMirror {
	return &MemberRoleMirror{db: db}
}

// mirrorTables are the tables Verify probes. Named once so the startup check
// and the guard tests agree on what "the mirror" is.
var mirrorTables = []string{"registry_role_templates", "organization_member_roles"}

// Verify reports whether this connection resolves registry's own authorization
// tables, returning ErrMirrorUnreachable when it does not.
//
// to_regclass respects search_path, so this answers the question that actually
// matters -- "will the statements below resolve to something?" -- rather than
// "does a table of this name exist in some schema". It is the same shape as the
// library's carrier/outbox VerifyTable probes NewRouter already runs, and for
// the same reason: a mirror that silently writes nowhere is worse than one that
// refuses at boot, because the divergence is only discovered at the cutover.
func (m *MemberRoleMirror) Verify(ctx context.Context) error {
	for _, table := range mirrorTables {
		var resolved sql.NullString
		if err := m.db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&resolved); err != nil {
			return fmt.Errorf("probe %s: %w", table, err)
		}
		if !resolved.Valid {
			return fmt.Errorf("%w: %s does not resolve on this connection", ErrMirrorUnreachable, table)
		}
	}
	return nil
}

// AssignRole records the role a member holds in registry, creating the row if
// this is a new membership.
//
// roleTemplateID may be nil: a membership that carries no role is mirrored as a
// row with a NULL role_template_id, NOT as an absent row. Migration 000055
// explains why -- a dual-write phase must be able to tell "no role here" apart
// from "not mirrored yet", and an absent row means both.
func (m *MemberRoleMirror) AssignRole(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO organization_member_roles (organization_id, user_id, role_template_id, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (organization_id, user_id) DO UPDATE
		   SET role_template_id = EXCLUDED.role_template_id,
		       updated_at       = NOW()
		 WHERE organization_member_roles.role_template_id IS DISTINCT FROM EXCLUDED.role_template_id
	`, orgID, userID, roleTemplateID)
	if err != nil {
		return fmt.Errorf("mirror role assignment for (%s, %s): %w", orgID, userID, err)
	}
	return nil
}

// ClearMember drops one member's registry role assignment.
func (m *MemberRoleMirror) ClearMember(ctx context.Context, orgID, userID string) error {
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID)
	if err != nil {
		return fmt.Errorf("mirror membership removal for (%s, %s): %w", orgID, userID, err)
	}
	return nil
}

// ClearUserEverywhere drops every registry role assignment a user holds,
// in every organization.
//
// Separate from ClearMember because the two callers are different in kind: the
// scoped sweep (RemoveAllMembershipsForUser) knows exactly which organizations
// it emptied and clears those, while the GDPR erasure removes the user's
// memberships with no tenant predicate at all and must do the same here or
// leave the erased subject's authorization behind.
func (m *MemberRoleMirror) ClearUserEverywhere(ctx context.Context, userID string) error {
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM organization_member_roles WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("mirror membership sweep for user %s: %w", userID, err)
	}
	return nil
}

// UpsertRoleTemplate records a role template in registry's own table, keyed by
// the SAME id the source row carries.
//
// Sharing the id is what lets `organization_member_roles.role_template_id` hold
// the value the source membership holds, so the two copies can be compared
// directly by the divergence query in docs/identity-schema.md rather than
// joined through names.
func (m *MemberRoleMirror) UpsertRoleTemplate(ctx context.Context, t *models.RoleTemplate) error {
	scopes, err := json.Marshal(t.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes for role template %q: %w", t.Name, err)
	}
	if t.Scopes == nil {
		// json.Marshal(nil slice) is "null", which is a legal jsonb value but
		// not a legal scope list; every reader expects an array.
		scopes = []byte(`[]`)
	}
	_, err = m.db.ExecContext(ctx, `
		INSERT INTO registry_role_templates (id, name, display_name, description, scopes, is_system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE
		   SET name         = EXCLUDED.name,
		       display_name = EXCLUDED.display_name,
		       description  = EXCLUDED.description,
		       scopes       = EXCLUDED.scopes,
		       is_system    = EXCLUDED.is_system,
		       updated_at   = NOW()
		 WHERE registry_role_templates.name         IS DISTINCT FROM EXCLUDED.name
		    OR registry_role_templates.display_name IS DISTINCT FROM EXCLUDED.display_name
		    OR registry_role_templates.description  IS DISTINCT FROM EXCLUDED.description
		    OR registry_role_templates.scopes       IS DISTINCT FROM EXCLUDED.scopes
		    OR registry_role_templates.is_system    IS DISTINCT FROM EXCLUDED.is_system
	`, t.ID, t.Name, t.DisplayName, t.Description, scopes, t.IsSystem)
	if err != nil {
		return fmt.Errorf("mirror role template %q: %w", t.Name, err)
	}
	return nil
}

// DeleteRoleTemplate drops a role template from registry's own table.
//
// The FK on organization_member_roles.role_template_id is ON DELETE SET NULL,
// so this clears the assignment on every mirrored membership that held it --
// exactly what 000001_initial_schema's FK does on the source side when a
// template is deleted there. That symmetry is deliberate: it is the one role
// change in the product that no statement naming a membership performs.
func (m *MemberRoleMirror) DeleteRoleTemplate(ctx context.Context, id uuid.UUID) error {
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM registry_role_templates WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("mirror role template deletion %s: %w", id, err)
	}
	return nil
}

// mirrorFailed is the single place a mirror error is absorbed.
//
// It is absorbed rather than returned ON PURPOSE, and the reasoning is the
// whole safety argument for this phase:
//
//   - The authoritative write has already committed. Reads still come from the
//     existing location, so the caller's request succeeded in every sense the
//     caller can observe. Turning a mirror failure into a 500 would make this
//     phase change behaviour, which is precisely what it must not do -- and it
//     would do so on the privilege paths, the worst place to introduce a new
//     failure mode.
//   - Divergence is not left to be discovered at the cutover. It is logged at
//     ERROR with the identifiers needed to find the row, the startup reconcile
//     re-derives the whole mirror from the authoritative source on the next
//     boot, and the divergence query in docs/identity-schema.md must return
//     zero rows before the read cutover ships. That query, not this function,
//     is the gate.
func mirrorFailed(ctx context.Context, op string, err error, attrs ...any) {
	args := []any{"operation", op, "error", err}
	args = append(args, attrs...)
	args = append(args,
		"impact", "registry's own authorization tables have diverged from the identity tables; "+
			"the request itself succeeded. Run the divergence query in docs/identity-schema.md, "+
			"and do not enable the read cutover while it returns rows.")
	slog.ErrorContext(ctx, "role-assignment mirror write failed", args...)
}

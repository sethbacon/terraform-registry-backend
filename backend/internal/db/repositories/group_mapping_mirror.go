// group_mapping_mirror.go writes registry's own per-app group-mapping table --
// `group_mappings`, migration 000059.
//
// Design: sethbacon/terraform-suite-identity#206, phase 2. Identity is shared,
// authorization is per-app. An IdP group mapping is authorization policy --
// "members of IdP group G get THIS APP's role R in organization O" -- and it
// moves into registry's own schema, next to the role tables 000055 created.
//
// The authoritative store is still the `group_mappings` JSON list inside
// `oidc_config.extra_config` on the identity connection, and every read still
// comes from there (resolveGroupMappingConfig in internal/api/admin/auth.go).
// NOTHING READS THIS TABLE YET. This file exists so that the read cutover has
// a populated, continuously reconciled copy to switch onto. Every write below
// happens AFTER the authoritative write has succeeded, and a failure here is
// logged rather than returned -- see groupMappingMirrorFailed.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

// GroupMappingMirror writes registry's own copy of the group->role mappings
// that currently live in oidc_config.extra_config.
//
// It deliberately exposes no reads beyond Verify, for the same reason
// MemberRoleMirror does not: a read method here would be the first step of the
// cutover, and the cutover is a separate, separately reviewable change.
// Leaving the type write-only makes "nothing observable changes" checkable by
// looking at the type rather than at every caller.
type GroupMappingMirror struct {
	db *sql.DB
}

// NewGroupMappingMirror builds a mirror over the given connection -- the
// REGISTRY connection, the one migration 000059 created the table on.
func NewGroupMappingMirror(db *sql.DB) *GroupMappingMirror {
	return &GroupMappingMirror{db: db}
}

// groupMappingMirrorTables are the tables Verify probes. registry_role_templates
// is included because every insert below resolves the mapped role name against
// it; a connection that resolves one but not the other is misconfigured.
var groupMappingMirrorTables = []string{"group_mappings", "registry_role_templates"}

// Verify reports whether this connection resolves registry's own group-mapping
// table (and the role-template table its FK targets).
//
// Same shape as (*MemberRoleMirror).Verify and for the same reason: a mirror
// that silently writes nowhere is worse than one that refuses at boot, because
// the divergence is only discovered at the cutover.
func (m *GroupMappingMirror) Verify(ctx context.Context) error {
	for _, table := range groupMappingMirrorTables {
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

// ReplaceForConfig makes the mirrored rows for one oidc_config row equal the
// given ordered list, wholesale, in one transaction.
//
// Wholesale rather than diffed ON PURPOSE: the source is an ordered JSON list
// whose positions shift on any edit, the list is small (it is typed into an
// admin form), and a partial update that got the order wrong would corrupt the
// one property the cutover cannot reconstruct -- first-match-wins resolution
// order (terraform-suite-identity#269).
//
// Each row's role_template_id is re-resolved from the mapped role name against
// registry_role_templates AT WRITE TIME, inside the same statement. NULL when
// the name does not resolve -- a mapping naming a missing template is a legal,
// faithful row (it confers nothing at login today; see guardProvisionableRole),
// and the boot reconcile re-resolves it once the template appears.
//
// An empty (or nil) list deletes the config's rows: "this config has no
// mappings" is represented by no rows, exactly like the source list being
// absent from extra_config.
func (m *GroupMappingMirror) ReplaceForConfig(ctx context.Context, configID uuid.UUID, mappings []identitymodels.OIDCGroupMapping) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mirror replace for oidc config %s: %w", configID, err)
	}
	defer tx.Rollback() // nolint:errcheck

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_mappings WHERE oidc_config_id = $1`, configID); err != nil {
		return fmt.Errorf("clear mirrored mappings for oidc config %s: %w", configID, err)
	}
	for i, mapping := range mappings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO group_mappings
			       (oidc_config_id, position, group_name, organization_name, role_template_name, role_template_id)
			VALUES ($1, $2, $3, $4, $5,
			        (SELECT id FROM registry_role_templates WHERE name = $5))
		`, configID, i, mapping.Group, mapping.Organization, mapping.Role); err != nil {
			return fmt.Errorf("mirror mapping %d for oidc config %s: %w", i, configID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mirror replace for oidc config %s: %w", configID, err)
	}
	return nil
}

// ClearConfig drops every mirrored mapping row for one oidc_config row --
// the mirror half of deleting the config itself.
func (m *GroupMappingMirror) ClearConfig(ctx context.Context, configID uuid.UUID) error {
	if _, err := m.db.ExecContext(ctx,
		`DELETE FROM group_mappings WHERE oidc_config_id = $1`, configID); err != nil {
		return fmt.Errorf("mirror oidc config deletion %s: %w", configID, err)
	}
	return nil
}

// groupMappingsFromExtraConfig decodes the group-mapping list out of an
// oidc_config extra_config value -- USING THE LIBRARY'S OWN DECODER, so what
// the mirror writes is by construction what resolveGroupMappingConfig would
// read from the same bytes. A structurally wrong value (extra_config that is
// not an object, or a group_mappings key that is not a list) decodes to "no
// mappings" on the read path, so it decodes to "no mappings" here too.
func groupMappingsFromExtraConfig(extraConfig []byte) []identitymodels.OIDCGroupMapping {
	cfg := identitymodels.OIDCConfig{ExtraConfig: extraConfig}
	_, mappings, _ := cfg.GetGroupMappingConfig()
	return mappings
}

// groupMappingMirrorFailed is the single place a group-mapping mirror error is
// absorbed. Absorbed rather than returned ON PURPOSE, on the same safety
// argument as mirrorFailed: the authoritative write has already committed,
// reads still come from the existing location, so the caller's request
// succeeded in every sense the caller can observe -- and the boot reconcile
// re-derives this table from the authoritative source on the next boot. The
// group-mapping check in `role-drift` must report clean before the read
// cutover ships; that check, not this function, is the gate.
func groupMappingMirrorFailed(ctx context.Context, op string, err error, attrs ...any) {
	args := []any{"operation", op, "error", err}
	args = append(args, attrs...)
	args = append(args,
		"impact", "registry's own group_mappings table has diverged from oidc_config.extra_config; "+
			"the request itself succeeded. Restarting the backend repairs it; run `role-drift` "+
			"and do not enable the read cutover while it reports group-mapping drift.")
	slog.ErrorContext(ctx, "group-mapping mirror write failed", args...)
}

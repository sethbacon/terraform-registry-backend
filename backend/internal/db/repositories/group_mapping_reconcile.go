// group_mapping_reconcile.go derives registry's own group_mappings table from
// whatever registry resolves OIDC-config reads through TODAY
// (sethbacon/terraform-suite-identity#206, migration 000059).
//
// This is the backfill. It is Go rather than SQL inside the migration for the
// reason spelled out at length in 000059_group_mappings.up.sql (and before it
// in 000055): the EFFECTIVE source -- which schema, which database holds the
// live oidc_config rows -- is chosen at process start by the identity pool's
// search_path and dial target, and neither is visible to a migration running
// on the registry connection. Reading through the very *sql.DB the application
// resolves oidc_config through makes the effective source identical BY
// CONSTRUCTION.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

// GroupMappingReconcileReport is what one reconcile did, for the boot log.
type GroupMappingReconcileReport struct {
	// SourceConfigs / SourceMappings are what the effective identity source
	// holds: oidc_config rows seen, and mapping entries across all of them.
	SourceConfigs  int
	SourceMappings int
	// ConfigsRewritten counts configs whose mirrored rows were replaced because
	// they differed. Steady state is 0: an unchanged config is left alone, so a
	// quiet boot writes nothing.
	ConfigsRewritten int
	// ConfigsPruned counts mirrored config-row groups deleted because the
	// source no longer has the config.
	ConfigsPruned int
	// UnresolvedRoleRefs counts mappings whose role name resolves to no
	// registry_role_templates row. They are mirrored with a NULL
	// role_template_id rather than skipped -- a faithful copy of a mapping
	// that confers nothing at login today.
	UnresolvedRoleRefs int
	// UnparseableExtraConfigs counts oidc_config rows whose extra_config is not
	// a JSON object at all. The library's own decoder reads "no mappings" out
	// of such a row, so the mirror faithfully holds no rows for it; counted and
	// logged because the stored provider config being corrupt is worth an
	// operator's attention even though it is not divergence.
	UnparseableExtraConfigs int
}

// LogValue renders the report for slog without a field per counter.
func (r GroupMappingReconcileReport) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("source_configs", r.SourceConfigs),
		slog.Int("source_mappings", r.SourceMappings),
		slog.Int("configs_rewritten", r.ConfigsRewritten),
		slog.Int("configs_pruned", r.ConfigsPruned),
		slog.Int("unresolved_role_refs", r.UnresolvedRoleRefs),
		slog.Int("unparseable_extra_configs", r.UnparseableExtraConfigs),
	)
}

// mirroredGroupMapping is one row of registry's group_mappings table, in the
// shape the comparison below works on.
type mirroredGroupMapping struct {
	// Position is the row's stored position. For a wanted list it is the slice
	// index; for mirrored rows it is read back and COMPARED rather than assumed,
	// so a gap or duplicate the table should never contain still forces the
	// rewrite that repairs it.
	Position       int
	Group          string
	Organization   string
	RoleName       string
	RoleTemplateID *string
}

// ReconcileGroupMappings makes registry's own group_mappings table equal the
// effective identity source, and returns what it did.
//
// identityDB MUST be the connection the application resolves oidc_config reads
// through -- the same handle NewRouter hands the OIDC-config repository. That
// is the whole correctness argument: this function never decides which schema
// or database holds the live rows, it inherits that decision.
//
// registryDB is the connection migration 000059 created the table on.
//
// It runs on every boot, not once, for the same three reasons
// ReconcileMemberRoles does: re-deriving is cheap when nothing changed (an
// unchanged config is not touched), it repairs whatever a transient dual-write
// failure left behind, and it converges a deployment that upgraded before the
// table existed. That standing behaviour is correct only while
// oidc_config.extra_config is still authoritative; the read cutover must
// remove this call.
//
// It returns an error for STRUCTURAL failures -- tables that do not resolve, a
// query that fails -- and counts per-row problems into the report instead.
func ReconcileGroupMappings(ctx context.Context, identityDB, registryDB *sql.DB) (GroupMappingReconcileReport, error) {
	var report GroupMappingReconcileReport

	mirror := NewGroupMappingMirror(registryDB)
	if err := mirror.Verify(ctx); err != nil {
		return report, fmt.Errorf("registry group-mapping table unusable: %w", err)
	}
	if err := verifyGroupMappingSource(ctx, identityDB); err != nil {
		return report, err
	}

	// The role-name resolution the mirror rows should carry, read ONCE.
	// registry_role_templates is registry's own table on registryDB -- since
	// the phase-3b read cutover it is what login-time role resolution actually
	// consults, which makes it the right target for the derived id column.
	nameToID, err := registryRoleTemplateNames(ctx, registryDB)
	if err != nil {
		return report, err
	}

	sourceLists, unparseable, err := readEffectiveGroupMappings(ctx, identityDB)
	if err != nil {
		return report, err
	}
	report.SourceConfigs = len(sourceLists)
	report.UnparseableExtraConfigs = unparseable

	// The mirror as it stands, read ONCE; everything below is a diff against
	// this map, so a boot where nothing changed issues no writes at all.
	mirrored, err := readMirroredGroupMappings(ctx, registryDB)
	if err != nil {
		return report, err
	}

	for configID, mappings := range sourceLists {
		report.SourceMappings += len(mappings)
		want := make([]mirroredGroupMapping, len(mappings))
		for i, m := range mappings {
			var roleID *string
			if id, ok := nameToID[m.Role]; ok {
				idCopy := id
				roleID = &idCopy
			} else {
				report.UnresolvedRoleRefs++
			}
			want[i] = mirroredGroupMapping{Position: i, Group: m.Group, Organization: m.Organization, RoleName: m.Role, RoleTemplateID: roleID}
		}
		if sameGroupMappingList(mirrored[configID], want) {
			continue
		}
		if err := mirror.ReplaceForConfig(ctx, configID, mappings); err != nil {
			return report, fmt.Errorf("mirror group mappings for oidc config %s: %w", configID, err)
		}
		report.ConfigsRewritten++
	}

	// Prune mirrored rows for configs the source no longer has. Without this
	// the mirror only ever grows, and a config delete whose mirror write failed
	// would leave mapping policy behind in the table the read cutover switches
	// onto.
	for configID := range mirrored {
		if _, ok := sourceLists[configID]; ok {
			continue
		}
		if err := mirror.ClearConfig(ctx, configID); err != nil {
			return report, fmt.Errorf("prune mirrored group mappings for oidc config %s: %w", configID, err)
		}
		report.ConfigsPruned++
	}

	return report, nil
}

// verifyGroupMappingSource refuses to reconcile from a connection that does not
// resolve oidc_config.
//
// Refusing loudly is the point, same as verifyIdentitySource: an empty source
// and an unreachable source are indistinguishable from the row count alone,
// and a reconcile that quietly found nothing would empty the mirror.
func verifyGroupMappingSource(ctx context.Context, identityDB *sql.DB) error {
	var resolved sql.NullString
	if err := identityDB.QueryRowContext(ctx, `SELECT to_regclass('oidc_config')::text`).Scan(&resolved); err != nil {
		return fmt.Errorf("probe effective oidc_config: %w", err)
	}
	if !resolved.Valid {
		return fmt.Errorf("effective oidc_config does not resolve on the identity connection; " +
			"refusing to reconcile registry's group_mappings from a source that is not there")
	}
	slog.DebugContext(ctx, "group-mapping reconcile source resolved", "table", "oidc_config", "resolved_to", resolved.String)
	return nil
}

// registryRoleTemplateNames loads registry's own role-template name->id map.
func registryRoleTemplateNames(ctx context.Context, registryDB *sql.DB) (map[string]string, error) {
	rows, err := registryDB.QueryContext(ctx, `SELECT id, name FROM registry_role_templates`)
	if err != nil {
		return nil, fmt.Errorf("read registry role template names: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan registry role template: %w", err)
		}
		out[name] = id
	}
	return out, rows.Err()
}

// readEffectiveGroupMappings loads every oidc_config row's group-mapping list
// through the identity connection, keyed by config id.
//
// Bare table name, so the identity pool's search_path picks the effective row
// set -- exactly as every oidc_config read in the shared store does. Loaded
// into memory rather than joined because source and destination may be
// different DATABASES (TFR_IDENTITY_DATABASE_*).
func readEffectiveGroupMappings(ctx context.Context, identityDB *sql.DB) (map[uuid.UUID][]identitymodels.OIDCGroupMapping, int, error) {
	rows, err := identityDB.QueryContext(ctx,
		`SELECT id, COALESCE(extra_config, '{}'::jsonb) FROM oidc_config`)
	if err != nil {
		return nil, 0, fmt.Errorf("read effective oidc configs: %w", err)
	}
	defer rows.Close()

	out := map[uuid.UUID][]identitymodels.OIDCGroupMapping{}
	var unparseable int
	for rows.Next() {
		var id uuid.UUID
		var extra []byte
		if err := rows.Scan(&id, &extra); err != nil {
			return nil, 0, fmt.Errorf("scan effective oidc config: %w", err)
		}
		var probe map[string]json.RawMessage
		if len(extra) > 0 && json.Unmarshal(extra, &probe) != nil {
			unparseable++
			slog.WarnContext(ctx, "oidc_config.extra_config is not a JSON object; its group mappings read as none",
				"oidc_config_id", id.String())
		}
		out[id] = groupMappingsFromExtraConfig(extra)
	}
	return out, unparseable, rows.Err()
}

// readMirroredGroupMappings loads registry's group_mappings table, ordered,
// keyed by config id.
func readMirroredGroupMappings(ctx context.Context, registryDB *sql.DB) (map[uuid.UUID][]mirroredGroupMapping, error) {
	rows, err := registryDB.QueryContext(ctx, `
		SELECT oidc_config_id, position, group_name, organization_name, role_template_name, role_template_id
		  FROM group_mappings
		 ORDER BY oidc_config_id, position`)
	if err != nil {
		return nil, fmt.Errorf("read mirrored group mappings: %w", err)
	}
	defer rows.Close()

	out := map[uuid.UUID][]mirroredGroupMapping{}
	for rows.Next() {
		var configID uuid.UUID
		var row mirroredGroupMapping
		var roleID sql.NullString
		if err := rows.Scan(&configID, &row.Position, &row.Group, &row.Organization, &row.RoleName, &roleID); err != nil {
			return nil, fmt.Errorf("scan mirrored group mapping: %w", err)
		}
		if roleID.Valid {
			id := roleID.String
			row.RoleTemplateID = &id
		}
		out[configID] = append(out[configID], row)
	}
	return out, rows.Err()
}

// sameGroupMappingList reports whether the mirrored rows equal the wanted rows,
// field for field, in order.
func sameGroupMappingList(have, want []mirroredGroupMapping) bool {
	if len(have) != len(want) {
		return false
	}
	for i := range have {
		if have[i].Position != want[i].Position ||
			have[i].Group != want[i].Group ||
			have[i].Organization != want[i].Organization ||
			have[i].RoleName != want[i].RoleName ||
			!sameRole(have[i].RoleTemplateID, want[i].RoleTemplateID) {
			return false
		}
	}
	return true
}

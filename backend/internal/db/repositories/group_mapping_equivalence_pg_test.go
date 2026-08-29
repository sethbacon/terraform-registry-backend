package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// THE EQUIVALENCE PROOF for the group-mapping dual-write
// (sethbacon/terraform-suite-identity#206 phase 2, migration 000059), against
// real PostgreSQL and the real migrations.
//
// Everything else in this change argues that registry's own group_mappings
// table stays equal to the group-mapping lists in oidc_config.extra_config.
// This file DEMONSTRATES it: it writes through the REAL write path -- the
// repositories.OIDCConfigRepository wrapper, the same object both the setup
// wizard and PUT /admin/oidc/group-mapping hold -- and then compares the two
// copies row-for-row, both directly in SQL and through CheckGroupMappingDrift,
// the check `role-drift` runs against a live database.
//
// The falsification tests are the other half of the proof, and they are what
// make the rest of the file mean anything: each corrupts the mirror ONE way
// and asserts the comparison FAILS with the right kind -- a test that only
// ever sees agreement cannot distinguish "the two copies agree" from "the
// comparison is not looking at anything", and this repository has shipped
// guards that could not tell those apart. Each corruption is then repaired by
// ReconcileGroupMappings, the boot backfill, proving the repair path against
// every divergence class it claims to converge.
//
// These tests skip without TFR_TEST_DATABASE_URL and run in CI's
// postgres-tests job (issue #886), which fails if they skip.

// gmMigrationVersion is the migration that creates group_mappings.
const gmMigrationVersion = 59

// gmSeedTemplate creates one role template in the SOURCE table and reconciles
// it into registry_role_templates the way a boot does, returning its id.
func gmSeedTemplate(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	id := uuid.NewString()
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system)
	                 VALUES ($1, $2, $2, '["modules:read"]'::jsonb, false)`, id, name)
	if _, err := ReconcileMemberRoles(context.Background(), db, db); err != nil {
		t.Fatalf("reconcile member roles (template mirror): %v", err)
	}
	return id
}

// gmNewConfig builds a valid OIDCConfig whose extra_config carries the given
// mapping list, using the library's own encoder -- the same call the admin
// handler makes.
func gmNewConfig(t *testing.T, mappings []identitymodels.OIDCGroupMapping) *models.OIDCConfig {
	t.Helper()
	now := time.Now()
	cfg := &models.OIDCConfig{
		ID:                     uuid.New(),
		Name:                   "gm-eq-" + uuid.NewString()[:8],
		ProviderType:           "generic_oidc",
		IssuerURL:              "https://idp.example.com",
		ClientID:               "registry",
		ClientSecretCiphertext: "sealed",
		RedirectURL:            "https://registry.example.com/callback",
		Scopes:                 json.RawMessage(`["openid","email","profile"]`),
		IsActive:               true,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := cfg.SetGroupMappingConfig("groups", mappings, "viewer"); err != nil {
		t.Fatalf("SetGroupMappingConfig: %v", err)
	}
	return cfg
}

// gmMirrorRow is one group_mappings row as read back for comparison.
type gmMirrorRow struct {
	Position       int
	Group          string
	Organization   string
	RoleName       string
	RoleTemplateID sql.NullString
}

func gmReadMirror(t *testing.T, db *sql.DB, configID uuid.UUID) []gmMirrorRow {
	t.Helper()
	rows, err := db.Query(`SELECT position, group_name, organization_name, role_template_name, role_template_id
	                         FROM group_mappings WHERE oidc_config_id = $1 ORDER BY position`, configID)
	if err != nil {
		t.Fatalf("read mirror: %v", err)
	}
	defer rows.Close()
	var out []gmMirrorRow
	for rows.Next() {
		var r gmMirrorRow
		if err := rows.Scan(&r.Position, &r.Group, &r.Organization, &r.RoleName, &r.RoleTemplateID); err != nil {
			t.Fatalf("scan mirror: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// gmRequireEqual compares the mirror rows for one config against the SOURCE OF
// TRUTH read back out of oidc_config.extra_config -- not against the list the
// test happens to hold in a variable. Row for row: position, group,
// organization, role name, and the role-template resolution.
func gmRequireEqual(t *testing.T, db *sql.DB, configID uuid.UUID, wantRoleIDs map[string]string) {
	t.Helper()
	var extra []byte
	if err := db.QueryRow(`SELECT COALESCE(extra_config, '{}'::jsonb) FROM oidc_config WHERE id = $1`, configID).
		Scan(&extra); err != nil {
		t.Fatalf("read stored extra_config: %v", err)
	}
	source := groupMappingsFromExtraConfig(extra)
	mirror := gmReadMirror(t, db, configID)
	if len(mirror) != len(source) {
		t.Fatalf("mirror has %d row(s), stored extra_config has %d mapping(s)", len(mirror), len(source))
	}
	for i, m := range source {
		got := mirror[i]
		if got.Position != i || got.Group != m.Group || got.Organization != m.Organization || got.RoleName != m.Role {
			t.Errorf("row %d: mirror (pos=%d group=%q org=%q role=%q) != source (group=%q org=%q role=%q)",
				i, got.Position, got.Group, got.Organization, got.RoleName, m.Group, m.Organization, m.Role)
		}
		wantID, resolvable := wantRoleIDs[m.Role]
		switch {
		case resolvable && (!got.RoleTemplateID.Valid || got.RoleTemplateID.String != wantID):
			t.Errorf("row %d: role %q should resolve to %s, mirror holds %v", i, m.Role, wantID, got.RoleTemplateID)
		case !resolvable && got.RoleTemplateID.Valid:
			t.Errorf("row %d: role %q resolves to nothing, mirror holds %s", i, m.Role, got.RoleTemplateID.String)
		}
	}
}

func gmRequireClean(t *testing.T, db *sql.DB) GroupMappingDriftReport {
	t.Helper()
	report, err := CheckGroupMappingDrift(context.Background(), db, db)
	if err != nil {
		t.Fatalf("CheckGroupMappingDrift: %v", err)
	}
	if !report.Clean() {
		for _, row := range report.Rows {
			t.Errorf("unexpected drift: %s", row.String())
		}
		t.Fatalf("expected the two copies to agree; %d drift row(s)", len(report.Rows))
	}
	return report
}

// TestGroupMappingEquivalence_RealWritePathKeepsBothCopiesEqual drives the
// three authoritative write shapes an admin can actually reach -- create with
// mappings (setup wizard), replace the list (the group-mapping endpoint,
// including a reorder, because first-match-wins makes order load-bearing), and
// delete -- and proves the mirror equal after each.
func TestGroupMappingEquivalence_RealWritePathKeepsBothCopiesEqual(t *testing.T) {
	db, _ := reconcileScratchDB(t, gmMigrationVersion)
	ctx := context.Background()

	publisherID := gmSeedTemplate(t, db, "gm-publisher")
	viewerID := gmSeedTemplate(t, db, "gm-viewer")
	roleIDs := map[string]string{"gm-publisher": publisherID, "gm-viewer": viewerID}

	repo := NewOIDCConfigRepository(sqlx.NewDb(db, "postgres"))

	// CREATE, carrying mappings in extra_config -- including one whose role
	// names no template: a legal row that must be mirrored faithfully with a
	// NULL resolution, not dropped.
	cfg := gmNewConfig(t, []identitymodels.OIDCGroupMapping{
		{Group: "eng", Organization: "alpha", Role: "gm-publisher"},
		{Group: "eng", Organization: "beta", Role: "gm-viewer"},
		{Group: "ops", Organization: "alpha", Role: "gm-missing"},
	})
	if err := repo.CreateOIDCConfig(ctx, cfg); err != nil {
		t.Fatalf("CreateOIDCConfig: %v", err)
	}
	gmRequireEqual(t, db, cfg.ID, roleIDs)
	report := gmRequireClean(t, db)
	if report.SourceMappings != 3 || report.MirroredMappings != 3 {
		t.Fatalf("gate compared %d source / %d mirrored mapping(s), want 3/3 — a clean result that "+
			"looked at nothing proves nothing", report.SourceMappings, report.MirroredMappings)
	}

	// REPLACE via the exact sequence the admin handler runs: read the active
	// config, re-encode the mapping keys, write extra_config back. The new
	// list REORDERS the survivors, so a mirror that preserved membership but
	// not order fails here.
	stored, err := repo.GetActiveOIDCConfig(ctx)
	if err != nil {
		t.Fatalf("GetActiveOIDCConfig: %v", err)
	}
	if err := stored.SetGroupMappingConfig("groups", []identitymodels.OIDCGroupMapping{
		{Group: "eng", Organization: "beta", Role: "gm-viewer"},
		{Group: "eng", Organization: "alpha", Role: "gm-publisher"},
	}, "viewer"); err != nil {
		t.Fatalf("SetGroupMappingConfig: %v", err)
	}
	if err := repo.UpdateOIDCConfigExtraConfig(ctx, stored.ID, stored.ExtraConfig); err != nil {
		t.Fatalf("UpdateOIDCConfigExtraConfig: %v", err)
	}
	gmRequireEqual(t, db, cfg.ID, roleIDs)
	gmRequireClean(t, db)
	if got := gmReadMirror(t, db, cfg.ID); len(got) != 2 || got[0].RoleName != "gm-viewer" {
		t.Fatalf("after the reorder the mirror should hold 2 rows led by gm-viewer, got %+v", got)
	}

	// DELETE the config: its mapping policy goes with it, in both copies.
	if err := repo.DeleteOIDCConfig(ctx, cfg.ID); err != nil {
		t.Fatalf("DeleteOIDCConfig: %v", err)
	}
	if got := gmReadMirror(t, db, cfg.ID); len(got) != 0 {
		t.Fatalf("mirror rows survived the config delete: %+v", got)
	}
	gmRequireClean(t, db)
}

// TestGroupMappingEquivalence_ComparisonFailsOnEveryDivergenceClass corrupts
// the mirror one way per divergence kind, asserts the gate reports EXACTLY
// that kind, and asserts the boot reconcile repairs it back to clean.
func TestGroupMappingEquivalence_ComparisonFailsOnEveryDivergenceClass(t *testing.T) {
	db, _ := reconcileScratchDB(t, gmMigrationVersion)
	ctx := context.Background()

	gmSeedTemplate(t, db, "gm-publisher")
	repo := NewOIDCConfigRepository(sqlx.NewDb(db, "postgres"))
	cfg := gmNewConfig(t, []identitymodels.OIDCGroupMapping{
		{Group: "eng", Organization: "alpha", Role: "gm-publisher"},
		{Group: "ops", Organization: "beta", Role: "gm-publisher"},
	})
	if err := repo.CreateOIDCConfig(ctx, cfg); err != nil {
		t.Fatalf("CreateOIDCConfig: %v", err)
	}
	gmRequireClean(t, db)

	cases := []struct {
		name    string
		corrupt func()
		kind    string
	}{
		{"a mirrored field is wrong", func() {
			mustExec(t, db, `UPDATE group_mappings SET organization_name='wrong' WHERE oidc_config_id=$1 AND position=0`, cfg.ID)
		}, GroupMappingDriftFieldsDiffer},
		{"a source mapping is not mirrored", func() {
			mustExec(t, db, `DELETE FROM group_mappings WHERE oidc_config_id=$1 AND position=1`, cfg.ID)
		}, GroupMappingDriftNotMirrored},
		{"the mirror holds an extra row", func() {
			mustExec(t, db, `INSERT INTO group_mappings (oidc_config_id, position, group_name, organization_name, role_template_name)
			                 VALUES ($1, 2, 'ghost', 'alpha', 'gm-publisher')`, cfg.ID)
		}, GroupMappingDriftMirrorOrphaned},
		{"the mirror holds rows for a config that does not exist", func() {
			mustExec(t, db, `INSERT INTO group_mappings (oidc_config_id, position, group_name, organization_name, role_template_name)
			                 VALUES ($1, 0, 'ghost', 'alpha', 'gm-publisher')`, uuid.New())
		}, GroupMappingDriftMirrorOrphaned},
		{"the role resolution went stale", func() {
			mustExec(t, db, `UPDATE group_mappings SET role_template_id=NULL WHERE oidc_config_id=$1 AND position=0`, cfg.ID)
		}, GroupMappingDriftRoleRefStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.corrupt()
			report, err := CheckGroupMappingDrift(ctx, db, db)
			if err != nil {
				t.Fatalf("CheckGroupMappingDrift: %v", err)
			}
			if report.Clean() {
				t.Fatalf("the gate reported CLEAN over a corrupted mirror — the comparison is not " +
					"looking at anything, which is the failure this file exists to rule out")
			}
			var sawKind bool
			for _, row := range report.Rows {
				if row.Kind == tc.kind {
					sawKind = true
				}
			}
			if !sawKind {
				t.Fatalf("expected a %s row, got: %+v", tc.kind, report.Rows)
			}
			// The boot backfill must repair exactly this class.
			if _, err := ReconcileGroupMappings(ctx, db, db); err != nil {
				t.Fatalf("ReconcileGroupMappings: %v", err)
			}
			gmRequireClean(t, db)
		})
	}
}

// TestGroupMappingEquivalence_BackfillsPreexistingConfigs is the
// upgrade story: oidc_config rows written BEFORE this change exist (inserted
// here by direct SQL, bypassing the wrapper exactly as the old binary did),
// the mirror is empty, and one boot reconcile converges it. Also pins the
// gate's other duty — reporting the unpopulated mirror BEFORE the backfill —
// and the two per-row oddities the report counts: a role name that resolves to
// no template, and an extra_config that is not a JSON object (whose effective
// mapping list is "none" on both sides, by the library's own decoder).
func TestGroupMappingEquivalence_BackfillsPreexistingConfigs(t *testing.T) {
	db, _ := reconcileScratchDB(t, gmMigrationVersion)
	ctx := context.Background()

	publisherID := gmSeedTemplate(t, db, "gm-publisher")

	withMappings := uuid.New()
	mustExec(t, db, `INSERT INTO oidc_config (id, issuer_url, client_id, client_secret_encrypted, redirect_url, is_active, extra_config)
	                 VALUES ($1, 'https://idp', 'c', 's', 'https://cb', true,
	                         '{"group_claim_name":"groups","group_mappings":[{"group":"eng","organization":"alpha","role":"gm-publisher"},{"group":"ops","organization":"beta","role":"gm-missing"}],"default_role":"viewer"}'::jsonb)`,
		withMappings)
	noExtra := uuid.New()
	mustExec(t, db, `INSERT INTO oidc_config (id, issuer_url, client_id, client_secret_encrypted, redirect_url, is_active)
	                 VALUES ($1, 'https://idp2', 'c', 's', 'https://cb', false)`, noExtra)
	garbageExtra := uuid.New()
	mustExec(t, db, `INSERT INTO oidc_config (id, issuer_url, client_id, client_secret_encrypted, redirect_url, is_active, extra_config)
	                 VALUES ($1, 'https://idp3', 'c', 's', 'https://cb', false, '"not an object"'::jsonb)`, garbageExtra)

	// Before the backfill the gate must refuse to call this clean.
	pre, err := CheckGroupMappingDrift(ctx, db, db)
	if err != nil {
		t.Fatalf("CheckGroupMappingDrift: %v", err)
	}
	if pre.Clean() {
		t.Fatal("the gate reported CLEAN over an unpopulated mirror with live source mappings")
	}

	report, err := ReconcileGroupMappings(ctx, db, db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.SourceConfigs != 3 || report.SourceMappings != 2 ||
		report.ConfigsRewritten != 1 || report.UnresolvedRoleRefs != 1 || report.UnparseableExtraConfigs != 1 {
		t.Fatalf("backfill report does not match the seeded estate: %+v", report)
	}
	gmRequireEqual(t, db, withMappings, map[string]string{"gm-publisher": publisherID})
	post := gmRequireClean(t, db)
	if post.SourceMappings != 2 || post.MirroredMappings != 2 {
		t.Fatalf("gate compared %d/%d mapping(s) after the backfill, want 2/2", post.SourceMappings, post.MirroredMappings)
	}

	// A second reconcile over a converged estate writes nothing — the
	// steady-state property that makes running this on every boot cheap.
	again, err := ReconcileGroupMappings(ctx, db, db)
	if err != nil {
		t.Fatalf("second ReconcileGroupMappings: %v", err)
	}
	if again.ConfigsRewritten != 0 || again.ConfigsPruned != 0 {
		t.Fatalf("a no-change reconcile rewrote %d and pruned %d config(s); steady state must write nothing",
			again.ConfigsRewritten, again.ConfigsPruned)
	}
}

// TestGroupMappingEquivalence_RefusesToRunWithoutTheTable pins the structural
// failure mode: on a database that predates migration 000059 both the
// reconcile and the gate must ERROR — never report clean, never quietly write
// nowhere. "Could not check" and "checked and found nothing" must stay
// distinguishable, or an upgrade-ordering mistake gates the cutover open.
func TestGroupMappingEquivalence_RefusesToRunWithoutTheTable(t *testing.T) {
	db, _ := reconcileScratchDB(t, gmMigrationVersion-1)
	ctx := context.Background()

	if _, err := ReconcileGroupMappings(ctx, db, db); err == nil {
		t.Fatal("ReconcileGroupMappings succeeded against a database without group_mappings")
	}
	if _, err := CheckGroupMappingDrift(ctx, db, db); err == nil {
		t.Fatal("CheckGroupMappingDrift succeeded against a database without group_mappings")
	}
}

package repositories

import (
	"context"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// Reconcile tests that need no database, pinning the DECISIONS the boot
// backfill makes: what it rewrites, what it leaves alone, what it prunes, and
// what it refuses outright. The Postgres file proves the topology properties;
// this file is what gates merges. Same split as member_role_reconcile_test.go.

const (
	gmCfgB  = "dddddddd-0000-0000-0000-000000000002"
	gmRoleB = "cccccccc-0000-0000-0000-000000000012"
)

// expectGroupMappingSourceVerified queues verifyGroupMappingSource's probe --
// the one query the reconcile sends the identity side before reading it.
func expectGroupMappingSourceVerified(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT to_regclass").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("public.oidc_config"))
}

// expectRegistryTemplateNames queues registryRoleTemplateNames. pairs are
// id, name, id, name, ...
func expectRegistryTemplateNames(mock sqlmock.Sqlmock, pairs ...string) {
	rows := sqlmock.NewRows([]string{"id", "name"})
	for i := 0; i+1 < len(pairs); i += 2 {
		rows.AddRow(pairs[i], pairs[i+1])
	}
	mock.ExpectQuery("SELECT id, name FROM registry_role_templates").WillReturnRows(rows)
}

// expectSourceOIDCConfigs queues readEffectiveGroupMappings. Each row is
// id, extra_config JSON.
func expectSourceOIDCConfigs(mock sqlmock.Sqlmock, rows ...[2]string) {
	r := sqlmock.NewRows([]string{"id", "extra_config"})
	for _, row := range rows {
		r.AddRow(row[0], []byte(row[1]))
	}
	mock.ExpectQuery("FROM oidc_config").WillReturnRows(r)
}

// expectMirroredGroupMappings queues readMirroredGroupMappings. Each row is
// config id, position, group, organization, role name, role id or nil.
func expectMirroredGroupMappings(mock sqlmock.Sqlmock, rows ...[6]interface{}) {
	r := sqlmock.NewRows([]string{"oidc_config_id", "position", "group_name", "organization_name", "role_template_name", "role_template_id"})
	for _, row := range rows {
		r.AddRow(row[0], row[1], row[2], row[3], row[4], row[5])
	}
	mock.ExpectQuery("SELECT oidc_config_id, position").WillReturnRows(r)
}

const gmExtraOneMapping = `{"group_claim_name":"groups","group_mappings":[{"group":"eng","organization":"alpha","role":"publisher"}],"default_role":"viewer"}`

// TestReconcileGroupMappings_BackfillsAnEmptyMirror is the upgrade boot: the
// source has a config with one mapping whose role resolves, the mirror is
// empty, and the reconcile writes exactly that config's rows -- resolving the
// role name to registry's own template id in the insert.
func TestReconcileGroupMappings_BackfillsAnEmptyMirror(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock, gmRoleA, "publisher")
	expectSourceOIDCConfigs(identity.mock, [2]string{gmCfgA, gmExtraOneMapping})
	expectMirroredGroupMappings(registry.mock)

	registry.mock.ExpectBegin()
	registry.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(mustUUID(t, gmCfgA)).WillReturnResult(sqlmock.NewResult(0, 0))
	registry.mock.ExpectExec("INSERT INTO group_mappings").
		WithArgs(mustUUID(t, gmCfgA), 0, "eng", "alpha", "publisher").
		WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectCommit()

	report, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.SourceConfigs != 1 || report.SourceMappings != 1 || report.ConfigsRewritten != 1 ||
		report.ConfigsPruned != 0 || report.UnresolvedRoleRefs != 0 || report.UnparseableExtraConfigs != 0 {
		t.Fatalf("report: %+v", report)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	// Exercise the boot log rendering while a populated report is in hand.
	_ = report.LogValue()
}

// TestReconcileGroupMappings_SteadyStateWritesNothing pins the property that
// makes an every-boot reconcile affordable: when the mirror already equals the
// source -- fields, order AND role resolution -- no write statement is issued
// at all. sqlmock fails on any unexpected statement, so the assertion is the
// absence of expectations beyond the reads.
func TestReconcileGroupMappings_SteadyStateWritesNothing(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock, gmRoleA, "publisher")
	expectSourceOIDCConfigs(identity.mock, [2]string{gmCfgA, gmExtraOneMapping})
	expectMirroredGroupMappings(registry.mock,
		[6]interface{}{gmCfgA, 0, "eng", "alpha", "publisher", gmRoleA})

	report, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.ConfigsRewritten != 0 || report.ConfigsPruned != 0 {
		t.Fatalf("steady state wrote something: %+v", report)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileGroupMappings_RewritesAStaleRoleResolution pins that equality
// includes the DERIVED column: same fields, same order, but a role_template_id
// that no longer matches what the name resolves to forces the rewrite.
func TestReconcileGroupMappings_RewritesAStaleRoleResolution(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock, gmRoleB, "publisher")
	expectSourceOIDCConfigs(identity.mock, [2]string{gmCfgA, gmExtraOneMapping})
	expectMirroredGroupMappings(registry.mock,
		[6]interface{}{gmCfgA, 0, "eng", "alpha", "publisher", gmRoleA})

	registry.mock.ExpectBegin()
	registry.mock.ExpectExec("DELETE FROM group_mappings").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectExec("INSERT INTO group_mappings").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectCommit()

	report, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.ConfigsRewritten != 1 {
		t.Fatalf("stale resolution not rewritten: %+v", report)
	}
}

// TestReconcileGroupMappings_PrunesAConfigTheSourceLost pins the direction
// that would otherwise GRANT after the cutover: mirror rows for a config the
// source no longer has are deleted.
func TestReconcileGroupMappings_PrunesAConfigTheSourceLost(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock)
	expectSourceOIDCConfigs(identity.mock)
	expectMirroredGroupMappings(registry.mock,
		[6]interface{}{gmCfgB, 0, "eng", "alpha", "publisher", nil})

	registry.mock.ExpectExec("DELETE FROM group_mappings WHERE oidc_config_id").
		WithArgs(mustUUID(t, gmCfgB)).WillReturnResult(sqlmock.NewResult(0, 1))

	report, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.ConfigsPruned != 1 {
		t.Fatalf("orphaned config not pruned: %+v", report)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileGroupMappings_CountsWhatItCannotResolve pins the two per-row
// oddities: a role name with no template is mirrored with a NULL id and
// counted, and an extra_config that is not a JSON object is counted while its
// effective mapping list -- none, per the library's decoder -- is mirrored
// faithfully as no rows.
func TestReconcileGroupMappings_CountsWhatItCannotResolve(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock)
	expectSourceOIDCConfigs(identity.mock, [2]string{gmCfgA, gmExtraOneMapping})
	expectMirroredGroupMappings(registry.mock)

	registry.mock.ExpectBegin()
	registry.mock.ExpectExec("DELETE FROM group_mappings").WillReturnResult(sqlmock.NewResult(0, 0))
	registry.mock.ExpectExec("INSERT INTO group_mappings").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectCommit()

	report, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report.UnresolvedRoleRefs != 1 {
		t.Fatalf("unresolved role not counted: %+v", report)
	}

	identity2, registry2 := newReconcileMocks(t)
	expectGroupMappingMirrorVerified(registry2.mock)
	expectGroupMappingSourceVerified(identity2.mock)
	expectRegistryTemplateNames(registry2.mock)
	expectSourceOIDCConfigs(identity2.mock, [2]string{gmCfgA, `"not an object"`})
	expectMirroredGroupMappings(registry2.mock)

	report2, err := ReconcileGroupMappings(context.Background(), identity2.db, registry2.db)
	if err != nil {
		t.Fatalf("ReconcileGroupMappings: %v", err)
	}
	if report2.UnparseableExtraConfigs != 1 || report2.ConfigsRewritten != 0 {
		t.Fatalf("unparseable extra_config mishandled: %+v", report2)
	}
}

// TestReconcileGroupMappings_RefusesStructuralFailures pins each early exit:
// a mirror that does not resolve, a source that does not resolve, and each
// read or write that fails must surface as an error naming the step -- never
// as a quiet, empty reconcile.
func TestReconcileGroupMappings_RefusesStructuralFailures(t *testing.T) {
	t.Run("mirror unreachable", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		registry.mock.ExpectQuery("SELECT to_regclass").
			WithArgs("group_mappings").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
		_, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
		if err == nil || !strings.Contains(err.Error(), "group-mapping table unusable") {
			t.Fatalf("want the mirror refusal, got %v", err)
		}
	})
	t.Run("source unreachable", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		identity.mock.ExpectQuery("SELECT to_regclass").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
		_, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db)
		if err == nil || !strings.Contains(err.Error(), "refusing to reconcile") {
			t.Fatalf("want the source refusal, got %v", err)
		}
	})
	t.Run("source probe fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		identity.mock.ExpectQuery("SELECT to_regclass").WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("template names read fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		registry.mock.ExpectQuery("SELECT id, name FROM registry_role_templates").WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("source read fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		identity.mock.ExpectQuery("FROM oidc_config").WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("source row does not scan", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		expectSourceOIDCConfigs(identity.mock, [2]string{"not-a-uuid", "{}"})
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("mirror read fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		expectSourceOIDCConfigs(identity.mock)
		registry.mock.ExpectQuery("SELECT oidc_config_id, position").WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("rewrite fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		expectSourceOIDCConfigs(identity.mock, [2]string{gmCfgA, gmExtraOneMapping})
		expectMirroredGroupMappings(registry.mock)
		registry.mock.ExpectBegin().WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("prune fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		expectSourceOIDCConfigs(identity.mock)
		expectMirroredGroupMappings(registry.mock,
			[6]interface{}{gmCfgB, 0, "eng", "alpha", "publisher", nil})
		registry.mock.ExpectExec("DELETE FROM group_mappings").WillReturnError(errors.New("boom"))
		if _, err := ReconcileGroupMappings(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
}

// TestSameGroupMappingList pins the equality the steady-state decision hangs
// on, one differing field per case.
func TestSameGroupMappingList(t *testing.T) {
	id := gmRoleA
	base := func() []mirroredGroupMapping {
		return []mirroredGroupMapping{{Position: 0, Group: "g", Organization: "o", RoleName: "r", RoleTemplateID: &id}}
	}
	if !sameGroupMappingList(base(), base()) {
		t.Fatal("identical lists compared unequal")
	}
	cases := map[string]func([]mirroredGroupMapping) []mirroredGroupMapping{
		"length":       func(l []mirroredGroupMapping) []mirroredGroupMapping { return l[:0] },
		"position":     func(l []mirroredGroupMapping) []mirroredGroupMapping { l[0].Position = 1; return l },
		"group":        func(l []mirroredGroupMapping) []mirroredGroupMapping { l[0].Group = "x"; return l },
		"organization": func(l []mirroredGroupMapping) []mirroredGroupMapping { l[0].Organization = "x"; return l },
		"role name":    func(l []mirroredGroupMapping) []mirroredGroupMapping { l[0].RoleName = "x"; return l },
		"role id":      func(l []mirroredGroupMapping) []mirroredGroupMapping { l[0].RoleTemplateID = nil; return l },
	}
	for name, mutate := range cases {
		if sameGroupMappingList(mutate(base()), base()) {
			t.Errorf("lists differing in %s compared equal", name)
		}
	}
}

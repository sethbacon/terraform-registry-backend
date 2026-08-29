package repositories

import (
	"context"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// Drift-gate tests that need no database. The Postgres equivalence file
// falsifies the gate against real rows; this file pins the CLASSIFICATION --
// which disagreement produces which kind, in which order -- and the
// structural refusals, on the runs that gate merges.

// driftMocks queues the five reads CheckGroupMappingDrift performs, in order.
func driftMocks(t *testing.T, templates []string, source [][2]string, mirror [][6]interface{}) (identity, registry *mockConn) {
	t.Helper()
	identity, registry = newReconcileMocks(t)
	expectGroupMappingMirrorVerified(registry.mock)
	expectGroupMappingSourceVerified(identity.mock)
	expectRegistryTemplateNames(registry.mock, templates...)
	expectSourceOIDCConfigs(identity.mock, source...)
	expectMirroredGroupMappings(registry.mock, mirror...)
	return identity, registry
}

func TestCheckGroupMappingDrift_CleanWhenBothCopiesAgree(t *testing.T) {
	identity, registry := driftMocks(t,
		[]string{gmRoleA, "publisher"},
		[][2]string{{gmCfgA, gmExtraOneMapping}},
		[][6]interface{}{{gmCfgA, 0, "eng", "alpha", "publisher", gmRoleA}})

	report, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("CheckGroupMappingDrift: %v", err)
	}
	if !report.Clean() {
		t.Fatalf("want clean, got %+v", report.Rows)
	}
	if report.SourceConfigs != 1 || report.SourceMappings != 1 || report.MirroredMappings != 1 {
		t.Fatalf("scope counters must prove the gate looked at something: %+v", report)
	}
}

// TestCheckGroupMappingDrift_ClassifiesEveryDisagreement builds one estate
// with all four kinds at once and asserts each classification AND the report
// order -- orphaned (grants) first, stale resolution last.
func TestCheckGroupMappingDrift_ClassifiesEveryDisagreement(t *testing.T) {
	const extra = `{"group_mappings":[` +
		`{"group":"eng","organization":"alpha","role":"publisher"},` +
		`{"group":"ops","organization":"beta","role":"publisher"},` +
		`{"group":"sec","organization":"gamma","role":"publisher"}]}`
	identity, registry := driftMocks(t,
		[]string{gmRoleA, "publisher"},
		[][2]string{{gmCfgA, extra}},
		[][6]interface{}{
			{gmCfgA, 0, "eng", "WRONG", "publisher", gmRoleA}, // fields differ
			{gmCfgA, 1, "ops", "beta", "publisher", nil},      // role resolution stale
			// position 2 missing: not mirrored
			{gmCfgB, 0, "ghost", "alpha", "publisher", gmRoleA}, // whole config orphaned
		})

	report, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("CheckGroupMappingDrift: %v", err)
	}
	var kinds []string
	for _, row := range report.Rows {
		kinds = append(kinds, row.Kind)
		if row.String() == "" {
			t.Error("a drift row rendered empty")
		}
	}
	want := []string{
		GroupMappingDriftMirrorOrphaned,
		GroupMappingDriftFieldsDiffer,
		GroupMappingDriftNotMirrored,
		GroupMappingDriftRoleRefStale,
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("want kinds %v worst-first, got %v", want, kinds)
	}
}

// TestCheckGroupMappingDrift_StaleResolutionRendersBothSides pins the
// operator-facing rendering of the one kind whose two sides are DERIVED
// values: the unresolved side must say so rather than print an empty id.
func TestCheckGroupMappingDrift_StaleResolutionRendersBothSides(t *testing.T) {
	identity, registry := driftMocks(t,
		[]string{}, // publisher resolves to nothing
		[][2]string{{gmCfgA, gmExtraOneMapping}},
		[][6]interface{}{{gmCfgA, 0, "eng", "alpha", "publisher", gmRoleA}})

	report, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("CheckGroupMappingDrift: %v", err)
	}
	if len(report.Rows) != 1 || report.Rows[0].Kind != GroupMappingDriftRoleRefStale {
		t.Fatalf("want one stale-resolution row, got %+v", report.Rows)
	}
	if !strings.Contains(report.Rows[0].Identity, "unresolved") {
		t.Fatalf("the unresolved side must say so: %q", report.Rows[0].Identity)
	}
}

func TestCheckGroupMappingDrift_RefusesStructuralFailures(t *testing.T) {
	t.Run("mirror unreachable", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		registry.mock.ExpectQuery("SELECT to_regclass").
			WithArgs("group_mappings").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
		if _, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("source unreachable", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		identity.mock.ExpectQuery("SELECT to_regclass").
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))
		if _, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("template names read fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		registry.mock.ExpectQuery("SELECT id, name FROM registry_role_templates").WillReturnError(errors.New("boom"))
		if _, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("source read fails", func(t *testing.T) {
		identity, registry := newReconcileMocks(t)
		expectGroupMappingMirrorVerified(registry.mock)
		expectGroupMappingSourceVerified(identity.mock)
		expectRegistryTemplateNames(registry.mock)
		identity.mock.ExpectQuery("FROM oidc_config").WillReturnError(errors.New("boom"))
		if _, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db); err == nil {
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
		if _, err := CheckGroupMappingDrift(context.Background(), identity.db, registry.db); err == nil {
			t.Fatal("want error")
		}
	})
}

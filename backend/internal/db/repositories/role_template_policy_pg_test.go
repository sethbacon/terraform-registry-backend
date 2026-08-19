package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/rolepolicy"
)

// Issue #891, against real PostgreSQL and the real migrations.
//
// CI DOES NOT RUN THIS. No workflow sets TFR_TEST_DATABASE_URL (issue #886), so
// everything below skips on a PR, exactly as the rest of this package's
// database-backed tests do. It is evidence produced locally against postgres:16
// and named as such in the pull request. The guard that runs on every PR is
// internal/db/rolepolicy's, which needs no database.
//
// It is here anyway because seeding is DATABASE behaviour. The static model in
// internal/db/rolepolicy is an interpretation of the migration files, and an
// interpretation nothing ever checks against the engine is a second opinion, not
// a fact. The first test below is what makes it a fact.

const policyMigrationsDir = "../migrations"

// scratchAtHead applies every migration, deriving head from the files rather
// than carrying a number that goes stale the next time one lands.
func scratchAtHead(t *testing.T) *sql.DB {
	t.Helper()
	head, err := rolepolicy.HeadVersion(policyMigrationsDir)
	if err != nil {
		t.Fatalf("HeadVersion: %v", err)
	}
	db, _ := reconcileScratchDB(t, uint(head))
	return db
}

// systemScopesIn reads name -> scopes for the system templates of one table.
func systemScopesIn(t *testing.T, db *sql.DB, table string) map[string][]string {
	t.Helper()
	rows, err := db.Query(`SELECT name, scopes FROM ` + table + ` WHERE is_system = true`)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var name string
		var raw []byte
		if scanErr := rows.Scan(&name, &raw); scanErr != nil {
			t.Fatalf("scan %s: %v", table, scanErr)
		}
		var scopes []string
		if jsonErr := json.Unmarshal(raw, &scopes); jsonErr != nil {
			t.Fatalf("decode %s.%s scopes %q: %v", table, name, raw, jsonErr)
		}
		out[name] = rolepolicy.Normalize(scopes)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s: %v", table, err)
	}
	return out
}

// TestPolicy_TheStaticModelMatchesWhatPostgresActuallyHolds validates the guard
// that runs in CI against the engine that runs in production.
//
// internal/db/rolepolicy evaluates the migrations' role-template DML in Go. If
// its reading of a statement were wrong -- a predicate it evaluates differently
// from Postgres, a `||` it de-duplicates where jsonb does not -- the PR-time
// guard would be comparing the Go list against a policy no database ever holds,
// and would be equally confident while doing it. This is the only test that can
// tell those apart, and it is why the model fails closed rather than guessing.
func TestPolicy_TheStaticModelMatchesWhatPostgresActuallyHolds(t *testing.T) {
	db := scratchAtHead(t)

	derived, err := rolepolicy.FromMigrations(policyMigrationsDir)
	if err != nil {
		t.Fatalf("FromMigrations: %v", err)
	}
	model := derived[rolepolicy.RoleTemplatesTable].SystemScopes()
	actual := systemScopesIn(t, db, "role_templates")

	if len(actual) == 0 {
		t.Fatal("the migrations seeded no system role templates; the comparison is vacuous")
	}
	for _, name := range unionOfKeys(model, actual) {
		want, inModel := model[name]
		got, inDB := actual[name]
		switch {
		case inModel && !inDB:
			t.Errorf("rolepolicy derives a system template %q the migrations do not "+
				"actually leave in the database", name)
		case inDB && !inModel:
			t.Errorf("the migrations leave a system template %q that rolepolicy did not "+
				"derive: the PR-time guard is reasoning about fewer roles than exist "+
				"(scopes in the database: %v)", name, got)
		case !reflect.DeepEqual(want, got):
			t.Errorf("rolepolicy and PostgreSQL disagree about %q.\n  model    : %v\n  database : %v\n"+
				"The static model is what gates every PR; when it is wrong the gate is wrong "+
				"in the same direction and just as quietly.", name, want, got)
		}
	}
}

// TestPolicy_TheMigratedDatabaseAgreesWithTheGoList is issue #891 stated as the
// database property it actually is: the default topology, seeded entirely by the
// migrations, must hold exactly what the identity-schema cutover's seed would
// write. Before the fix `devops` and `auditor` differ by `scanning:read`.
func TestPolicy_TheMigratedDatabaseAgreesWithTheGoList(t *testing.T) {
	db := scratchAtHead(t)

	actual := systemScopesIn(t, db, "role_templates")
	fromGo := map[string][]string{}
	for _, tmpl := range models.PredefinedRoleTemplates() {
		if tmpl.IsSystem {
			fromGo[tmpl.Name] = rolepolicy.Normalize(tmpl.Scopes)
		}
	}
	for _, name := range unionOfKeys(actual, fromGo) {
		if !reflect.DeepEqual(actual[name], fromGo[name]) {
			t.Errorf("role template %q: migrated database has %v, the seed would write %v",
				name, actual[name], fromGo[name])
		}
	}
}

// TestPolicy_NeitherSeedRemovesAScopeTheMigrationsGranted is the defect itself,
// exercised on BOTH write paths in one database, because a fix that covers one
// leaves the other live -- and the two feed different readers.
//
//	SeedSharedIdentityRoleTemplates -> role_templates.          Registry stopped
//	   reading this table at phase 3b. The STATE MANAGER's boot adopts from it
//	   every role name it does not define itself, and `devops` and `auditor` are
//	   two such names, so whatever this seed leaves here is what those two
//	   templates mean in the sibling application. It is also what a rollback to
//	   the previous registry image authorizes from.
//
//	SeedSystemRoleTemplates -> registry_role_templates.         Every
//	   authorization decision this application makes reads that table.
//
// Both are run in the order internal/api/router.go and cmd/server/main.go run
// them, including the reconcile between, since the reconcile re-derives
// registry's table from the shared one and a seed that ran before it would be
// undone on the same boot.
func TestPolicy_NeitherSeedRemovesAScopeTheMigrationsGranted(t *testing.T) {
	db := scratchAtHead(t)
	ctx := context.Background()

	granted := systemScopesIn(t, db, "role_templates")
	if len(granted) == 0 {
		t.Fatal("no system role templates after migrating; nothing to preserve")
	}

	// cmd/server/main.go, before NewRouter.
	if err := SeedSharedIdentityRoleTemplates(ctx, db, models.PredefinedRoleTemplates()); err != nil {
		t.Fatalf("SeedSharedIdentityRoleTemplates: %v", err)
	}
	// internal/api/router.go: reconcile, then seed registry's own table.
	if _, err := ReconcileMemberRoles(ctx, db, db); err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if err := SeedSystemRoleTemplates(ctx, db, models.PredefinedRoleTemplates()); err != nil {
		t.Fatalf("SeedSystemRoleTemplates: %v", err)
	}

	for _, tc := range []struct {
		table  string
		reader string
	}{
		{"role_templates", "the state manager's adopt pass, and a rollback to the previous image"},
		{"registry_role_templates", "every authorization decision this application makes"},
	} {
		after := systemScopesIn(t, db, tc.table)
		for name, want := range granted {
			got, ok := after[name]
			if !ok {
				t.Errorf("%s: template %q is gone after the boot sequence (%s reads this table)",
					tc.table, name, tc.reader)
				continue
			}
			for _, scope := range want {
				if !containsScope(got, scope) {
					t.Errorf("%s: the boot sequence REMOVED %q from %q, which migration "+
						"policy grants it. %s reads this table.\n  granted : %v\n  after   : %v",
						tc.table, scope, name, tc.reader, want, got)
				}
			}
			for _, scope := range got {
				if !containsScope(want, scope) {
					t.Errorf("%s: the boot sequence GRANTED %q to %q, which no migration "+
						"grants it. %s reads this table.\n  granted : %v\n  after   : %v",
						tc.table, scope, name, tc.reader, want, got)
				}
			}
		}
	}
}

func containsScope(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func unionOfKeys(maps ...map[string][]string) []string {
	seen := map[string]struct{}{}
	for _, m := range maps {
		for k := range m {
			seen[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package rolepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

const migrationsDir = "../migrations"

// TestTheGoListAndTheMigrationsStateTheSamePolicy is issue #891's guard, and the
// half of #891 that outlives the one-line list fix.
//
// THE DEFECT IT EXISTS FOR. Registry states its role -> scope policy twice:
// once as SQL (migration 000001's seed and every migration that has amended it),
// once as models.PredefinedRoleTemplates(). Only one of the two is exercised in
// any given topology, so they can disagree indefinitely without anything
// failing. Migration 000018 granted `scanning:read` to `devops` and `auditor`;
// the Go list never learned it; and because both seeds upsert with
// `scopes = EXCLUDED.scopes`, every boot in the topology where they run REMOVED
// a scope a migration had granted.
//
// WHY IT IS A CLASS GUARD AND NOT A SPELLING OF THIS ONE BUG. Nothing below
// names a scope, a template, or a migration. The expectation is DERIVED from
// whatever the migration files currently say, so a migration that lands tomorrow
// is covered the moment it exists. Verified by adding a scratch migration that
// grants an unrelated scope and watching this fail -- a guard whose universe is
// a list somebody has to remember to extend is inert against exactly the case it
// was written for.
//
// BOTH DIRECTIONS, DELIBERATELY. Today's drift removes authority, which fails
// safe: the auditor sees an empty scanning page. The mirror-image drift -- a Go
// list carrying a scope the migrations never granted -- would silently WIDEN
// what a role confers on every deployment the seed reaches, which does not fail
// safe at all. The diff below is symmetric so neither can land.
func TestTheGoListAndTheMigrationsStateTheSamePolicy(t *testing.T) {
	policies, err := FromMigrations(migrationsDir)
	if err != nil {
		t.Fatalf("deriving the role-template policy from the migrations: %v", err)
	}

	fromSQL := policies[RoleTemplatesTable].SystemScopes()
	if len(fromSQL) == 0 {
		// An empty expectation passes every comparison. That is not a clean
		// guard, it is a blind one.
		t.Fatalf("derived no system role templates from %s at all; the guard would "+
			"pass regardless of what the Go list says", migrationsDir)
	}

	fromGo := map[string][]string{}
	for _, tmpl := range models.PredefinedRoleTemplates() {
		if !tmpl.IsSystem {
			continue
		}
		fromGo[tmpl.Name] = Normalize(tmpl.Scopes)
	}

	for _, name := range sortedKeys(fromSQL, fromGo) {
		sqlScopes, inSQL := fromSQL[name]
		goScopes, inGo := fromGo[name]
		switch {
		case inSQL && !inGo:
			t.Errorf("role template %q is seeded by the migrations and missing from "+
				"models.PredefinedRoleTemplates(); the seed cannot restate it and the "+
				"cutover topology will not have it. Migration scopes: %v", name, sqlScopes)
		case inGo && !inSQL:
			t.Errorf("role template %q is in models.PredefinedRoleTemplates() and is not "+
				"seeded by any migration; the seed CREATES it in the cutover topology and "+
				"the default topology has never had it. Go scopes: %v", name, goScopes)
		case !reflect.DeepEqual(sqlScopes, goScopes):
			removed, added := diff(sqlScopes, goScopes)
			t.Errorf("role template %q: the two statements of one policy disagree.\n"+
				"  migrations grant : %v\n"+
				"  the Go list says : %v\n"+
				"  the seed would REMOVE : %v\n"+
				"  the seed would GRANT  : %v\n"+
				"Both seeds upsert with `scopes = EXCLUDED.scopes`, so whichever column "+
				"this leaves is what the role actually confers. Removing is an outage that "+
				"presents as an empty page; granting is a silent privilege widening. Fix "+
				"models.PredefinedRoleTemplates() (or, if the migration is the mistake, "+
				"write the migration that corrects it).",
				name, sqlScopes, goScopes, removed, added)
		}
	}
}

// TestRegistrysOwnTableIsNotSeededBehindTheGuardsBack covers the second write
// path. `registry_role_templates` (migration 000055) is created empty and filled
// at runtime; if a migration ever starts seeding it too, that becomes a third
// statement of the same policy and has to agree with the other two.
func TestRegistrysOwnTableIsNotSeededBehindTheGuardsBack(t *testing.T) {
	policies, err := FromMigrations(migrationsDir)
	if err != nil {
		t.Fatalf("deriving the role-template policy from the migrations: %v", err)
	}
	own := policies[RegistryRoleTemplatesTable].SystemScopes()
	if len(own) == 0 {
		return
	}
	fromGo := map[string][]string{}
	for _, tmpl := range models.PredefinedRoleTemplates() {
		fromGo[tmpl.Name] = Normalize(tmpl.Scopes)
	}
	for name, scopes := range own {
		if !reflect.DeepEqual(scopes, fromGo[name]) {
			t.Errorf("a migration now seeds %s.%s with %v, which is not what "+
				"models.PredefinedRoleTemplates() says (%v). Registry authorizes from that "+
				"table, so the two must agree.",
				RegistryRoleTemplatesTable, name, scopes, fromGo[name])
		}
	}
}

// TestTheDeriverFailsClosed is the guard on the guard. A model that silently
// skips what it cannot read reports "clean" for precisely the migrations doing
// something interesting, and is indistinguishable from one that never ran.
func TestTheDeriverFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{
			"UPDATE whose scopes expression is a function call",
			`UPDATE role_templates SET scopes = some_function(scopes) WHERE name = 'devops';`,
		},
		{
			"UPDATE whose WHERE clause is a subquery",
			`UPDATE role_templates SET scopes = '["x:read"]'::jsonb
			   WHERE id IN (SELECT role_template_id FROM organization_members);`,
		},
		{
			"INSERT ... SELECT",
			`INSERT INTO role_templates (name, display_name, scopes, is_system)
			 SELECT name, display_name, scopes, true FROM some_other_table;`,
		},
		{
			"ON CONFLICT DO UPDATE",
			`INSERT INTO role_templates (name, display_name, scopes, is_system)
			 VALUES ('x', 'X', '["a:read"]'::jsonb, true)
			 ON CONFLICT (name) DO UPDATE SET scopes = EXCLUDED.scopes;`,
		},
		{
			"ALTER that rewrites the scopes column",
			`ALTER TABLE role_templates ALTER COLUMN scopes TYPE jsonb USING to_jsonb(scopes);`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "000001_base.up.sql",
				`INSERT INTO role_templates (name, display_name, scopes, is_system)
				 VALUES ('devops', 'DevOps', '["modules:read"]'::jsonb, true);`)
			write(t, dir, "000002_probe.up.sql", tc.sql)

			_, err := FromMigrations(dir)
			if err == nil {
				t.Fatalf("the deriver accepted a role-template write it cannot evaluate; "+
					"it would report a policy that is not what %q leaves behind", tc.name)
			}
			var unmodelled *UnmodelledError
			if !asUnmodelled(err, &unmodelled) {
				t.Fatalf("expected an *UnmodelledError naming the file, got %T: %v", err, err)
			}
			if unmodelled.File != "000002_probe.up.sql" {
				t.Errorf("UnmodelledError.File = %q, want the offending migration", unmodelled.File)
			}
		})
	}
}

// TestTheDeriverModelsTheFormsTheMigrationsUse pins the constructs the real
// migrations are written in, so a refactor of the scanner cannot quietly stop
// understanding them and start reporting a policy assembled from fewer
// statements than the tree actually contains.
func TestTheDeriverModelsTheFormsTheMigrationsUse(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "000001_seed.up.sql", `
-- a comment with an apostrophe: the organization's roles
INSERT INTO role_templates (name, display_name, description, scopes, is_system) VALUES
('viewer', 'Viewer', 'Read-only', '["modules:read"]'::jsonb, true),
('devops', 'DevOps', 'CI/CD', '["modules:read", "scm:manage"]'::jsonb, true),
('admin',  'Administrator', 'Full access', '["admin"]'::jsonb, true),
('custom', 'Custom', 'not a system role', '["modules:read"]'::jsonb, false);`)

	write(t, dir, "000002_grant.up.sql", `
UPDATE role_templates
SET scopes = scopes || '["scanning:read"]'::jsonb
WHERE name = 'devops' AND is_system = true;`)

	write(t, dir, "000003_revoke.up.sql", `
UPDATE public.role_templates SET scopes = scopes - 'scm:manage' WHERE name = 'devops';`)

	// The shape migration 000054 uses: a DO block, a plpgsql CONSTANT holding the
	// replacement, and a follow-up statement whose SET expression is not
	// modellable but whose predicate selects nothing by the time it runs.
	write(t, dir, "000004_carrier_only.up.sql", `
DO $$
DECLARE
  org_owner_scopes CONSTANT jsonb := '["organizations:write", "modules:read"]'::jsonb;
BEGIN
  UPDATE public.role_templates
     SET scopes = org_owner_scopes, description = 'rewritten'
   WHERE name = 'admin' AND scopes @> '["admin"]'::jsonb;

  UPDATE public.role_templates rt
     SET scopes = COALESCE((SELECT jsonb_agg(d.s ORDER BY d.s)
                              FROM (SELECT DISTINCT s FROM (
                                      SELECT jsonb_array_elements_text(rt.scopes) AS s) a
                                    WHERE s <> 'admin') d), '[]'::jsonb)
   WHERE rt.scopes @> '["admin"]'::jsonb;

  -- identity's copy is deliberately not modelled
  UPDATE identity.role_templates SET scopes = ARRAY['whatever'] WHERE name = 'admin';
END $$;`)

	policies, err := FromMigrations(dir)
	if err != nil {
		t.Fatalf("FromMigrations: %v", err)
	}
	got := policies[RoleTemplatesTable]

	want := map[string][]string{
		"viewer": {"modules:read"},
		"devops": {"modules:read", "scanning:read"},
		"admin":  {"modules:read", "organizations:write"},
		"custom": {"modules:read"},
	}
	for name, wantScopes := range want {
		tmpl, ok := got[name]
		if !ok {
			t.Errorf("template %q was not derived at all", name)
			continue
		}
		if !reflect.DeepEqual(tmpl.Scopes, wantScopes) {
			t.Errorf("template %q scopes = %v, want %v", name, tmpl.Scopes, wantScopes)
		}
	}
	if got["custom"].IsSystem {
		t.Error("a non-system template was derived as a system one")
	}
	if _, ok := got.SystemScopes()["custom"]; ok {
		t.Error("SystemScopes() returned a non-system template")
	}
}

// TestTheDeriverSeesEveryUpMigration fails on an empty or truncated universe:
// a deriver pointed at nothing reports a policy of nothing and agrees with
// everything.
func TestTheDeriverSeesEveryUpMigration(t *testing.T) {
	files, err := UpMigrations(migrationsDir)
	if err != nil {
		t.Fatalf("UpMigrations: %v", err)
	}
	onDisk, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != len(onDisk) {
		t.Fatalf("UpMigrations read %d files, %d *.up.sql are on disk: the deriver is "+
			"reasoning about a subset of the migrations", len(files), len(onDisk))
	}
	if len(files) == 0 {
		t.Fatal("no migrations found; every comparison against this policy is vacuous")
	}
	for i := 1; i < len(files); i++ {
		if files[i].Version <= files[i-1].Version {
			t.Fatalf("migrations are not in version order at %s", files[i].Name)
		}
	}
	head, err := HeadVersion(migrationsDir)
	if err != nil {
		t.Fatalf("HeadVersion: %v", err)
	}
	if head != files[len(files)-1].Version {
		t.Errorf("HeadVersion = %d, want %d", head, files[len(files)-1].Version)
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func asUnmodelled(err error, out **UnmodelledError) bool {
	u, ok := err.(*UnmodelledError)
	if ok {
		*out = u
	}
	return ok
}

func sortedKeys(maps ...map[string][]string) []string {
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

// diff reports what a seed carrying `have` would take away from, and add to, a
// row currently holding `base`.
func diff(base, have []string) (removed, added []string) {
	in := func(hay []string, s string) bool {
		for _, h := range hay {
			if h == s {
				return true
			}
		}
		return false
	}
	for _, s := range base {
		if !in(have, s) {
			removed = append(removed, s)
		}
	}
	for _, s := range have {
		if !in(base, s) {
			added = append(added, s)
		}
	}
	return removed, added
}

package db_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestMigrationFilesAreConsistent(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	upCount := 0
	downCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upCount++
		}
		if strings.HasSuffix(e.Name(), ".down.sql") {
			downCount++
		}
	}
	if upCount != downCount {
		t.Errorf("migration up/down count mismatch: %d up, %d down", upCount, downCount)
	}
}

// migrations/README.md is the rollback reference an operator reads during an
// incident, and it is maintained by hand. It has already drifted once: it sat
// at 46 rows while the directory held 49 migrations, so the four newest had no
// documented rollback behaviour at exactly the moment someone would need it,
// and nothing failed. Drift is invisible in review because the row and the file
// live in different diffs.
//
// The check is BIDIRECTIONAL by number and by name. Undocumented migrations are
// the reported failure, but a stale row (documenting a migration that no longer
// exists, or naming one that was renamed) is just as wrong and fails here too --
// a one-way check would let the table rot in the other direction.
func TestMigrationsAreDocumented(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]string{} // number -> name
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".up.sql")
		if !ok {
			continue
		}
		num, rest, ok := strings.Cut(name, "_")
		if !ok {
			t.Errorf("migration %q is not <number>_<name>.up.sql", e.Name())
			continue
		}
		onDisk[num] = rest
	}
	if len(onDisk) == 0 {
		// Guard the guard: a bad path or a changed filename convention would
		// make every assertion below vacuously true.
		t.Fatal("no .up.sql migrations found - this test would pass vacuously")
	}

	readme, err := os.ReadFile("migrations/README.md")
	if err != nil {
		t.Fatal(err)
	}
	// | 000001 | `initial_schema` | ...
	row := regexp.MustCompile("(?m)^\\|\\s*(\\d{6})\\s*\\|\\s*`([^`]+)`")
	documented := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(readme), -1) {
		documented[m[1]] = m[2]
	}

	for num, name := range onDisk {
		got, ok := documented[num]
		if !ok {
			t.Errorf("migration %s_%s is not documented in migrations/README.md - add a row with its rollback behaviour", num, name)
			continue
		}
		if got != name {
			t.Errorf("migrations/README.md documents %s as %q, but the migration on disk is %q", num, got, name)
		}
	}
	for num, name := range documented {
		if _, ok := onDisk[num]; !ok {
			t.Errorf("migrations/README.md documents %s (%q), which does not exist on disk - remove the stale row", num, name)
		}
	}
}

// Issue #883 -- the re-runnable signature for the defect class, not for the one
// table that was reported.
//
// Migrations 000038 and 000045 chose each foreign key's TARGET SCHEMA from
// schema existence:
//
//	IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity')
//	  ... REFERENCES identity.organizations(id)
//	ELSE
//	  ... REFERENCES public.organizations(id)
//
// Schema existence is not schema authority. The identity schema is created by
// TFR_IDENTITY_MIGRATIONS_ENABLED while whether the application reads and
// writes it is the separate TFR_IDENTITY_SCHEMA_ENABLED cutover, so in the gap
// between them -- a state docs/identity-schema.md documents as a rollout step --
// the constraints resolved at `identity` while every row carried a `public` id
// and every feature write was rejected. Under TFR_IDENTITY_DATABASE_* the
// constraint is not expressible at all. Migration 000056 dropped all 24.
//
// This guard is the half that runs everywhere: the behavioural proof is in
// identity_fk_migration_test.go, but no workflow sets TFR_TEST_DATABASE_URL
// (issue #886), so that one skips in CI and this one does not. It fails the
// moment either half of the idiom reappears -- a fresh cross-schema REFERENCES,
// or a fresh schema-existence probe -- including in a migration nobody thought
// to write a database test for.
//
// The expectations are EXACT and BIDIRECTIONAL. The three files below are
// history: they are already applied in deployments and must never be edited, so
// a count that DROPS is as much a failure as one that rises. A new file with a
// nonzero count fails with no entry at all.
type identitySchemaIdiom struct {
	// crossSchemaRefs counts `REFERENCES <schema>.<table>` where <schema> is
	// not `public` -- a foreign key aimed at a schema whose authority is a
	// runtime property.
	crossSchemaRefs int
	// schemaProbes counts catalogue lookups that ask whether a schema exists.
	schemaProbes int
}

var frozenIdentitySchemaIdioms = map[string]identitySchemaIdiom{
	"000038_feature_fk_to_identity.up.sql":   {crossSchemaRefs: 22, schemaProbes: 1},
	"000038_feature_fk_to_identity.down.sql": {crossSchemaRefs: 0, schemaProbes: 1},
	"000045_namespace_org_claims.up.sql":     {crossSchemaRefs: 2, schemaProbes: 1},
}

// crossSchemaReference matches a schema-qualified foreign-key target. The
// capture is the schema name so `public` can be allowed and everything else
// reported; `\s` matches newlines, so a REFERENCES clause wrapped across lines
// is still seen.
var crossSchemaReference = regexp.MustCompile(`(?i)REFERENCES\s+([A-Za-z_][A-Za-z0-9_$]*)\s*\.`)

// schemaExistenceProbe matches the three ways to ask PostgreSQL whether a
// schema exists. Naming all three matters: swapping information_schema.schemata
// for to_regnamespace would otherwise reintroduce the idiom past a guard that
// only knew the spelling the defect happened to use.
var schemaExistenceProbe = regexp.MustCompile(`(?i)information_schema\.schemata|to_regnamespace|pg_namespace`)

// stripSQLComments removes `--` line comments and `/* */` block comments,
// tracking single-quoted string literals so a `--` inside one is not mistaken
// for a comment. Without this the guard would fire on prose: migration 000050
// describes an identity foreign key in a comment, and 000056 quotes the whole
// idiom while explaining why it was removed.
func stripSQLComments(sql string) string {
	var out strings.Builder
	inString, inLine, inBlock := false, false, false
	for i := 0; i < len(sql); i++ {
		switch {
		case inLine:
			if sql[i] == '\n' {
				inLine = false
				out.WriteByte('\n')
			}
		case inBlock:
			if sql[i] == '/' && i > 0 && sql[i-1] == '*' {
				inBlock = false
			}
		case inString:
			out.WriteByte(sql[i])
			if sql[i] == '\'' {
				inString = false
			}
		case sql[i] == '\'':
			inString = true
			out.WriteByte(sql[i])
		case sql[i] == '-' && i+1 < len(sql) && sql[i+1] == '-':
			inLine = true
			i++
		case sql[i] == '/' && i+1 < len(sql) && sql[i+1] == '*':
			inBlock = true
			i++
		default:
			out.WriteByte(sql[i])
		}
	}
	return out.String()
}

func TestNoMigrationChoosesAForeignKeyTargetFromSchemaExistence(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// Guard the guard: a moved directory or a changed suffix would make every
	// assertion below vacuously true, which is exactly how a class guard ships
	// inert.
	if len(paths) == 0 {
		t.Fatal("no migration .sql files found - this guard is not scanning anything")
	}
	sort.Strings(paths)

	seen := map[string]identitySchemaIdiom{}
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- path comes from a glob of this package's own migrations
		if err != nil {
			t.Fatal(err)
		}
		sql := stripSQLComments(string(raw))
		name := filepath.Base(path)

		var got identitySchemaIdiom
		for _, m := range crossSchemaReference.FindAllStringSubmatch(sql, -1) {
			if !strings.EqualFold(m[1], "public") {
				got.crossSchemaRefs++
			}
		}
		got.schemaProbes = len(schemaExistenceProbe.FindAllString(sql, -1))
		if got != (identitySchemaIdiom{}) {
			seen[name] = got
		}

		want := frozenIdentitySchemaIdioms[name]
		if got.crossSchemaRefs != want.crossSchemaRefs {
			t.Errorf("%s: %d foreign keys target a non-public schema, expected %d.\n"+
				"A registry table must not hold a foreign key into the identity schema: which schema the "+
				"application reads identity from is a RUNTIME decision (TFR_IDENTITY_SCHEMA_ENABLED), and "+
				"under TFR_IDENTITY_DATABASE_* it is a different database entirely, where no foreign key can "+
				"reach. Store the id as an unconstrained attribution and enforce the invariant in Go -- see "+
				"000046_user_token_revocations, 000051_platform_admins and 000056_drop_identity_attribution_fks "+
				"(issue #883). If you are deliberately changing one of the frozen historical migrations, update "+
				"frozenIdentitySchemaIdioms in the same commit and say why.",
				name, got.crossSchemaRefs, want.crossSchemaRefs)
		}
		if got.schemaProbes != want.schemaProbes {
			t.Errorf("%s: %d schema-existence probes, expected %d.\n"+
				"Do not branch a migration on whether a schema exists. Schema existence is not schema "+
				"authority: the identity schema is created by TFR_IDENTITY_MIGRATIONS_ENABLED, while whether "+
				"the application uses it is TFR_IDENTITY_SCHEMA_ENABLED, and a deployment sits in the gap "+
				"between them for as long as it likes. A statically chosen target is wrong in one topology "+
				"whichever branch it picks (issue #883).",
				name, got.schemaProbes, want.schemaProbes)
		}
	}

	// The other direction: a frozen file that no longer carries what it was
	// recorded as carrying has been edited. Those migrations are already applied
	// in deployments, so editing them changes nothing that ran and silently
	// desynchronises this guard from reality.
	for name := range frozenIdentitySchemaIdioms {
		if _, ok := seen[name]; !ok {
			t.Errorf("%s is recorded in frozenIdentitySchemaIdioms but no longer contains the idiom - "+
				"an applied migration was edited or renamed. Deployments have already run the original; "+
				"write a new migration instead and remove the stale entry.", name)
		}
	}
}

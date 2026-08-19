package db_test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sethbacon/terraform-suite-identity/identity"
)

// Issue #883, migration 000056 — the behavioural half, against a real
// PostgreSQL carrying the topology the defect needs.
//
// That topology is the one docs/identity-schema.md tells an operator to run:
// TFR_IDENTITY_MIGRATIONS_ENABLED=true creates the `identity` schema, and
// TFR_IDENTITY_SCHEMA_ENABLED stays unset until the data has been copied, so
// the schema EXISTS while the application still reads and writes `public`.
// Migrations 000038 and 000045 chose their foreign-key target from schema
// existence, so in that window every feature write was aimed at rows that live
// somewhere else and was rejected.
//
// It is reproduced here exactly as cmd/server/main.go builds it: identity
// migrations first (main.go's identityMigrationsEnabled branch), registry
// migrations second. Nothing is hand-rolled — identity.RunMigrations is the
// same call the server makes, so the `identity` schema is the real one, seeded
// with its own default organization whose id differs from public's.
//
// The test asserts the BEFORE as hard as the after. A run that could not
// reproduce the failure at 000055 would report a passing fix while proving
// nothing, so each write is required to fail first, by name.
//
// PR CI does not run this: no workflow sets TFR_TEST_DATABASE_URL (issue #886).
// The migration-text guard in migrations_test.go is the half that always runs.

// crossSchemaFeatureFKs counts foreign keys on `public` tables whose referenced
// table is in some other schema — the exact shape 000038 and 000045 created.
const crossSchemaFeatureFKs = `
	SELECT count(*)
	  FROM pg_constraint c
	  JOIN pg_class cl      ON cl.oid = c.conrelid
	  JOIN pg_namespace cn  ON cn.oid = cl.relnamespace
	  JOIN pg_class fc      ON fc.oid = c.confrelid
	  JOIN pg_namespace fn  ON fn.oid = fc.relnamespace
	 WHERE c.contype = 'f' AND cn.nspname = 'public' AND fn.nspname <> 'public'`

// registryWithIdentitySchema brings a scratch database up to targetVersion with
// the identity schema present, and returns a pool on it.
func registryWithIdentitySchema(t *testing.T, targetVersion uint) *sql.DB {
	t.Helper()
	dsn := migrationScratchDB(t)

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// The server runs these first, against the identity database, whenever
	// TFR_IDENTITY_MIGRATIONS_ENABLED is set (cmd/server/main.go).
	if err := identity.RunMigrations(conn, "up"); err != nil {
		t.Fatalf("identity migrations: %v", err)
	}

	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Migrate(targetVersion); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrating to %d: %v", targetVersion, err)
	}
	return conn
}

func countCrossSchemaFKs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(crossSchemaFeatureFKs).Scan(&n); err != nil {
		t.Fatalf("counting cross-schema foreign keys: %v", err)
	}
	return n
}

// publicPrincipals returns the organization and user ids the application
// actually writes with when the cutover has NOT happened: both from `public`.
func publicPrincipals(t *testing.T, db *sql.DB) (orgID, userID string) {
	t.Helper()
	if err := db.QueryRow(
		`SELECT id FROM public.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Fatalf("reading the public default organization: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO public.users (email, name) VALUES ('admin@dev.local', 'Admin') RETURNING id`,
	).Scan(&userID); err != nil {
		t.Fatalf("seeding a public user: %v", err)
	}

	// Guard the guard. The whole defect is that these two schemas hold
	// DIFFERENT rows; if the identity schema happened to carry the same
	// organization id, every assertion below would pass for the wrong reason.
	var identityOrg string
	if err := db.QueryRow(
		`SELECT id FROM identity.organizations ORDER BY created_at LIMIT 1`).Scan(&identityOrg); err != nil {
		t.Fatalf("reading the identity default organization: %v", err)
	}
	if identityOrg == orgID {
		t.Fatal("the identity and public default organizations share an id — this database does not " +
			"reproduce the divergence #883 is about, and the assertions below would be vacuous")
	}
	return orgID, userID
}

// featureWrites are the statements #883 breaks, in the form the application
// issues them.
type featureWrite struct {
	what       string
	constraint string // the foreign key expected to reject it before 000056
	exec       func(db *sql.DB, orgID, userID string) error
}

func featureWritesUnderTest() []featureWrite {
	return []featureWrite{
		{
			// NamespaceClaimRepository.ClaimNamespace, reached by POST
			// /api/v1/modules. The reported failure.
			what:       "claim a namespace (POST /api/v1/modules)",
			constraint: "namespace_claims_organization_id_fkey",
			exec: func(db *sql.DB, orgID, userID string) error {
				_, err := db.Exec(
					`INSERT INTO namespace_claims (namespace, organization_id, claimed_by)
					 VALUES ('acme', $1, $2) ON CONFLICT (namespace) DO NOTHING`, orgID, userID)
				return err
			},
		},
		{
			// ModuleRepository.CreateModule. Not in the issue: the module row
			// itself is rejected too, so the defect is wider than the one
			// constraint that was reported.
			what:       "insert the module row a publish creates",
			constraint: "modules_created_by_fkey",
			exec: func(db *sql.DB, orgID, userID string) error {
				_, err := db.Exec(
					`INSERT INTO modules (namespace, name, system, organization_id, created_by)
					 VALUES ('acme', 'vpc', 'aws', $1, $2)`, orgID, userID)
				return err
			},
		},
		{
			// ProviderRepository.UpsertProvider, reached SYNCHRONOUSLY from the
			// UNAUTHENTICATED network-mirror index on a cache miss
			// (internal/api/mirror/index.go -> PullThroughService). created_by
			// is NULL on this path, so organization_id is the constraint that
			// rejects it — and this is a PUBLIC consumption path, which makes
			// #883 a public-serving outage and not only a publishing one.
			what:       "insert a pull-through provider (anonymous mirror GET)",
			constraint: "providers_organization_id_fkey",
			exec: func(db *sql.DB, orgID, _ string) error {
				_, err := db.Exec(
					`INSERT INTO providers (organization_id, namespace, type, description, source, created_by)
					 VALUES ($1, 'hashicorp', 'null', 'Pull-through cached provider', 'registry.terraform.io', NULL)`,
					orgID)
				return err
			},
		},
	}
}

// TestMigration000055_RejectsFeatureWritesWhereTheIdentitySchemaExists is the
// falsification: it proves the failure is real, and that it is these
// constraints producing it, before the next test claims to have removed it.
func TestMigration000055_RejectsFeatureWritesWhereTheIdentitySchemaExists(t *testing.T) {
	db := registryWithIdentitySchema(t, 55)

	if n := countCrossSchemaFKs(t, db); n != 24 {
		t.Fatalf("%d foreign keys on public tables point outside public, want 24 — this database does "+
			"not carry the schema #883 describes, so the rejections below would prove nothing", n)
	}

	orgID, userID := publicPrincipals(t, db)
	for _, w := range featureWritesUnderTest() {
		err := w.exec(db, orgID, userID)
		if err == nil {
			t.Errorf("%s: succeeded at migration 000055, but #883 says the identity-targeting "+
				"foreign key rejects it", w.what)
			continue
		}
		if !containsAll(err.Error(), "foreign key constraint", w.constraint) {
			t.Errorf("%s: failed for the wrong reason.\ngot:  %v\nwant: a violation of %s",
				w.what, err, w.constraint)
		}
	}
}

// TestMigration000056_RepairsFeatureWritesWhereTheIdentitySchemaExists is the
// fix, on the same database shape, applied one migration further.
func TestMigration000056_RepairsFeatureWritesWhereTheIdentitySchemaExists(t *testing.T) {
	db := registryWithIdentitySchema(t, 56)

	if n := countCrossSchemaFKs(t, db); n != 0 {
		t.Errorf("%d foreign keys on public tables still point outside public after 000056, want 0", n)
	}

	orgID, userID := publicPrincipals(t, db)
	for _, w := range featureWritesUnderTest() {
		if err := w.exec(db, orgID, userID); err != nil {
			t.Errorf("%s: still rejected after 000056: %v", w.what, err)
		}
	}

	// Public consumption. Reads never evaluate a foreign key, and the
	// download counters update only the counter column, so neither could have
	// been affected by the constraints or by their removal — asserted rather
	// than assumed, because the owner's requirement is that these keep working.
	var modID, verID string
	if err := db.QueryRow(`SELECT id FROM modules WHERE namespace = 'acme'`).Scan(&modID); err != nil {
		t.Fatalf("read back the published module: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO module_versions (module_id, version, published_by, storage_path, storage_backend, size_bytes, checksum)
		 VALUES ($1, '1.0.0', $2, 'm/acme/vpc/aws/1.0.0.tgz', 'local', 1024, 'deadbeef') RETURNING id`,
		modID, userID).Scan(&verID); err != nil {
		t.Fatalf("publish a module version: %v", err)
	}
	var listed int
	if err := db.QueryRow(
		`SELECT count(*) FROM module_versions WHERE module_id = $1`, modID).Scan(&listed); err != nil {
		t.Errorf("version listing (GET /v1/modules/.../versions): %v", err)
	}
	if listed != 1 {
		t.Errorf("version listing returned %d versions, want 1", listed)
	}
	// ModuleRepository.IncrementDownloadCount — one column, so PostgreSQL does
	// not revalidate published_by even while a constraint on it exists.
	if _, err := db.Exec(
		`UPDATE module_versions SET download_count = download_count + 1 WHERE id = $1`, verID); err != nil {
		t.Errorf("download counter (GET /v1/modules/.../download): %v", err)
	}
}

// TestMigration000056_ConvergesTheStandaloneTopology asserts the other half of
// the point: after 000056 the schema has the SAME shape whether or not the
// identity schema exists. A fix that only repaired one topology would leave the
// constraint set a property of how the database was migrated, which is the
// defect restated.
func TestMigration000056_ConvergesTheStandaloneTopology(t *testing.T) {
	dsn := migrationScratchDB(t)
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// No identity migrations: the default, standalone deployment.
	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate up: %v", err)
	}

	var present bool
	if err := conn.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity')`,
	).Scan(&present); err != nil {
		t.Fatalf("probing for the identity schema: %v", err)
	}
	if present {
		t.Fatal("the identity schema exists on a database that never ran identity migrations")
	}

	// The 24 constraints are gone here too, aimed at public though they were.
	for _, name := range []string{
		"namespace_claims_organization_id_fkey",
		"namespace_claims_claimed_by_fkey",
		"modules_created_by_fkey",
		"modules_organization_id_fkey",
		"providers_organization_id_fkey",
		"scm_oauth_tokens_user_id_fkey",
		"download_events_user_id_fkey",
		"system_settings_storage_configured_by_fkey",
	} {
		var exists bool
		if err := conn.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = $1 AND contype = 'f')`,
			name).Scan(&exists); err != nil {
			t.Fatalf("looking up %s: %v", name, err)
		}
		if exists {
			t.Errorf("%s survives on a standalone database — 000056 must drop the constraints in "+
				"every topology, or which constraints exist stays a property of how the database "+
				"was migrated", name)
		}
	}

	// The identity-owned foreign keys are NOT collateral: those tables move to
	// the identity schema wholesale at cutover and their constraints travel
	// with them, which is why 000038 left them alone and 000056 does too.
	for _, name := range []string{
		"organization_members_user_id_fkey",
		"organization_members_organization_id_fkey",
		"api_keys_user_id_fkey",
		"audit_logs_user_id_fkey",
	} {
		var exists bool
		if err := conn.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = $1 AND contype = 'f')`,
			name).Scan(&exists); err != nil {
			t.Fatalf("looking up %s: %v", name, err)
		}
		if !exists {
			t.Errorf("%s was dropped — 000056 overreached beyond the registry's feature tables "+
				"into identity's own", name)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

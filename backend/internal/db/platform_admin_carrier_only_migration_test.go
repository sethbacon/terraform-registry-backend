package db_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
)

// Issue #766, migration 000054 — the breaking migration, applied, refused,
// rolled back and re-applied against a real PostgreSQL.
//
// PR CI does not run migrations (only the manually dispatched chaos workflow
// does), so a migration that fails to apply, whose ordering is wrong, or whose
// down cannot undo it, would otherwise be discovered by whoever upgrades first.
// This one is worse than most if it is wrong: it is the migration that takes
// platform-admin authority off the role templates, so a backfill that does not
// run before the removal locks an operator out of their own deployment.
//
// Three properties, each with its own falsification:
//
//  1. ORDER — a user holding an admin-bearing template and NO carrier row comes
//     out the other side with one. Falsified by running the same migration with
//     its backfill deleted, which must then REFUSE.
//  2. REFUSAL — the refusal is a rollback, not a partial apply. Nothing is
//     changed by a migration that refuses.
//  3. REVERSIBILITY — down restores `["admin"]` and migration 000053's view;
//     up re-applies cleanly on top of its own output.
//
// Set TFR_TEST_DATABASE_URL to run these.

// carrierOnlySeed is the fixture all three tests share: an organization, two
// users, the seeded `admin` template and a CUSTOM admin-bearing template, and
// memberships onto both.
//
// Neither user gets a platform_admins row. That is the entire point: this is
// the state of every deployment that granted the `admin` template after
// migration 000051's one-time backfill ran.
type carrierOnlySeed struct {
	orgID          string
	seededAdminUsr string
	customAdminUsr string
	customRoleID   string
}

func seedAdminBearingMemberships(t *testing.T, db *sql.DB) carrierOnlySeed {
	t.Helper()
	s := carrierOnlySeed{
		orgID:          uuid.New().String(),
		seededAdminUsr: uuid.New().String(),
		customAdminUsr: uuid.New().String(),
		customRoleID:   uuid.New().String(),
	}

	mustExec(t, db, `INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $3)`,
		s.orgID, "acme-"+s.orgID[:8], "Acme")
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`,
		s.seededAdminUsr, "seeded-"+s.seededAdminUsr[:8]+"@example.com", "Seeded Admin")
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`,
		s.customAdminUsr, "custom-"+s.customAdminUsr[:8]+"@example.com", "Custom Admin")

	// A custom template that carries the wildcard alongside a scope of its own.
	// It exists to prove the removal is not special-cased to the row named
	// 'admin': `admin` is the carrier for the wildcard wherever it appears.
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system)
	                 VALUES ($1, $2, $3, '["admin","audit:read"]'::jsonb, false)`,
		s.customRoleID, "custom-super-"+s.customRoleID[:8], "Custom Super")

	var seededAdminRole string
	if err := db.QueryRow(`SELECT id FROM role_templates WHERE name = 'admin'`).Scan(&seededAdminRole); err != nil {
		t.Fatalf("the seeded admin role template is missing: %v", err)
	}
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id) VALUES ($1,$2,$3)`,
		s.orgID, s.seededAdminUsr, seededAdminRole)
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id) VALUES ($1,$2,$3)`,
		s.orgID, s.customAdminUsr, s.customRoleID)

	// The precondition the whole migration turns on.
	if carrierRows(t, db) != 0 {
		t.Fatalf("the fixture must start with an EMPTY carrier, or the backfill proves nothing")
	}
	return s
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", strings.TrimSpace(strings.SplitN(query, "\n", 2)[0]), err)
	}
}

func carrierRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM platform_admins`).Scan(&n); err != nil {
		t.Fatalf("counting platform_admins: %v", err)
	}
	return n
}

func hasCarrierRow(t *testing.T, db *sql.DB, userID string) bool {
	t.Helper()
	var present bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM platform_admins WHERE user_id = $1)`, userID).Scan(&present); err != nil {
		t.Fatalf("reading platform_admins: %v", err)
	}
	return present
}

func templateScopes(t *testing.T, db *sql.DB, name string) []string {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT scopes FROM role_templates WHERE name = $1`, name).Scan(&raw); err != nil {
		t.Fatalf("reading role template %q: %v", name, err)
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing role template %q scopes %s: %v", name, raw, err)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestMigration000054_BackfillsTheCarrierBeforeRemovingTheAdminScope is
// property 1: the ordering.
func TestMigration000054_BackfillsTheCarrierBeforeRemovingTheAdminScope(t *testing.T) {
	dsn := migrationScratchDB(t)
	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Migrate(53); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("applying migrations through 000053: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	seed := seedAdminBearingMemberships(t, db)

	// The state before: `admin` is on the template, and nobody has a carrier
	// row. Under the 4.x binary these two people ARE the platform
	// administrators.
	if got := templateScopes(t, db, "admin"); !contains(got, "admin") {
		t.Fatalf("the seeded admin template does not carry `admin` at version 53 (%v) — the fixture is wrong", got)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("applying 000054: %v", err)
	}
	if version, dirty, err := m.Version(); err != nil || version != 54 || dirty {
		t.Fatalf("after apply: version %d dirty %v err %v; want 54, clean", version, dirty, err)
	}

	// --- the ordering, both halves ---------------------------------------
	if !hasCarrierRow(t, db, seed.seededAdminUsr) {
		t.Error("the holder of the seeded `admin` template has no carrier row: the migration removed the " +
			"authority without capturing it, which is a lockout")
	}
	if !hasCarrierRow(t, db, seed.customAdminUsr) {
		t.Error("the holder of a CUSTOM admin-bearing template has no carrier row: the backfill only looks at " +
			"the template named `admin`, so a custom wildcard template is a silent lockout")
	}

	if got := templateScopes(t, db, "admin"); contains(got, "admin") {
		t.Errorf("the seeded admin template still carries `admin` after 000054: %v", got)
	} else if !contains(got, "organizations:write") {
		t.Errorf("the seeded admin template = %v, want the org_owner scope set — emptying it would strand "+
			"every organization its holders administer (invariant B)", got)
	}

	customName := templateName(t, db, seed.customRoleID)
	custom := templateScopes(t, db, customName)
	if contains(custom, "admin") {
		t.Errorf("the custom admin-bearing template still carries `admin`: %v", custom)
	}
	if !contains(custom, "audit:read") {
		t.Errorf("the custom template lost its own scopes: %v, want audit:read kept", custom)
	}
	if !contains(custom, "organizations:write") {
		t.Errorf("the custom template = %v, want the org_owner scope set in place of the wildcard", custom)
	}

	// --- the audit intents, which migration 000052's trigger required ----
	//
	// The grant could not have committed without them, so their absence here
	// would mean the backfill silently inserted nothing at all.
	for _, u := range []string{seed.seededAdminUsr, seed.customAdminUsr} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM audit_outbox
		                        WHERE action = 'platform_admin.granted' AND resource_id = $1
		                          AND metadata->>'source' = 'migration 000054 backfill'`, u).Scan(&n); err != nil {
			t.Fatalf("reading audit_outbox: %v", err)
		}
		if n != 1 {
			t.Errorf("user %s has %d migration-000054 grant intents, want exactly 1", u, n)
		}
	}

	// --- the view now answers under the new rule -------------------------
	//
	// Both users hold a carrier row, so there is no deployment violation. Put
	// `admin` back on a template by hand and DELETE the carrier: migration
	// 000053's view would call that healthy, and this one must not.
	mustExec(t, db, `UPDATE role_templates SET scopes = '["admin"]'::jsonb WHERE name = 'admin'`)
	clearCarrierWithIntents(t, db)
	var deploymentViolations int
	if err := db.QueryRow(`SELECT count(*) FROM admin_floor_violations WHERE scope = 'deployment'`).
		Scan(&deploymentViolations); err != nil {
		t.Fatalf("reading admin_floor_violations: %v", err)
	}
	if deploymentViolations != 1 {
		t.Errorf("admin_floor_violations reported %d deployment violation(s), want 1: an admin-bearing "+
			"role template is not a platform administrator any more, and a view that still says it is "+
			"reports a deployment nobody can administer as healthy", deploymentViolations)
	}
}

func templateName(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var name string
	if err := db.QueryRow(`SELECT name FROM role_templates WHERE id = $1`, id).Scan(&name); err != nil {
		t.Fatalf("reading role template %s: %v", id, err)
	}
	return name
}

// clearCarrierWithIntents empties platform_admins, writing the revoke intent
// migration 000052's trigger demands for each row.
func clearCarrierWithIntents(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(`
		WITH gone AS (DELETE FROM platform_admins RETURNING user_id)
		INSERT INTO audit_outbox (event_id, action, resource_type, resource_id, metadata)
		SELECT gen_random_uuid(), 'platform_admin.revoked', 'platform_admin', g.user_id::text,
		       jsonb_build_object('target_user_id', g.user_id, 'source', 'test fixture')
		  FROM gone g`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("clearing the carrier: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("committing the carrier clear: %v", err)
	}
}

// backfillBlock matches the two `WITH granted AS ( INSERT INTO platform_admins
// ... ) INSERT INTO audit_outbox ...;` statements that are step 1 of the
// migration. Replacing them with an assignment — VALID plpgsql, so the rest of
// the migration still runs — is the mutation.
var backfillBlock = regexp.MustCompile(`(?s)WITH granted AS \(.*?FROM granted g;`)

// raisedRefusal reports whether err is migration 000054's own RAISE EXCEPTION,
// read from the PostgreSQL error rather than from the rendered string.
//
// THIS IS NOT FASTIDIOUSNESS. golang-migrate's database.Error renders as
// "<err> in line N: <THE ENTIRE MIGRATION SQL>", and that SQL contains the
// literal text of the RAISE EXCEPTION message — so `strings.Contains(err.Error(),
// "migration 000054 REFUSED")` is true for a SYNTAX error in this file, and this
// test passed with the transition guard replaced by `IF FALSE`. Matching the
// SQLSTATE and the raised message on the driver error is what makes the
// assertion about the refusal instead of about the source code.
// TWO DRIVER ERROR TYPES, deliberately. The application migrated off lib/pq to
// jackc/pgx (#905, landed as #910), and this file's assertion moved to
// *pgconn.PgError with it -- but golang-migrate's own postgres driver still
// uses lib/pq internally, so the error arriving here is a *pq.Error. The
// assertion silently stopped matching, and a CORRECT refusal carrying the
// CORRECT SQLSTATE 23514 was reported as "a different failure".
//
// Nothing caught it, because no workflow set TFR_TEST_DATABASE_URL and this
// test has never run in CI (issue #886). It is the first thing the new
// postgres-tests job found. Handling both types is not defensive clutter: the
// two drivers genuinely coexist here, one in the application and one inside
// golang-migrate, and which one surfaces is not this test's choice.
func driverErrorFields(err error) (code, message string, ok bool) {
	var pgxErr *pgconn.PgError
	if errors.As(err, &pgxErr) {
		return string(pgxErr.Code), pgxErr.Message, true
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code), pqErr.Message, true
	}
	return "", "", false
}

func raisedRefusal(err error) (bool, string) {
	code, message, ok := driverErrorFields(err)
	if !ok {
		var dbErr database.Error
		if !errors.As(err, &dbErr) {
			return false, err.Error()
		}
		if code, message, ok = driverErrorFields(dbErr.OrigErr); !ok {
			return false, fmt.Sprintf("%v", dbErr.OrigErr)
		}
	}
	detail := code + ": " + message
	return code == "23514" && strings.Contains(message, "migration 000054 REFUSED"), detail
}

// TestMigration000054_RefusesWhenTheBackfillDidNotRun is property 1's
// falsification and property 2 in one.
//
// The migration is copied to a scratch directory with step 1 — the carrier
// backfill — deleted, and applied to the same fixture. It MUST refuse, and it
// must refuse by rolling everything back: `admin` still on the template, no
// carrier row, nothing half-applied.
//
// This is what makes the assertion in step 3 a guard rather than decoration. On
// a coherent deployment the backfill covers, by construction, everybody the
// count in step 0 saw — so the only way to watch the refusal fire is to break
// the thing it protects.
func TestMigration000054_RefusesWhenTheBackfillDidNotRun(t *testing.T) {
	dsn := migrationScratchDB(t)

	// A migrations directory that is the real one, with 000054's backfill
	// removed. Copied rather than edited in place so a failing test cannot
	// leave the repository mutated.
	dir := t.TempDir()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("reading migrations: %v", err)
	}
	var mutated bool
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		if e.Name() == "000054_platform_admin_carrier_only.up.sql" {
			// `backfilled := 0;` rather than a bare `SELECT 1;`: plpgsql
			// rejects a query with no destination, so that spelling made the
			// migration die of a syntax error before it ever reached step 3.
			stripped := backfillBlock.ReplaceAll(body, []byte("backfilled := 0;"))
			if len(stripped) == len(body) {
				t.Fatal("the backfill pattern matched nothing in 000054 — this mutation is inert, " +
					"and so is the property it is supposed to falsify")
			}
			body, mutated = stripped, true
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), body, 0o600); err != nil {
			t.Fatalf("writing %s: %v", e.Name(), err)
		}
	}
	if !mutated {
		t.Fatal("000054's up migration was not found in the migrations directory")
	}

	m, err := migrate.New("file://"+dir, dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Migrate(53); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("applying migrations through 000053: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	seed := seedAdminBearingMemberships(t, db)

	err = m.Steps(1)
	if err == nil {
		t.Fatal("000054 applied with its carrier backfill deleted: the transition guard in step 3 is inert, " +
			"and a deployment that granted the admin template after migration 000051 loses every administrator")
	}
	if refused, detail := raisedRefusal(err); !refused {
		t.Fatalf("000054 failed with %s, want the step-3 refusal (SQLSTATE 23514) — a different failure, "+
			"a syntax error in the mutation above included, proves nothing about the guard", detail)
	}

	// The refusal is a rollback, not a partial apply.
	if got := templateScopes(t, db, "admin"); !contains(got, "admin") {
		t.Errorf("the admin template = %v after a REFUSED migration: the removal committed and the refusal did not "+
			"undo it, which is the lockout this check exists to prevent", got)
	}
	if hasCarrierRow(t, db, seed.seededAdminUsr) || carrierRows(t, db) != 0 {
		t.Error("a refused migration left rows in platform_admins")
	}
}

// TestMigration000054_RollsBackAndReApplies is property 3.
func TestMigration000054_RollsBackAndReApplies(t *testing.T) {
	dsn := migrationScratchDB(t)
	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Migrate(53); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("applying migrations through 000053: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	seed := seedAdminBearingMemberships(t, db)

	if err := m.Steps(1); err != nil {
		t.Fatalf("applying 000054: %v", err)
	}

	// --- down -------------------------------------------------------------
	if err := m.Steps(-1); err != nil {
		t.Fatalf("rolling back 000054: %v", err)
	}
	if version, dirty, err := m.Version(); err != nil || version != 53 || dirty {
		t.Fatalf("after rollback: version %d dirty %v err %v; want 53, clean", version, dirty, err)
	}
	if got := templateScopes(t, db, "admin"); len(got) != 1 || got[0] != "admin" {
		t.Errorf("after rollback the admin template = %v, want exactly [admin] — a rollback of the binary "+
			"restores union authority and the template has to carry it again", got)
	}
	// The backfilled grants stay, deliberately: deleting them would strip real
	// authority from real people on a rollback.
	if !hasCarrierRow(t, db, seed.seededAdminUsr) {
		t.Error("the rollback deleted a backfilled carrier grant")
	}
	// Migration 000053's view is back: it excuses a deployment whose only
	// administrator holds an admin-bearing template, because under the 4.x
	// binary that IS an administrator.
	clearCarrierWithIntents(t, db)
	var violations int
	if err := db.QueryRow(`SELECT count(*) FROM admin_floor_violations WHERE scope = 'deployment'`).Scan(&violations); err != nil {
		t.Fatalf("reading admin_floor_violations: %v", err)
	}
	if violations != 0 {
		t.Errorf("after rollback admin_floor_violations reported %d deployment violation(s), want 0: "+
			"migration 000053's definition counts the scope union and was not restored", violations)
	}

	// --- re-apply ---------------------------------------------------------
	if err := m.Steps(1); err != nil {
		t.Fatalf("re-applying 000054: %v", err)
	}
	if version, dirty, err := m.Version(); err != nil || version != 54 || dirty {
		t.Fatalf("after re-apply: version %d dirty %v err %v; want 54, clean", version, dirty, err)
	}
	if got := templateScopes(t, db, "admin"); contains(got, "admin") {
		t.Errorf("re-applying 000054 left `admin` on the template: %v", got)
	}
	if !hasCarrierRow(t, db, seed.seededAdminUsr) {
		t.Error("re-applying 000054 did not re-backfill the carrier after the fixture cleared it")
	}
}

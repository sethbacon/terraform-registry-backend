package db_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Issue #766, migration 000052 — the migration itself, applied, rolled back and
// re-applied against a real PostgreSQL.
//
// PR CI does not run migrations (only the manually dispatched chaos workflow
// does), so a migration that fails to apply, or a down that cannot undo it,
// would otherwise be discovered by whoever upgrades first. This exercises the
// full chain on a throwaway database.
//
// It also contains the migration's own mutation verification: after the
// rollback, an UNAUDITED platform-admin grant is shown to commit again. That is
// what proves the refusal in the test above it comes from this migration and
// not from something else in the schema.
//
// Set TFR_TEST_DATABASE_URL to run it. The database it names is only used to
// CREATE and DROP the scratch database; the migrations run there.

const auditOutboxScratchPrefix = "tfr_migr_000052_"

func migrationScratchDB(t *testing.T) (dsn string) {
	t.Helper()

	raw := os.Getenv("TFR_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}
	base, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(base.Scheme, "postgres") {
		t.Skipf("TFR_TEST_DATABASE_URL is not a postgres:// URL (%q)", raw)
	}

	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}

	name := auditOutboxScratchPrefix + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		drop, err := sql.Open("pgx", raw)
		if err != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})

	scratch := *base
	scratch.Path = "/" + name
	return scratch.String()
}

// grantWithoutAnIntent attempts the raw, unaudited carrier mutation and returns
// the commit's error (nil when it committed).
func grantWithoutAnIntent(t *testing.T, db *sql.DB, userID string) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, userID); err != nil {
		_ = tx.Rollback()
		t.Fatalf("INSERT: %v", err)
	}
	return tx.Commit()
}

func objectExists(t *testing.T, db *sql.DB, query string, args ...interface{}) bool {
	t.Helper()
	var present bool
	if err := db.QueryRow(query, args...).Scan(&present); err != nil {
		t.Fatalf("catalogue query failed: %v", err)
	}
	return present
}

const (
	outboxTableExists = `SELECT to_regclass('audit_outbox') IS NOT NULL`
	outboxTrigExists  = `SELECT EXISTS (SELECT 1 FROM pg_trigger
	                       WHERE tgname = 'platform_admins_require_audit_intent' AND NOT tgisinternal)`
)

func TestMigration000052_AppliesRollsBackAndReApplies(t *testing.T) {
	dsn := migrationScratchDB(t)

	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	// Migrated TO 000052 rather than to head. This test rolls 000052 back with
	// Steps(-1) and re-applies it with Steps(1), so it has to start standing on
	// it; migrating to head instead made "the latest migration" and "the
	// migration under test" the same thing only until the next one landed, and
	// 000053 (issue #766's administrator floor) is the one that landed.
	//
	// Naming the target keeps the rest of this test verbatim and makes it
	// robust against every future migration rather than just that one.
	if err := m.Migrate(52); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("applying migrations through 000052: %v", err)
	}
	version, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if dirty {
		t.Fatalf("the schema is dirty at version %d", version)
	}
	if version != 52 {
		t.Fatalf("migrated to version %d, want 52 — this test is not exercising 000052", version)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if !objectExists(t, db, outboxTableExists) {
		t.Error("audit_outbox was not created")
	}
	if !objectExists(t, db, outboxTrigExists) {
		t.Fatal("the platform_admins audit-intent constraint trigger was not created")
	}

	// --- the property, at the head revision -------------------------------
	subject := uuid.New().String()
	if err := grantWithoutAnIntent(t, db, subject); err == nil {
		t.Fatal("an unaudited platform-admin grant committed at version 52")
	} else if !strings.Contains(err.Error(), "no audit intent in this transaction") {
		t.Fatalf("the commit failed with %v, want the audit-intent refusal", err)
	}

	// --- rollback ---------------------------------------------------------
	if err := m.Steps(-1); err != nil {
		t.Fatalf("rolling back 000052: %v", err)
	}
	if version, _, err := m.Version(); err != nil || version != 51 {
		t.Fatalf("after rollback: version %d, err %v; want 51", version, err)
	}
	if objectExists(t, db, outboxTableExists) {
		t.Error("audit_outbox survived the rollback")
	}
	if objectExists(t, db, outboxTrigExists) {
		t.Error("the constraint trigger survived the rollback and now references a dropped table")
	}

	// MUTATION VERIFICATION, in the test itself: with 000052 rolled back the
	// unaudited grant commits again. Without this, the refusal above could be
	// coming from anything.
	if err := grantWithoutAnIntent(t, db, subject); err != nil {
		t.Fatalf("with 000052 rolled back the unaudited grant should commit, but got %v — "+
			"the refusal at version 52 is not attributable to this migration", err)
	}
	if _, err := db.Exec(`DELETE FROM platform_admins WHERE user_id = $1`, subject); err != nil {
		t.Fatalf("cleaning up the rolled-back grant: %v", err)
	}

	// --- re-apply ---------------------------------------------------------
	if err := m.Steps(1); err != nil {
		t.Fatalf("re-applying 000052: %v", err)
	}
	if version, dirty, err := m.Version(); err != nil || version != 52 || dirty {
		t.Fatalf("after re-apply: version %d dirty %v err %v; want 52, clean", version, dirty, err)
	}
	if !objectExists(t, db, outboxTableExists) || !objectExists(t, db, outboxTrigExists) {
		t.Fatal("re-applying 000052 did not restore the outbox and its trigger")
	}
	if err := grantWithoutAnIntent(t, db, uuid.New().String()); err == nil {
		t.Fatal("an unaudited platform-admin grant committed after 000052 was re-applied")
	}
}

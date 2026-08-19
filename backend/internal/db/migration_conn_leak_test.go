package db_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/terraform-registry/terraform-registry/internal/db"
)

// Issue #788 — the migration helpers leaked a pooled connection.
//
// postgres.WithInstance checks out a *sql.Conn and holds it for the driver's
// lifetime; neither helper closed the driver, so every call permanently
// consumed one slot of the caller's MaxOpenConns. cmd/server/main.go calls
// GetMigrationVersion with the long-lived application pool (25 connections),
// so the slot was never reclaimed — and that pool backs identity queries on
// the auth hot path.
//
// The obvious fix is a trap worth naming: postgres.WithInstance records the
// *sql.DB on the driver, so driver.Close()/m.Close() closes the caller's
// shared pool. "defer m.Close()" would have turned a one-connection leak into
// a closed application pool at startup. The helpers now borrow a connection
// explicitly and use postgres.WithConnection, which leaves that field nil.

// TestMigrationHelpers_DoNotUseWithInstance is the re-runnable signature for
// the defect, and the half that runs everywhere — no database required.
//
// The behavioural test below is the honest proof, but it only runs where a
// Postgres is reachable. This one fails in any environment the moment the
// pool-closing constructor reappears, including in a new helper nobody thought
// to write a connection test for.
func TestMigrationHelpers_DoNotUseWithInstance(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Fail rather than pass vacuously if the glob ever stops finding this
	// package's sources.
	if len(sources) == 0 {
		t.Fatal("no .go sources found — this guard is not scanning anything")
	}

	var scanned int
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			// Skip prose: the fix is explained in a comment that names the
			// symbol on purpose.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(line, "postgres.WithInstance(") {
				t.Errorf("%s:%d uses postgres.WithInstance, which records the caller's "+
					"*sql.DB on the driver — the driver then holds a pooled connection "+
					"for its lifetime AND its Close() closes the caller's pool. Use "+
					"newMigrator/closeMigrator (postgres.WithConnection over a borrowed "+
					"connection) instead. See issue #788.", path, i+1)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no non-test sources — the guard is vacuous")
	}
}

// TestGetMigrationVersion_ReturnsItsConnectionToThePool is the test the issue
// asked for: a pool of exactly one connection, so a leak is not a statistic
// but a deadlock.
//
// Asserted against a context deadline rather than db.Stats(), because the
// failure mode is that the next query BLOCKS waiting for a connection that
// will never come back. Stats alone would report a plausible-looking
// InUse count and tell you nothing about whether the pool still works.
//
// Set TFR_TEST_DATABASE_URL to run this (any reachable Postgres; the helpers
// only read golang-migrate's version table).
func TestGetMigrationVersion_ReturnsItsConnectionToThePool(t *testing.T) {
	dsn := os.Getenv("TFR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}

	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer pool.Close()

	// One connection. With the leak, the helper takes it and never gives it
	// back, and every subsequent query waits forever.
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}

	// Call it more than once: a per-call leak with MaxOpenConns(1) blocks on
	// the second call, which is itself the regression signal.
	for i := 0; i < 3; i++ {
		if _, _, err := db.GetMigrationVersion(pool); err != nil {
			t.Fatalf("GetMigrationVersion call %d: %v", i+1, err)
		}
	}

	// The real assertion: the pool still serves queries. A short deadline, so
	// a leak fails fast and unambiguously instead of hanging the suite.
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer queryCancel()

	var one int
	if err := pool.QueryRowContext(queryCtx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("pool is unusable after GetMigrationVersion — the borrowed "+
			"connection was never returned (issue #788): %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 returned %d", one)
	}

	// Stats is a secondary check, not the assertion: with the connection
	// returned, nothing should still be checked out.
	if inUse := pool.Stats().InUse; inUse != 0 {
		t.Errorf("pool reports %d connection(s) still in use after the helper returned", inUse)
	}
}

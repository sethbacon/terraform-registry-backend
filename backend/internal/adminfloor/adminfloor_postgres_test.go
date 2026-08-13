package adminfloor

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// The concurrency half of issue #766, against a real Postgres.
//
// sqlmock can show that the lock is TAKEN before the floor is read
// (TestProtect_TakesTheLockBeforeReadingAnything does), but it cannot show
// that the lock WORKS — that a second caller waits for the first, and then
// sees the world the first one left behind. Only a real database can.
//
// AND THE INTERLEAVING IS FORCED, NOT RACED. PR #862 recorded the lesson
// directly: its two-goroutine test passed with AND without the FOR UPDATE,
// because the window between "read the remaining grants" and "delete the row"
// is a few hundred microseconds and two goroutines started together do not
// reliably land inside it. A test that cannot fail without the fix is not
// evidence of the fix.
//
// So this does not race. It pins the schedule:
//
//	1. remover A enters Protect, takes the lock, and BLOCKS on a test hook
//	   before reading anything
//	2. remover B enters Protect and blocks on pg_advisory_xact_lock
//	3. the test WAITS UNTIL POSTGRES ITSELF REPORTS B AS WAITING (pg_locks),
//	   so the blocking is observed rather than assumed
//	4. A is released; it reads two administrators, removes one, commits
//	5. B wakes, reads ONE administrator, and refuses
//
// Set TFR_TEST_DATABASE_URL to run these. Every table is created in a
// throwaway schema selected through the connection string, so nothing outside
// it is touched.

const testSchema = "adminfloor_test"

// postgresPool opens a pool whose search_path is the throwaway schema, creates
// that schema, and lays out the five tables the floor reads.
func postgresPool(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TFR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}

	// Bootstrap on the caller's own search_path to create the schema, then
	// reopen pinned to it. Done in two steps because `options=-c search_path=X`
	// makes every connection in the pool fail until X exists.
	bootstrap, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := bootstrap.PingContext(ctx); err != nil {
		bootstrap.Close()
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}
	if _, err := bootstrap.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`); err != nil {
		bootstrap.Close()
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := bootstrap.ExecContext(ctx, `CREATE SCHEMA `+testSchema); err != nil {
		bootstrap.Close()
		t.Fatalf("create schema: %v", err)
	}
	bootstrap.Close()

	scoped, err := withSearchPath(dsn, testSchema)
	if err != nil {
		t.Fatalf("build scoped dsn: %v", err)
	}
	pool, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatalf("sql.Open (scoped): %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, err := sql.Open("postgres", dsn)
		if err != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`)
	})

	// The columns the floor actually reads, with the types migration 000001
	// and 000051 give them. scopes is JSONB here, the registry's own encoding;
	// the TEXT[] form the shared identity schema uses is covered by
	// TestParseRoleScopes, which does not need a database.
	schema := []string{
		`CREATE TABLE users (id UUID PRIMARY KEY, email VARCHAR(255) NOT NULL)`,
		`CREATE TABLE organizations (id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL)`,
		`CREATE TABLE role_templates (id UUID PRIMARY KEY, name VARCHAR(100) NOT NULL, scopes JSONB NOT NULL DEFAULT '[]')`,
		`CREATE TABLE organization_members (
			organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			role_template_id UUID REFERENCES role_templates(id) ON DELETE SET NULL,
			PRIMARY KEY (organization_id, user_id))`,
		`CREATE TABLE platform_admins (user_id UUID PRIMARY KEY, granted_by UUID, granted_at TIMESTAMPTZ NOT NULL DEFAULT now(), note TEXT)`,
	}
	for _, stmt := range schema {
		if _, err := pool.Exec(stmt); err != nil {
			t.Fatalf("create schema object: %v\n%s", err, stmt)
		}
	}
	return pool
}

// withSearchPath rewrites a DSN so every connection from the pool resolves
// unqualified table names in schema and nowhere else.
func withSearchPath(dsn, schema string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("options", "-c search_path="+schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

const (
	orgMain     = "aaaaaaaa-0000-0000-0000-000000000001"
	tmplAdmin   = "bbbbbbbb-0000-0000-0000-000000000001"
	tmplViewer  = "bbbbbbbb-0000-0000-0000-000000000002"
	userAdminA  = "cccccccc-0000-0000-0000-00000000000a"
	userAdminB  = "cccccccc-0000-0000-0000-00000000000b"
	userViewerC = "cccccccc-0000-0000-0000-00000000000c"
)

// seedTwoAdministrators lays out the state both concurrency tests start from:
// one organization, two administrators, one plain member, and an EMPTY
// carrier — the shape a deployment bootstrapped by the setup wizard before
// this release actually has.
func seedTwoAdministrators(t *testing.T, pool *sql.DB) {
	t.Helper()
	stmts := []string{
		`INSERT INTO organizations (id, name) VALUES ('` + orgMain + `', 'acme')`,
		`INSERT INTO role_templates (id, name, scopes) VALUES ('` + tmplAdmin + `', 'admin', '["admin"]'::jsonb)`,
		`INSERT INTO role_templates (id, name, scopes) VALUES ('` + tmplViewer + `', 'viewer', '["modules:read"]'::jsonb)`,
		`INSERT INTO users (id, email) VALUES ('` + userAdminA + `', 'a@example.com')`,
		`INSERT INTO users (id, email) VALUES ('` + userAdminB + `', 'b@example.com')`,
		`INSERT INTO users (id, email) VALUES ('` + userViewerC + `', 'c@example.com')`,
		`INSERT INTO organization_members VALUES ('` + orgMain + `', '` + userAdminA + `', '` + tmplAdmin + `')`,
		`INSERT INTO organization_members VALUES ('` + orgMain + `', '` + userAdminB + `', '` + tmplAdmin + `')`,
		`INSERT INTO organization_members VALUES ('` + orgMain + `', '` + userViewerC + `', '` + tmplViewer + `')`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}
}

func administratorsRemaining(t *testing.T, pool *sql.DB) int {
	t.Helper()
	var n int
	err := pool.QueryRow(`
		SELECT count(*)
		  FROM organization_members om
		  JOIN users u ON u.id = om.user_id
		  JOIN role_templates rt ON rt.id = om.role_template_id
		 WHERE rt.scopes @> '["admin"]'::jsonb`).Scan(&n)
	if err != nil {
		t.Fatalf("count administrators: %v", err)
	}
	return n
}

// waitForAdvisoryLockWaiter blocks until Postgres reports somebody WAITING on
// the floor's advisory lock. This is the step that makes the interleaving
// forced rather than hoped for: without it the test would release the first
// remover on a timer and could not tell a serialised run from a lucky one.
func waitForAdvisoryLockWaiter(t *testing.T, pool *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		err := pool.QueryRow(`
			SELECT count(*) FROM pg_locks
			 WHERE locktype = 'advisory' AND granted = false`).Scan(&waiting)
		if err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no session ever blocked on the administrator-floor advisory lock — the second " +
		"remover was never serialised behind the first, so this test is not exercising the lock " +
		"at all and would pass with it removed")
}

// removeMember is the write both removers perform.
func removeMember(pool *sql.DB, userID string) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := pool.ExecContext(ctx,
			`DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`, orgMain, userID)
		return err
	}
}

// TestProtect_ConcurrentRemovalsCannotBothPass is the headline concurrency
// assertion: two well-formed requests, each removing a different one of the
// deployment's two administrators, must not both succeed.
func TestProtect_ConcurrentRemovalsCannotBothPass(t *testing.T) {
	pool := postgresPool(t)
	seedTwoAdministrators(t, pool)

	// Two guards over the same pools, as two HTTP requests would be.
	first := New(pool, pool)
	second := New(pool, pool)

	entered := make(chan struct{})
	release := make(chan struct{})
	// Released through a sync.Once registered as a cleanup, not with a bare
	// close(). A t.Fatal below returns from THIS goroutine while the first
	// remover is still parked in beforeCheck holding an open transaction, and
	// the pool's own cleanup then blocks forever waiting for that connection:
	// the test would hang instead of failing, which is what the first run of
	// the lock mutation actually did.
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	first.beforeCheck = func(context.Context) {
		close(entered)
		<-release
	}

	type outcome struct {
		err error
	}
	firstDone := make(chan outcome, 1)
	secondDone := make(chan outcome, 1)

	change := func(userID string) Change {
		return Change{UserID: userID, OrganizationIDs: []string{orgMain}, RemovesMembership: true}
	}

	go func() {
		firstDone <- outcome{first.Protect(context.Background(), change(userAdminA), removeMember(pool, userAdminA))}
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first remover never reached the floor check")
	}

	go func() {
		secondDone <- outcome{second.Protect(context.Background(), change(userAdminB), removeMember(pool, userAdminB))}
	}()

	// Observed, not assumed: the second remover is blocked on the lock.
	waitForAdvisoryLockWaiter(t, pool)

	releaseAll()

	var firstErr, secondErr error
	select {
	case o := <-firstDone:
		firstErr = o.err
	case <-time.After(15 * time.Second):
		t.Fatal("the first remover never finished")
	}
	select {
	case o := <-secondDone:
		secondErr = o.err
	case <-time.After(15 * time.Second):
		t.Fatal("the second remover never finished — the lock was not released")
	}

	if firstErr != nil {
		t.Fatalf("the first removal failed: %v — it ran against two administrators and must succeed", firstErr)
	}
	if !errors.Is(secondErr, ErrLastPlatformAdmin) {
		t.Fatalf("the second removal returned %v, want ErrLastPlatformAdmin — it ran AFTER the "+
			"first one committed and must see only one administrator left", secondErr)
	}
	if n := administratorsRemaining(t, pool); n != 1 {
		t.Fatalf("%d administrator(s) remain, want exactly 1 — two concurrent removals took the "+
			"deployment below the floor", n)
	}
}

// TestUnserialisedRemovalsReachZero is the falsification, kept permanently
// rather than run once and described in a commit message.
//
// It performs the SAME two removals with the same schedule and the same
// check — "is there another administrator?" — but WITHOUT the lock, and
// asserts that the deployment reaches zero administrators. If this ever stops
// reaching zero, the scenario has drifted and the test above is no longer
// exercising the hazard it claims to.
func TestUnserialisedRemovalsReachZero(t *testing.T) {
	pool := postgresPool(t)
	seedTwoAdministrators(t, pool)

	// The naive shape: read, then write, with no lock between them.
	othersRemain := func(userID string) bool {
		var n int
		if err := pool.QueryRow(`
			SELECT count(*)
			  FROM organization_members om
			  JOIN users u ON u.id = om.user_id
			  JOIN role_templates rt ON rt.id = om.role_template_id
			 WHERE rt.scopes @> '["admin"]'::jsonb AND om.user_id <> $1`, userID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n > 0
	}

	// Both readers run BEFORE either writer — the interleaving forced by hand,
	// which is exactly what two requests hitting the window would produce.
	aSeesAnother := othersRemain(userAdminA)
	bSeesAnother := othersRemain(userAdminB)
	if !aSeesAnother || !bSeesAnother {
		t.Fatal("both removers should observe another administrator before either writes; " +
			"the seed no longer sets up the race this test exists to demonstrate")
	}
	if err := removeMember(pool, userAdminA)(context.Background()); err != nil {
		t.Fatalf("remove A: %v", err)
	}
	if err := removeMember(pool, userAdminB)(context.Background()); err != nil {
		t.Fatalf("remove B: %v", err)
	}

	if n := administratorsRemaining(t, pool); n != 0 {
		t.Fatalf("%d administrator(s) remain, want 0 — the unserialised sequence no longer "+
			"reaches the state the lock exists to prevent, so the serialised test above proves "+
			"nothing", n)
	}
}

// TestProtect_ReleasesTheLockOnEveryPath. The lock is scoped to a transaction
// that is always rolled back, so a refusal, an error and a success must all
// leave it free. A leaked advisory lock would wedge every subsequent
// administrative write in the deployment — a far worse outcome than the
// refusal it leaked on.
func TestProtect_ReleasesTheLockOnEveryPath(t *testing.T) {
	pool := postgresPool(t)
	seedTwoAdministrators(t, pool)
	g := New(pool, pool)
	ctx := context.Background()

	writeErr := errors.New("the write itself failed")
	cases := []struct {
		name   string
		change Change
		write  func(context.Context) error
		want   error
	}{
		{
			name:   "allowed",
			change: Change{UserID: userViewerC, OrganizationIDs: []string{orgMain}, RemovesMembership: true},
			write:  removeMember(pool, userViewerC),
		},
		{
			name:   "refused",
			change: Change{UserID: userAdminA, OrganizationIDs: []string{orgMain}, RemovesMembership: true},
			write:  func(context.Context) error { return nil },
		},
		{
			name:   "write failed",
			change: Change{UserID: userAdminA, OrganizationIDs: []string{orgMain}, RemovesMembership: true},
			write:  func(context.Context) error { return writeErr },
		},
		{
			name:   "indeterminate",
			change: Change{RemovesMembership: true},
			write:  func(context.Context) error { return nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = g.Protect(ctx, tc.change, tc.write)
			var held int
			if err := pool.QueryRow(
				`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'`).Scan(&held); err != nil {
				t.Fatalf("read pg_locks: %v", err)
			}
			if held != 0 {
				t.Fatalf("%d advisory lock(s) still held after the %s path — the floor's lock leaked, "+
					"and every later administrative write in this deployment will block on it", held, tc.name)
			}
		})
	}

	// The "refused" and "write failed" cases must also have left the data
	// alone; a released lock over a half-applied change would be worse than a
	// leak. userAdminA is still an administrator, userViewerC is not a member.
	if n := administratorsRemaining(t, pool); n != 2 {
		t.Fatalf("%d administrator(s) remain, want 2 — a refused change was written anyway", n)
	}
}

// TestProtect_UsesADeterministicLockKey. Two separately constructed Guards must
// contend on the SAME key, or the serialisation is per-process and buys
// nothing in a multi-replica deployment.
func TestProtect_UsesADeterministicLockKey(t *testing.T) {
	pool := postgresPool(t)

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)

	first := New(pool, pool)
	first.beforeCheck = func(context.Context) {
		close(held)
		<-release
	}
	go func() {
		done <- first.Serialize(context.Background(), func(context.Context) error { return nil })
	}()
	<-held

	// A second, independently constructed Guard must block.
	second := New(pool, pool)
	blocked := make(chan error, 1)
	go func() {
		blocked <- second.Serialize(context.Background(), func(context.Context) error { return nil })
	}()
	waitForAdvisoryLockWaiter(t, pool)

	releaseAll()
	if err := <-done; err != nil {
		t.Fatalf("first Serialize: %v", err)
	}
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("second Serialize: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the second Serialize never completed after the lock was released")
	}
}

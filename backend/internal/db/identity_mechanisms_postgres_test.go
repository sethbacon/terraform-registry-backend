package db_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// The shared identity library's mechanisms — identity/platformadmin and
// identity/auditoutbox — against THIS repository's real, migrated tables
// (terraform-suite-identity#206, phase 2).
//
// The mechanisms have their own unit and integration tests in the library,
// against DDL the library renders. This file asks the only question those
// cannot: do they work against the tables migrations 000051 and 000052 actually
// created here, in the topology this repository ships by default — carrier and
// outbox in `public`, `audit_logs` the registry's own (which has never had
// actor_email; issue #864).
//
// PR CI does not run migrations. Set TFR_TEST_DATABASE_URL to run this.

// migratedRegistry brings a scratch database up to head and returns a pool on
// it.
func migratedRegistry(t *testing.T) *sql.DB {
	t.Helper()
	dsn := migrationScratchDB(t)

	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// carrierAndOutbox constructs both mechanisms exactly as internal/api/router.go
// does — unqualified names, resolved by the connection's search_path.
func carrierAndOutbox(t *testing.T, db *sql.DB) (*platformadmin.Carrier, *auditoutbox.Outbox) {
	t.Helper()
	carrier, err := platformadmin.New(db, "platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	outbox, err := auditoutbox.New(db, "audit_outbox")
	if err != nil {
		t.Fatalf("auditoutbox.New: %v", err)
	}
	return carrier, outbox
}

// seedUser inserts a users row, since the carrier deliberately holds no foreign
// key to one.
func seedUser(t *testing.T, db *sql.DB, id, email string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, id, email, "Test User"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func grantIntent(outbox *auditoutbox.Outbox, action, target string) platformadmin.AuditIntentWriter {
	resourceType := platformadmin.AuditResourceType
	resourceID := target
	return platformadmin.AuditIntentWriter(outbox.Writer(&auditoutbox.Intent{
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Metadata:     map[string]interface{}{"target_user_id": target},
	}))
}

func carrierRowCount(t *testing.T, db *sql.DB, userID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM platform_admins WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count carrier rows: %v", err)
	}
	return n
}

// TestCarrierVerifiesAgainstTheMigratedTable is the startup assertion
// internal/api/router.go makes, run against the real schema — and then against
// a table that has every expected COLUMN and no unique index on user_id, which
// is the shape that passes a column-only check and then fails every grant with
// "no unique or exclusion constraint matching the ON CONFLICT specification".
func TestCarrierVerifiesAgainstTheMigratedTable(t *testing.T) {
	db := migratedRegistry(t)
	carrier, _ := carrierAndOutbox(t, db)

	resolved, err := carrier.VerifyTable(context.Background())
	if err != nil {
		t.Fatalf("VerifyTable: %v", err)
	}
	if resolved != "public.platform_admins" {
		t.Errorf("resolved = %q, want %q — the operator is told where grants are read from",
			resolved, "public.platform_admins")
	}

	// Same columns, same types, no arbiter for ON CONFLICT (user_id).
	if _, err := db.Exec(`CREATE SCHEMA no_index;
		CREATE TABLE no_index.platform_admins (
			user_id UUID NOT NULL,
			granted_by UUID,
			granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			note TEXT)`); err != nil {
		t.Fatalf("create the index-less carrier: %v", err)
	}
	unindexed, err := platformadmin.New(db, "no_index.platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	_, err = unindexed.VerifyTable(context.Background())
	if !errors.Is(err, platformadmin.ErrTableShape) {
		t.Fatalf("VerifyTable = %v, want platformadmin.ErrTableShape on a carrier with no unique "+
			"index on user_id", err)
	}
	if !strings.Contains(err.Error(), "unique index") {
		t.Errorf("VerifyTable error = %q, want it to name the missing unique index", err)
	}

	// And the failure it predicts is real: the grant that table would accept in
	// a column-only world does not run.
	_, grantErr := unindexed.Grant(context.Background(), uuid.New().String(), nil, nil,
		func(context.Context, *sql.Tx) error { return nil })
	if grantErr == nil {
		t.Fatal("a grant succeeded against a carrier with no ON CONFLICT arbiter")
	}
	if !strings.Contains(grantErr.Error(), "ON CONFLICT") {
		t.Errorf("grant error = %q, want the ON CONFLICT arbiter failure the index check predicts", grantErr)
	}
}

// TestGrantAndRevokeCommitWithTheirAuditIntent exercises the whole contract
// against migration 000052's deferred constraint trigger: a grant carrying its
// intent commits, and one carrying a writer that records nothing does not — the
// property holds at the database, not merely in the Go layer.
func TestGrantAndRevokeCommitWithTheirAuditIntent(t *testing.T) {
	db := migratedRegistry(t)
	carrier, outbox := carrierAndOutbox(t, db)
	ctx := context.Background()

	first := uuid.New().String()
	second := uuid.New().String()
	seedUser(t, db, first, "first@example.com")
	seedUser(t, db, second, "second@example.com")

	if _, err := carrier.Grant(ctx, first, nil, nil,
		grantIntent(outbox, platformadmin.AuditActionGranted, first)); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if got := carrierRowCount(t, db, first); got != 1 {
		t.Fatalf("carrier rows for the grantee = %d, want 1", got)
	}

	// A writer that writes NOTHING. The Go layer is satisfied — a writer was
	// supplied — so the refusal here can only come from the trigger.
	_, err := carrier.Grant(ctx, second, nil, nil, func(context.Context, *sql.Tx) error { return nil })
	if err == nil {
		t.Fatal("an unaudited grant committed")
	}
	if !strings.Contains(err.Error(), "no audit intent in this transaction") {
		t.Fatalf("err = %v, want migration 000052's audit-intent refusal", err)
	}
	if got := carrierRowCount(t, db, second); got != 0 {
		t.Fatalf("carrier rows for the unaudited grantee = %d, want 0 — the refusal must take the "+
			"grant with it", got)
	}

	// The floor: the only exercisable administrator cannot be revoked.
	resolver := platformadmin.ResolverFunc(func(ctx context.Context, userID string) (bool, error) {
		var exists bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists)
		return exists, err
	})
	_, err = carrier.Revoke(ctx, first, platformadmin.RequireAnotherExercisableAdmin(resolver),
		grantIntent(outbox, platformadmin.AuditActionRevoked, first))
	if !errors.Is(err, platformadmin.ErrLastPlatformAdmin) {
		t.Fatalf("Revoke = %v, want ErrLastPlatformAdmin", err)
	}
	if got := carrierRowCount(t, db, first); got != 1 {
		t.Fatalf("carrier rows after the refusal = %d, want the grant still there", got)
	}

	// An ORPHANED second grant does not lift the floor: the row exists, the
	// principal does not.
	orphan := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, orphan); err != nil {
		// The trigger refuses an unaudited INSERT, so the orphan is seeded
		// through the mechanism and its user row removed afterwards.
		seedUser(t, db, orphan, "orphan@example.com")
		if _, gErr := carrier.Grant(ctx, orphan, nil, nil,
			grantIntent(outbox, platformadmin.AuditActionGranted, orphan)); gErr != nil {
			t.Fatalf("seed the orphan grant: %v", gErr)
		}
		if _, dErr := db.Exec(`DELETE FROM users WHERE id = $1`, orphan); dErr != nil {
			t.Fatalf("delete the orphan's user: %v", dErr)
		}
	}
	_, err = carrier.Revoke(ctx, first, platformadmin.RequireAnotherExercisableAdmin(resolver),
		grantIntent(outbox, platformadmin.AuditActionRevoked, first))
	if !errors.Is(err, platformadmin.ErrLastPlatformAdmin) {
		t.Fatalf("Revoke = %v, want ErrLastPlatformAdmin: an orphaned grant is a record, not an "+
			"administrator", err)
	}

	// A lookup FAILURE is not "everybody else is gone".
	broken := platformadmin.ResolverFunc(func(context.Context, string) (bool, error) {
		return false, errors.New("identity store unreachable")
	})
	_, err = carrier.Revoke(ctx, first, platformadmin.RequireAnotherExercisableAdmin(broken),
		grantIntent(outbox, platformadmin.AuditActionRevoked, first))
	if !errors.Is(err, platformadmin.ErrIdentityUnavailable) {
		t.Fatalf("Revoke = %v, want ErrIdentityUnavailable", err)
	}
	if errors.Is(err, platformadmin.ErrLastPlatformAdmin) {
		t.Error("an identity outage was reported as the last-administrator refusal; the two must " +
			"stay distinguishable")
	}

	// With a live second administrator, the revocation proceeds and takes its
	// audit intent with it.
	if _, err := carrier.Grant(ctx, second, &first, nil,
		grantIntent(outbox, platformadmin.AuditActionGranted, second)); err != nil {
		t.Fatalf("Grant (second): %v", err)
	}
	if _, err := carrier.Revoke(ctx, first, platformadmin.RequireAnotherExercisableAdmin(resolver),
		grantIntent(outbox, platformadmin.AuditActionRevoked, first)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := carrierRowCount(t, db, first); got != 0 {
		t.Fatalf("carrier rows after the revocation = %d, want 0", got)
	}

	var intents int
	if err := db.QueryRow(
		`SELECT count(*) FROM audit_outbox WHERE resource_type = 'platform_admin'`).Scan(&intents); err != nil {
		t.Fatalf("count intents: %v", err)
	}
	// Two grants and one revocation landed; the refused ones wrote nothing.
	if intents != 4 {
		t.Errorf("audit intents = %d, want 4 (two grants, the orphan's grant, one revocation)", intents)
	}
}

// TestSinkDeliversIntoTheRegistrysOwnAuditLogs is the topology issue #864 is
// about: `audit_logs` resolves to this repository's own public.audit_logs,
// which has no actor_email. The library's sink asks the destination which
// columns it has and inserts the intersection, so delivery works here — and a
// redelivery collapses on the destination's primary key rather than appending a
// second copy.
func TestSinkDeliversIntoTheRegistrysOwnAuditLogs(t *testing.T) {
	db := migratedRegistry(t)
	ctx := context.Background()

	var hasActorEmail bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_attribute
		 WHERE attrelid = to_regclass('audit_logs') AND attname = 'actor_email' AND NOT attisdropped)`).
		Scan(&hasActorEmail); err != nil {
		t.Fatalf("probe audit_logs: %v", err)
	}
	if hasActorEmail {
		t.Skip("this deployment's audit_logs already carries actor_email; the intersection this " +
			"test exercises is not the one that ships")
	}

	sink, err := auditoutbox.NewTableSink(db, "audit_logs")
	if err != nil {
		t.Fatalf("NewTableSink: %v", err)
	}
	resolved, err := sink.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if resolved != "public.audit_logs" {
		t.Errorf("resolved = %q, want %q", resolved, "public.audit_logs")
	}

	actor := uuid.New().String()
	email := "actor@example.com"
	seedUser(t, db, actor, email)
	resourceType := platformadmin.AuditResourceType
	resourceID := uuid.New().String()
	intent := auditoutbox.Intent{
		EventID:      uuid.New().String(),
		OccurredAt:   time.Now().UTC().Truncate(time.Millisecond),
		Action:       platformadmin.AuditActionGranted,
		ActorUserID:  &actor,
		ActorEmail:   &email,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Metadata:     map[string]interface{}{"target_user_id": resourceID},
	}

	if err := sink.Deliver(ctx, intent); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	// At-least-once transport, exactly-once in effect.
	if err := sink.Deliver(ctx, intent); err != nil {
		t.Fatalf("redeliver: %v", err)
	}

	var rows int
	var action, gotResource string
	if err := db.QueryRow(
		`SELECT count(*) FROM audit_logs WHERE id = $1`, intent.EventID).Scan(&rows); err != nil {
		t.Fatalf("count delivered rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("delivered rows = %d, want exactly 1 after two deliveries", rows)
	}
	if err := db.QueryRow(
		`SELECT action, resource_id FROM audit_logs WHERE id = $1`, intent.EventID).
		Scan(&action, &gotResource); err != nil {
		t.Fatalf("read the delivered row: %v", err)
	}
	if action != platformadmin.AuditActionGranted {
		t.Errorf("action = %q, want %q", action, platformadmin.AuditActionGranted)
	}
	if gotResource != resourceID {
		t.Errorf("resource_id = %q, want %q", gotResource, resourceID)
	}
}

// TestTriggerRejectsAMismatchedOrStaleIntent pins what migration 000052's
// trigger actually requires, which is more than "an intent exists": one naming
// THIS subject, with THIS action, written in THIS transaction.
//
// It is registry's own SQL rather than the library's — the mechanism supplies
// the intent, the migration decides whether it counts — so it is asserted here.
// It travelled with internal/audit's integration tests before those moved into
// identity/auditoutbox; the outbox below is the library's, the property is this
// repository's.
func TestTriggerRejectsAMismatchedOrStaleIntent(t *testing.T) {
	db := migratedRegistry(t)
	_, outbox := carrierAndOutbox(t, db)
	ctx := context.Background()

	target := uuid.New().String()
	other := uuid.New().String()
	seedUser(t, db, target, "target@example.com")
	seedUser(t, db, other, "other@example.com")

	intent := func(action, subject string) *auditoutbox.Intent {
		resourceType := platformadmin.AuditResourceType
		resourceID := subject
		return &auditoutbox.Intent{
			EventID:      uuid.New().String(),
			Action:       action,
			ResourceType: &resourceType,
			ResourceID:   &resourceID,
		}
	}

	t.Run("intent names another subject", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := outbox.Enqueue(ctx, tx, intent(platformadmin.AuditActionGranted, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("a grant committed against an audit record naming somebody else")
		} else if !strings.Contains(err.Error(), "no audit intent in this transaction") {
			t.Fatalf("commit failed with %v, want the audit-intent refusal", err)
		}
	})

	t.Run("intent from an earlier transaction", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if err := outbox.Enqueue(ctx, tx, intent(platformadmin.AuditActionGranted, target)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("committing the intent alone: %v", err)
		}

		second, err := db.Begin()
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		defer func() { _ = second.Rollback() }()
		if _, err := second.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := second.Commit(); err == nil {
			t.Fatal("a grant committed against an audit record written by an EARLIER transaction; " +
				"\"same transaction\" is the property, and a foreign key would not have expressed it")
		}
	})

	t.Run("revocation under a grant's record", func(t *testing.T) {
		carrier, _ := carrierAndOutbox(t, db)
		if _, err := carrier.Grant(ctx, other, nil, nil,
			grantIntent(outbox, platformadmin.AuditActionGranted, other)); err != nil {
			t.Fatalf("Grant: %v", err)
		}

		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`DELETE FROM platform_admins WHERE user_id = $1`, other); err != nil {
			t.Fatalf("delete: %v", err)
		}
		// The wrong ACTION: a revocation cannot commit under a record that says
		// "granted".
		if err := outbox.Enqueue(ctx, tx, intent(platformadmin.AuditActionGranted, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("a REVOCATION committed under a record that says \"granted\"")
		}
		if got := carrierRowCount(t, db, other); got != 1 {
			t.Errorf("carrier rows = %d, want the grant still there after the refused commit", got)
		}
	})
}

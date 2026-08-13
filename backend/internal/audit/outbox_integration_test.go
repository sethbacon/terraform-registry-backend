package audit

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Issue #766 — the evidence that the audit trail is durable, against a real
// PostgreSQL rather than a mock.
//
// Three of the four claims in this design cannot be proved anywhere else:
//
//   - "a privileged mutation cannot commit without its audit record" is
//     enforced by a DEFERRABLE constraint trigger, and only a real commit can
//     be refused by one;
//   - "redelivery does not duplicate" is enforced by audit_logs' primary key;
//   - "a crash mid-flight loses nothing" needs a transaction that really dies.
//     It is forced here by terminating the relay's backend while it is parked
//     inside its transaction, not by racing goroutines and hoping.
//
// Set TFR_TEST_DATABASE_URL to run these. Each test builds its own throwaway
// database and drops it afterwards, so nothing is written to the database the
// URL points at beyond the CREATE/DROP.

// minimalSchema is the part of the estate these tests need: the carrier
// (migration 000051), the audit destination and the users table the sink's
// actor_email fallback resolves against. Migration 000052 itself is then
// applied VERBATIM from disk, so the trigger under test is the one that ships.
var minimalSchema = []string{
	`CREATE TABLE users (
		id UUID PRIMARY KEY,
		email VARCHAR(255) NOT NULL,
		name VARCHAR(255),
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
	`CREATE TABLE audit_logs (
		id UUID PRIMARY KEY,
		user_id UUID,
		organization_id UUID,
		action VARCHAR(500) NOT NULL,
		resource_type VARCHAR(100),
		resource_id VARCHAR(255),
		ip_address VARCHAR(45),
		metadata JSONB,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		actor_email VARCHAR(255))`,
	`CREATE TABLE platform_admins (
		user_id UUID PRIMARY KEY,
		granted_by UUID,
		granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		note TEXT)`,
}

// scratchDB creates a throwaway database, applies the schema above plus
// migration 000052, and returns a connection to it.
func scratchDB(t *testing.T) (*sql.DB, string) {
	t.Helper()

	raw := os.Getenv("TFR_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TFR_TEST_DATABASE_URL not set — needs a reachable Postgres")
	}
	base, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(base.Scheme, "postgres") {
		t.Skipf("TFR_TEST_DATABASE_URL is not a postgres:// URL (%q); these tests need one to create a scratch database", raw)
	}

	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("Postgres not reachable at TFR_TEST_DATABASE_URL: %v", err)
	}

	name := "tfr_audit_outbox_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}

	scratch := *base
	scratch.Path = "/" + name
	db, err := sql.Open("postgres", scratch.String())
	if err != nil {
		t.Fatalf("sql.Open(scratch): %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		drop, err := sql.Open("postgres", raw)
		if err != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})

	for _, stmt := range minimalSchema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("schema setup failed (%s): %v", stmt, err)
		}
	}
	migration, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000052_audit_outbox.up.sql"))
	if err != nil {
		t.Fatalf("reading migration 000052: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("applying migration 000052: %v", err)
	}
	return db, scratch.String()
}

func seedUser(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	id := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, id, email, email); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
	return id
}

func countRows(t *testing.T, db *sql.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

// grantIntent is the intent the carrier's management API writes.
func grantIntent(actorID, targetID string) *Intent {
	resource := "platform_admin"
	ip := "203.0.113.7"
	return &Intent{
		Action:       "platform_admin.granted",
		ActorUserID:  &actorID,
		ResourceType: &resource,
		ResourceID:   &targetID,
		IPAddress:    &ip,
		Metadata:     map[string]interface{}{"target_user_id": targetID},
	}
}

// grantWithIntent performs the mutation and its audit intent in one
// transaction, exactly as PlatformAdminRepository.Grant does.
func grantWithIntent(t *testing.T, db *sql.DB, outbox *Outbox, actorID, targetID string) *Intent {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`INSERT INTO platform_admins (user_id, granted_by) VALUES ($1, $2)`, targetID, actorID); err != nil {
		t.Fatalf("granting: %v", err)
	}
	intent := grantIntent(actorID, targetID)
	if err := outbox.Enqueue(context.Background(), tx, intent); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return intent
}

// ---------------------------------------------------------------------------
// GUARD durable-audit-trigger — the database refuses the unaudited commit
// ---------------------------------------------------------------------------

// THE PROPERTY, ENFORCED RATHER THAN INTENDED. This is the case the Go layer
// cannot cover: hand-written SQL, a migration, a future handler that forgets.
// The trigger is DEFERRABLE INITIALLY DEFERRED, so the INSERT itself succeeds
// and the COMMIT is what fails — and the carrier is unchanged afterwards.
func TestIntegration_CarrierMutationWithoutAnIntentCannotCommit(t *testing.T) {
	db, _ := scratchDB(t)
	target := seedUser(t, db, "target@example.com")

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, target); err != nil {
		t.Fatalf("the INSERT itself should succeed; the deferred check happens at COMMIT: %v", err)
	}
	err = tx.Commit()
	if err == nil {
		t.Fatal("an unaudited platform-admin grant COMMITTED; migration 000052's constraint trigger is not enforcing")
	}
	if !strings.Contains(err.Error(), "no audit intent in this transaction") {
		t.Fatalf("commit failed with %v, want the audit-intent refusal", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM platform_admins`); n != 0 {
		t.Errorf("platform_admins has %d row(s) after the refused commit, want 0", n)
	}
}

// The same mutation WITH its intent commits. Without this the test above would
// pass against a trigger that refuses everything.
func TestIntegration_CarrierMutationWithItsIntentCommits(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")

	intent := grantWithIntent(t, db, outbox, actor, target)

	if n := countRows(t, db, `SELECT count(*) FROM platform_admins WHERE user_id = $1`, target); n != 1 {
		t.Errorf("platform_admins has %d row(s) for the target, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE event_id = $1`, intent.EventID); n != 1 {
		t.Errorf("audit_outbox has %d row(s) for the intent, want 1", n)
	}
}

// An intent that names a DIFFERENT subject does not satisfy the trigger, and
// neither does one written by an earlier transaction. Together these are what
// stop the check being satisfiable by any audit row that happens to exist.
func TestIntegration_TriggerRejectsAMismatchedOrStaleIntent(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")
	other := seedUser(t, db, "other@example.com")

	t.Run("intent names another subject", func(t *testing.T) {
		tx, _ := db.Begin()
		if _, err := tx.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := outbox.Enqueue(context.Background(), tx, grantIntent(actor, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("a grant committed against an audit record naming somebody else")
		}
	})

	t.Run("intent from an earlier transaction", func(t *testing.T) {
		// Write the intent, commit it, then try the mutation on its own.
		tx, _ := db.Begin()
		if err := outbox.Enqueue(context.Background(), tx, grantIntent(actor, target)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("committing the intent alone: %v", err)
		}

		tx2, _ := db.Begin()
		if _, err := tx2.Exec(`INSERT INTO platform_admins (user_id) VALUES ($1)`, target); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := tx2.Commit(); err == nil {
			t.Fatal("a grant committed against an audit record written by an EARLIER transaction; " +
				"\"same transaction\" is the property, and a foreign key would not have expressed it")
		}
	})

	t.Run("revocation under a grant's record", func(t *testing.T) {
		grantWithIntent(t, db, outbox, actor, other)

		tx, _ := db.Begin()
		if _, err := tx.Exec(`DELETE FROM platform_admins WHERE user_id = $1`, other); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := outbox.Enqueue(context.Background(), tx, grantIntent(actor, other)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := tx.Commit(); err == nil {
			t.Fatal("a REVOCATION committed under a record that says \"granted\"")
		}
		if n := countRows(t, db, `SELECT count(*) FROM platform_admins WHERE user_id = $1`, other); n != 1 {
			t.Errorf("the grant is gone despite the refused commit (%d rows)", n)
		}
	})
}

// ---------------------------------------------------------------------------
// GUARD durable-audit-delivery — the relay, end to end
// ---------------------------------------------------------------------------

func TestIntegration_RelayDeliversTheIntentToAuditLogs(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")

	intent := grantWithIntent(t, db, outbox, actor, target)

	relay := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 10})
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch = (%d, %v), want (1, nil)", delivered, err)
	}

	var action, resourceID, actorEmail string
	err := db.QueryRow(`SELECT action, resource_id, actor_email FROM audit_logs WHERE id = $1`, intent.EventID).
		Scan(&action, &resourceID, &actorEmail)
	if err != nil {
		t.Fatalf("the delivered audit_logs row is missing or unreadable: %v", err)
	}
	if action != "platform_admin.granted" || resourceID != target {
		t.Errorf("delivered row = (%q, %q), want (platform_admin.granted, %s)", action, resourceID, target)
	}
	// The actor's address was resolved by the sink's COALESCE fallback, which
	// is what keeps the entry attributable after the user is deleted.
	if actorEmail != "actor@example.com" {
		t.Errorf("actor_email = %q, want actor@example.com", actorEmail)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL`); n != 0 {
		t.Errorf("%d intent(s) still pending after a successful delivery", n)
	}
}

// GUARD durable-audit-idempotent-redelivery. At-least-once transport, applied
// twice, must leave exactly one row. Redelivery is forced by resetting
// delivered_at — which is precisely the state a crashed relay leaves behind.
func TestIntegration_RedeliveryDoesNotDuplicateTheAuditRow(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")

	intent := grantWithIntent(t, db, outbox, actor, target)
	relay := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 10})

	for i := 0; i < 3; i++ {
		// Each pass must SUCCEED, not merely fail harmlessly. A destination
		// that rejected the redelivery outright would also leave one row
		// behind, while leaving the intent stuck in the backlog forever.
		_, delivered, err := relay.DeliverBatch(context.Background())
		if err != nil || delivered != 1 {
			t.Fatalf("delivery %d = (%d, %v), want (1, nil) — redelivery must be absorbed, not rejected",
				i+1, delivered, err)
		}
		if _, err := db.Exec(`UPDATE audit_outbox SET delivered_at = NULL WHERE event_id = $1`, intent.EventID); err != nil {
			t.Fatalf("resetting delivery state: %v", err)
		}
	}

	if n := countRows(t, db, `SELECT count(*) FROM audit_logs WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("audit_logs holds %d copies of one event after three deliveries, want exactly 1", n)
	}
}

// GUARD durable-audit-survives-a-crash. THE CRASH TEST, with a FORCED
// SCHEDULE rather than a race: the relay is parked inside its transaction
// immediately after the destination write, its backend is terminated from
// another connection, and only then is it allowed to continue.
//
// What must be true afterwards: the audit_logs row exists (the sink got there),
// the outbox intent is STILL PENDING (nothing was marked under a transaction
// that never committed), and a fresh relay delivers it again to a total of
// exactly one row.
func TestIntegration_RelayCrashMidFlightLosesNothingAndDuplicatesNothing(t *testing.T) {
	db, dsn := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")
	intent := grantWithIntent(t, db, outbox, actor, target)

	// A single-connection pool for the relay, so the backend to terminate is
	// known exactly rather than guessed at from pg_stat_activity.
	relayPool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open(relay pool): %v", err)
	}
	defer relayPool.Close()
	relayPool.SetMaxOpenConns(1)
	relayPool.SetMaxIdleConns(1)
	var relayPID int
	if err := relayPool.QueryRow(`SELECT pg_backend_pid()`).Scan(&relayPID); err != nil {
		t.Fatalf("reading the relay's backend pid: %v", err)
	}

	parked := make(chan struct{})
	release := make(chan struct{})
	crashing := &parkingSink{
		inner:   NewAuditLogSink(db),
		parked:  parked,
		release: release,
	}

	relay := NewRelay(NewOutbox(relayPool), crashing, nil, RelayConfig{BatchSize: 10})
	done := make(chan error, 1)
	go func() {
		_, _, err := relay.DeliverBatch(context.Background())
		done <- err
	}()

	select {
	case <-parked:
	case <-time.After(20 * time.Second):
		t.Fatal("the relay never reached the sink")
	}

	// The destination write has happened; the outbox transaction has not
	// committed. Kill it.
	if n := countRows(t, db, `SELECT count(*) FROM audit_logs WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("audit_logs holds %d row(s) at the parked moment, want 1 — the schedule is not what the test assumes", n)
	}
	if _, err := db.Exec(`SELECT pg_terminate_backend($1)`, relayPID); err != nil {
		t.Fatalf("terminating the relay backend: %v", err)
	}
	close(release)

	if err := <-done; err == nil {
		t.Fatal("the relay reported a successful batch after its backend was killed")
	}

	// NOTHING WAS MARKED. This is the crash contract.
	if n := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE event_id = $1 AND delivered_at IS NULL`, intent.EventID); n != 1 {
		t.Fatalf("the intent is no longer pending after the crash (%d pending rows); "+
			"a marked-but-uncommitted delivery would mean records can be lost", n)
	}

	// A fresh relay picks it up, and the destination absorbs the redelivery.
	recovered := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 10})
	if _, delivered, err := recovered.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("recovery DeliverBatch = (%d, %v), want (1, nil)", delivered, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_logs WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("audit_logs holds %d copies after the crash and recovery, want exactly 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL`); n != 0 {
		t.Errorf("%d intent(s) still pending after recovery", n)
	}
}

// parkingSink delivers for real, then blocks so the test can kill the relay's
// backend at a moment of its choosing.
type parkingSink struct {
	inner   Sink
	parked  chan struct{}
	release chan struct{}
	once    bool
}

func (s *parkingSink) Deliver(ctx context.Context, intent Intent) error {
	if err := s.inner.Deliver(ctx, intent); err != nil {
		return err
	}
	if !s.once {
		s.once = true
		close(s.parked)
		<-s.release
	}
	return nil
}

// GUARD durable-audit-destination-outage. The destination is unreachable: the
// mutation has already committed with its record, so the record must survive
// the outage and land when the destination returns.
func TestIntegration_DestinationOutageRetainsTheRecordAndDeliversItLater(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")
	target := seedUser(t, db, "target@example.com")
	intent := grantWithIntent(t, db, outbox, actor, target)

	// A sink pointed at a closed connection: the outage.
	closed, err := sql.Open("postgres", "postgres://127.0.0.1:1/nowhere?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	closed.Close()

	down := NewRelay(outbox, NewAuditLogSink(closed), nil, RelayConfig{BatchSize: 10})
	if _, delivered, err := down.DeliverBatch(context.Background()); err != nil || delivered != 0 {
		t.Fatalf("DeliverBatch against a dead destination = (%d, %v), want (0, nil) — "+
			"the batch records the failure and moves on", delivered, err)
	}

	backlog, err := outbox.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if backlog.Pending != 1 || backlog.Failed != 1 {
		t.Fatalf("backlog = %+v, want 1 pending and 1 failed — an operator must be able to see this", backlog)
	}
	var lastErr sql.NullString
	if err := db.QueryRow(`SELECT last_error FROM audit_outbox WHERE event_id = $1`, intent.EventID).Scan(&lastErr); err != nil {
		t.Fatalf("reading last_error: %v", err)
	}
	if !lastErr.Valid || lastErr.String == "" {
		t.Error("the retained intent carries no reason for its failure")
	}

	// The destination comes back.
	up := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 10})
	if _, delivered, err := up.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch after recovery = (%d, %v), want (1, nil)", delivered, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_logs WHERE id = $1`, intent.EventID); n != 1 {
		t.Fatalf("audit_logs holds %d row(s) after the outage cleared, want 1", n)
	}
}

// GUARD durable-audit-prune-delivered-only, behaviourally. Pruning bounds the
// table's growth, and must never be able to reach a record that has not
// arrived.
func TestIntegration_PruneRemovesDeliveredHistoryAndNeverTheBacklog(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")

	deliveredTargets := []string{seedUser(t, db, "a@example.com"), seedUser(t, db, "b@example.com")}
	for _, target := range deliveredTargets {
		grantWithIntent(t, db, outbox, actor, target)
	}
	relay := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 10})
	if _, delivered, err := relay.DeliverBatch(context.Background()); err != nil || delivered != 2 {
		t.Fatalf("DeliverBatch = (%d, %v), want (2, nil)", delivered, err)
	}
	// Age them past the retention window.
	if _, err := db.Exec(`UPDATE audit_outbox SET delivered_at = now() - interval '30 days'`); err != nil {
		t.Fatalf("ageing delivered intents: %v", err)
	}

	// One intent that never got delivered.
	stuck := grantWithIntent(t, db, outbox, actor, seedUser(t, db, "c@example.com"))
	if _, err := db.Exec(`UPDATE audit_outbox SET occurred_at = now() - interval '30 days' WHERE event_id = $1`, stuck.EventID); err != nil {
		t.Fatalf("ageing the stuck intent: %v", err)
	}

	pruned, err := outbox.PruneDelivered(context.Background(), time.Now().Add(-7*24*time.Hour), 100)
	if err != nil {
		t.Fatalf("PruneDelivered: %v", err)
	}
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}
	if n := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE event_id = $1`, stuck.EventID); n != 1 {
		t.Fatal("the pruner deleted an UNDELIVERED intent; that is a destroyed audit record, " +
			"which is worse than the unbounded table it was trying to prevent")
	}
}

// The relay drains a backlog larger than one batch, oldest first.
func TestIntegration_RelayDrainsABacklogAcrossBatches(t *testing.T) {
	db, _ := scratchDB(t)
	outbox := NewOutbox(db)
	actor := seedUser(t, db, "actor@example.com")

	const n = 7
	for i := 0; i < n; i++ {
		grantWithIntent(t, db, outbox, actor, seedUser(t, db, fmt.Sprintf("t%d@example.com", i)))
	}

	relay := NewRelay(outbox, NewAuditLogSink(db), nil, RelayConfig{BatchSize: 2, RetainDelivered: -1})
	relay.RunCycle(context.Background())

	if got := countRows(t, db, `SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL`); got != 0 {
		t.Errorf("%d intent(s) still pending after a full cycle", got)
	}
	if got := countRows(t, db, `SELECT count(*) FROM audit_logs`); got != n {
		t.Errorf("audit_logs holds %d rows, want %d", got, n)
	}
}

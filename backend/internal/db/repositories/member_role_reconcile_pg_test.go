package repositories

import (
	"context"
	"database/sql"
	"errors"
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

// The backfill for registry's own authorization tables, against real
// PostgreSQL and the real migrations (sethbacon/terraform-suite-identity#206,
// migration 000055).
//
// This has to be a real database. The property under test is which SCHEMA a
// bare table name resolves to under a given search_path, and no mock evaluates
// a search_path — a sqlmock-based test of the reconcile would pass identically
// whether it read the live rows or a stale copy, which is the exact mistake
// migration 000055 declines to make in SQL.
//
// CI DOES NOT RUN THIS. No workflow sets TFR_TEST_DATABASE_URL (issue #886), so
// everything below skips on a PR. It is evidence produced locally against
// postgres:16 and named as such in the pull request.
//
// Set TFR_TEST_DATABASE_URL to run these.

const roleTablesScratchPrefix = "tfr_206_"

// reconcileScratchDB creates a scratch database, applies registry's migrations
// to the requested version, and returns a connection to it.
//
// version is explicit rather than "head" so the pre-000055 state stays testable
// after later migrations land: the unreachable-tables case below needs a
// database where these tables genuinely do not exist.
func reconcileScratchDB(t *testing.T, version uint) (*sql.DB, string) {
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

	name := roleTablesScratchPrefix + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Skipf("cannot create a scratch database (needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		drop, dropErr := sql.Open("pgx", raw)
		if dropErr != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})

	scratch := *base
	scratch.Path = "/" + name
	dsn := scratch.String()

	m, err := migrate.New("file://../migrations", dsn)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	if err := m.Migrate(version); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		_, _ = m.Close()
		t.Fatalf("applying migrations to %d: %v", version, err)
	}
	_, _ = m.Close()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open scratch: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, dsn
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// seedPublicIdentity creates one organization, one user, one role template and
// one membership in the registry's own public schema — the DEFAULT topology,
// where identity data lives beside the app's tables. It returns the template's
// name, which is uniquified because 000001 and 000049 have already seeded the
// system templates and `role_templates.name` is UNIQUE.
func seedPublicIdentity(t *testing.T, db *sql.DB, orgID, userID, roleID string, roleName string) string {
	t.Helper()
	unique := roleName + "-" + roleID[:8]
	mustExec(t, db, `INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "org-"+unique)
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'Test User')`, userID, userID+"@example.com")
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system)
	                 VALUES ($1, $2, $2, '["modules:read"]'::jsonb, false)`, roleID, unique)
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id)
	                 VALUES ($1, $2, $3)`, orgID, userID, roleID)
	return unique
}

func mirroredRole(t *testing.T, db *sql.DB, orgID, userID string) (sql.NullString, bool) {
	t.Helper()
	var role sql.NullString
	err := db.QueryRow(
		`SELECT role_template_id FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.NullString{}, false
	}
	if err != nil {
		t.Fatalf("read mirrored role: %v", err)
	}
	return role, true
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestReconcile_BackfillsFromThePublicSchema is the default topology: identity
// data is in the app's own schema and the identity connection IS the registry
// connection.
func TestReconcile_BackfillsFromThePublicSchema(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	name := seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")

	report, err := ReconcileMemberRoles(context.Background(), db, db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.SourceMemberships != 1 {
		t.Errorf("SourceMemberships = %d, want 1", report.SourceMemberships)
	}
	role, ok := mirroredRole(t, db, orgID, userID)
	if !ok {
		t.Fatal("the membership was not mirrored into organization_member_roles at all")
	}
	if !role.Valid || role.String != roleID {
		t.Errorf("mirrored role_template_id = %v, want %s", role, roleID)
	}

	var mirroredName string
	if err := db.QueryRow(`SELECT name FROM registry_role_templates WHERE id = $1`, roleID).Scan(&mirroredName); err != nil {
		t.Fatalf("the role template was not mirrored: %v", err)
	}
	if mirroredName != name {
		t.Errorf("mirrored template name = %q, want %q", mirroredName, name)
	}
}

// TestReconcile_UsesTheEffectiveSourceUnderTheSchemaCutover is the headline
// property, and the reason migration 000055 ships no SQL backfill.
//
// Under TFR_IDENTITY_SCHEMA_ENABLED the live rows are in the identity schema
// and `public` keeps only the PRE-CUTOVER copy. A backfill that read
// public.organization_members — which is what any `INSERT ... SELECT` inside a
// migration on the registry connection would do — would capture the stale side
// and mirror role assignments the product stopped honouring.
//
// Here the two copies deliberately DISAGREE: the same member holds a different
// template in each. Passing the identity-search_path pool as the source is the
// whole mechanism, and the assertion is that the mirror carries the identity
// value.
func TestReconcile_UsesTheEffectiveSourceUnderTheSchemaCutover(t *testing.T) {
	db, dsn := reconcileScratchDB(t, 55)

	orgID, userID := uuid.NewString(), uuid.NewString()
	staleRoleID, liveRoleID := uuid.NewString(), uuid.NewString()

	// The pre-cutover copy: registry's public schema still holds the old row.
	mustExec(t, db, `INSERT INTO organizations (id, name, display_name) VALUES ($1, 'acme', 'Acme')`, orgID)
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, 'a@example.com', 'A')`, userID)
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system)
	                 VALUES ($1, 'stale', 'Stale', '["modules:read"]'::jsonb, false)`, staleRoleID)
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id)
	                 VALUES ($1, $2, $3)`, orgID, userID, staleRoleID)

	// The live copy, in the identity schema. Shaped like the shared identity
	// schema after its migration 000003: scopes is JSONB, not TEXT[].
	mustExec(t, db, `CREATE SCHEMA identity`)
	mustExec(t, db, `CREATE TABLE identity.role_templates (
	    id UUID PRIMARY KEY, name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
	    description TEXT, scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
	    is_system BOOLEAN NOT NULL DEFAULT false,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)
	mustExec(t, db, `CREATE TABLE identity.organization_members (
	    organization_id UUID NOT NULL, user_id UUID NOT NULL,
	    role_template_id UUID REFERENCES identity.role_templates(id) ON DELETE SET NULL,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (organization_id, user_id))`)
	mustExec(t, db, `INSERT INTO identity.role_templates (id, name, display_name, scopes)
	                 VALUES ($1, 'live', 'Live', '["modules:write"]'::jsonb)`, liveRoleID)
	mustExec(t, db, `INSERT INTO identity.organization_members (organization_id, user_id, role_template_id)
	                 VALUES ($1, $2, $3)`, orgID, userID, liveRoleID)

	// The identity pool, exactly as cmd/server/main.go opens it under
	// TFR_IDENTITY_SCHEMA_ENABLED: search_path = "<schema>,public".
	identityDSN := dsn
	if strings.Contains(identityDSN, "?") {
		identityDSN += "&search_path=identity,public"
	} else {
		identityDSN += "?search_path=identity,public"
	}
	identityDB, err := sql.Open("pgx", identityDSN)
	if err != nil {
		t.Fatalf("open identity pool: %v", err)
	}
	defer identityDB.Close()

	report, err := ReconcileMemberRoles(context.Background(), identityDB, db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.SourceMemberships != 1 {
		t.Fatalf("SourceMemberships = %d, want 1 (the identity row)", report.SourceMemberships)
	}

	role, ok := mirroredRole(t, db, orgID, userID)
	if !ok {
		t.Fatal("nothing was mirrored")
	}
	if !role.Valid || role.String != liveRoleID {
		t.Errorf("mirrored role_template_id = %v, want the LIVE identity template %s. "+
			"Got the stale public copy %s? Then the backfill read the wrong side, which is exactly "+
			"what migration 000055 declines to do in SQL.", role, liveRoleID, staleRoleID)
	}

	// The stale template must not have been mirrored either: registry's copy is
	// derived from the effective source, not from the union of both.
	var staleMirrored int
	if err := db.QueryRow(`SELECT count(*) FROM registry_role_templates WHERE id = $1`, staleRoleID).Scan(&staleMirrored); err != nil {
		t.Fatalf("count stale mirrored template: %v", err)
	}
	if staleMirrored != 0 {
		t.Errorf("the pre-cutover role template was mirrored (%d rows); the backfill unioned the two "+
			"copies instead of choosing the effective one", staleMirrored)
	}
}

// TestReconcile_RemovesMirroredRowsTheSourceNoLongerHas is the direction that
// GRANTS rather than withholds. A deprovision whose mirror write failed leaves
// authority behind in the table the read cutover switches onto, so the
// reconcile must be a reconcile and not an append.
func TestReconcile_RemovesMirroredRowsTheSourceNoLongerHas(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")
	if _, err := ReconcileMemberRoles(context.Background(), db, db); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if _, ok := mirroredRole(t, db, orgID, userID); !ok {
		t.Fatal("precondition: the first reconcile mirrored nothing")
	}

	// The member is removed at the source, and the mirror write is lost.
	mustExec(t, db, `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`, orgID, userID)

	report, err := ReconcileMemberRoles(context.Background(), db, db)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if report.MembershipsRemoved != 1 {
		t.Errorf("MembershipsRemoved = %d, want 1", report.MembershipsRemoved)
	}
	if _, ok := mirroredRole(t, db, orgID, userID); ok {
		t.Error("the mirrored role survived a deprovision; registry's own table still grants it")
	}
}

// TestReconcile_IsIdempotent asserts the steady state: a second run over
// unchanged data writes nothing. The upserts carry an IS DISTINCT FROM guard so
// a restart is not a mass UPDATE against the whole table.
func TestReconcile_IsIdempotent(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")
	if _, err := ReconcileMemberRoles(context.Background(), db, db); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	var firstUpdatedAt time.Time
	if err := db.QueryRow(
		`SELECT updated_at FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&firstUpdatedAt); err != nil {
		t.Fatalf("read updated_at: %v", err)
	}

	report, err := ReconcileMemberRoles(context.Background(), db, db)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if report.MembershipsRemoved != 0 || report.RoleTemplatesRemoved != 0 {
		t.Errorf("second run removed rows (%d memberships, %d templates); it should have been a no-op",
			report.MembershipsRemoved, report.RoleTemplatesRemoved)
	}
	// The reconcile runs on every boot, so "no change" must cost no writes at
	// all — not one statement per membership that discovers it had nothing to
	// do. A deployment with a hundred thousand memberships pays this on every
	// restart otherwise.
	if report.MembershipsWritten != 0 {
		t.Errorf("MembershipsWritten = %d on an unchanged second run, want 0: the reconcile is "+
			"upserting every row instead of diffing against the mirror it already read",
			report.MembershipsWritten)
	}

	var secondUpdatedAt time.Time
	if err := db.QueryRow(
		`SELECT updated_at FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&secondUpdatedAt); err != nil {
		t.Fatalf("read updated_at again: %v", err)
	}
	if !secondUpdatedAt.Equal(firstUpdatedAt) {
		t.Errorf("updated_at moved on an unchanged row (%s -> %s); the upsert's IS DISTINCT FROM "+
			"guard is not holding, so every restart rewrites the whole table",
			firstUpdatedAt, secondUpdatedAt)
	}
}

// TestMemberRoleMirror_AssignRole_IsANoOpWhenNothingChanged exercises the
// upsert's own IS DISTINCT FROM guard directly.
//
// The reconcile no longer reaches it — it diffs in Go first — but the LIVE
// dual-write does: re-assigning the role a member already holds is a legitimate
// no-op request, and it must not rewrite the row. Without this test the SQL
// guard has no coverage at all, which a mutation confirmed by surviving.
func TestMemberRoleMirror_AssignRole_IsANoOpWhenNothingChanged(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")
	if _, err := ReconcileMemberRoles(context.Background(), db, db); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	readUpdatedAt := func() time.Time {
		var at time.Time
		if err := db.QueryRow(
			`SELECT updated_at FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
			orgID, userID).Scan(&at); err != nil {
			t.Fatalf("read updated_at: %v", err)
		}
		return at
	}
	before := readUpdatedAt()

	mirror := NewMemberRoleMirror(db)
	role := roleID
	if err := mirror.AssignRole(context.Background(), orgID, userID, &role); err != nil {
		t.Fatalf("AssignRole (unchanged): %v", err)
	}
	if after := readUpdatedAt(); !after.Equal(before) {
		t.Errorf("updated_at moved (%s -> %s) on an assignment that changed nothing; the upsert's "+
			"IS DISTINCT FROM guard is not holding", before, after)
	}

	// And a real change still lands.
	other := uuid.NewString()
	mustExec(t, db, `INSERT INTO registry_role_templates (id, name, display_name, scopes)
	                 VALUES ($1, $2, $2, '["modules:read"]'::jsonb)`, other, "other-"+other[:8])
	if err := mirror.AssignRole(context.Background(), orgID, userID, &other); err != nil {
		t.Fatalf("AssignRole (changed): %v", err)
	}
	var got string
	if err := db.QueryRow(
		`SELECT role_template_id FROM organization_member_roles WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&got); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if got != other {
		t.Errorf("role_template_id = %s, want %s — the guard suppressed a real change", got, other)
	}
}

// TestReconcile_OrphanedRoleReferenceIsMirroredAsNoRole covers the inconsistent
// data the constraints cannot prevent: a membership naming a template that is
// not in role_templates at all. It must not abort the whole backfill over one
// bad row, and it must not invent an assignment.
func TestReconcile_OrphanedRoleReferenceIsMirroredAsNoRole(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")

	// A second member whose role template is dangling. public.organization_members
	// has an FK to public.role_templates, so the row is created through it and the
	// template is then removed with the constraint disabled — the state a
	// cross-schema deployment reaches for real, where no FK spans the boundary.
	otherUser := uuid.NewString()
	danglingRole := uuid.NewString()
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, 'b@example.com', 'B')`, otherUser)
	mustExec(t, db, `ALTER TABLE organization_members DISABLE TRIGGER ALL`)
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id)
	                 VALUES ($1, $2, $3)`, orgID, otherUser, danglingRole)
	mustExec(t, db, `ALTER TABLE organization_members ENABLE TRIGGER ALL`)

	report, err := ReconcileMemberRoles(context.Background(), db, db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.OrphanedRoleRefs != 1 {
		t.Errorf("OrphanedRoleRefs = %d, want 1", report.OrphanedRoleRefs)
	}
	if report.SourceMemberships != 2 {
		t.Errorf("SourceMemberships = %d, want 2 — the bad row must not abort the backfill",
			report.SourceMemberships)
	}

	role, ok := mirroredRole(t, db, orgID, otherUser)
	if !ok {
		t.Fatal("the membership with a dangling role was not mirrored at all")
	}
	if role.Valid {
		t.Errorf("mirrored role_template_id = %q, want NULL: the named template does not exist, "+
			"so mirroring it would be inventing an assignment", role.String)
	}
	// The good row is still mirrored correctly.
	good, ok := mirroredRole(t, db, orgID, userID)
	if !ok || !good.Valid || good.String != roleID {
		t.Errorf("the healthy membership mirrored as %v, want %s", good, roleID)
	}
}

// TestReconcile_RefusesWhenTheMirrorTablesAreAbsent is the loud refusal. A
// reconcile that quietly found nothing would leave the mirror empty and report
// success — and the next phase would cut reads over onto an empty table, which
// revokes everybody at once.
func TestReconcile_RefusesWhenTheMirrorTablesAreAbsent(t *testing.T) {
	db, _ := reconcileScratchDB(t, 54)

	_, err := ReconcileMemberRoles(context.Background(), db, db)
	if !errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("ReconcileMemberRoles = %v, want it to wrap ErrMirrorUnreachable", err)
	}
}

// TestReconcile_RefusesWhenTheSourceDoesNotResolve is the other half of the
// loud refusal, and the more dangerous half.
//
// If the identity connection's search_path does not reach the identity tables,
// the reconcile's own SELECT would fail — but an earlier shape of this code
// could equally have found zero rows and called it success, which would empty
// the mirror and then, at the read cutover, revoke every role in the
// deployment at once. "The source is not there" and "the source is empty" must
// not be the same answer.
func TestReconcile_RefusesWhenTheSourceDoesNotResolve(t *testing.T) {
	db, dsn := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")

	// A pool whose search_path names a schema holding none of the identity
	// tables, and which does NOT fall back to public.
	mustExec(t, db, `CREATE SCHEMA empty_identity`)
	blindDSN := dsn
	if strings.Contains(blindDSN, "?") {
		blindDSN += "&search_path=empty_identity"
	} else {
		blindDSN += "?search_path=empty_identity"
	}
	identityDB, err := sql.Open("pgx", blindDSN)
	if err != nil {
		t.Fatalf("open blind identity pool: %v", err)
	}
	defer identityDB.Close()

	report, err := ReconcileMemberRoles(context.Background(), identityDB, db)
	if err == nil {
		t.Fatalf("ReconcileMemberRoles = nil error with report %+v, want a refusal. A source that "+
			"does not resolve must not be reported as a source with no rows", report)
	}
	if !strings.Contains(err.Error(), "organization_members") {
		t.Errorf("error = %q, want it to name the table that did not resolve", err)
	}
	if n := countRows(t, db, "organization_member_roles"); n != 0 {
		t.Errorf("the refused reconcile still wrote %d mirrored row(s)", n)
	}
}

// TestMigration000055_CreatesEmptyTablesWithNoBackfill pins the migration's
// deliberate omission. If somebody later adds an `INSERT ... SELECT` to it,
// this fails — and that insert would be the silent wrong-source backfill the
// file spends a page explaining it will not do.
func TestMigration000055_CreatesEmptyTablesWithNoBackfill(t *testing.T) {
	db, _ := reconcileScratchDB(t, 54)

	// Data exists BEFORE 000055 runs, so a backfill inside it would have
	// something to copy.
	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")

	var dsn string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&dsn); err != nil {
		t.Fatalf("current_database: %v", err)
	}
	raw := os.Getenv("TFR_TEST_DATABASE_URL")
	base, _ := url.Parse(raw)
	base.Path = "/" + dsn
	m, err := migrate.New("file://../migrations", base.String())
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Migrate(55); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("applying 000055: %v", err)
	}

	if n := countRows(t, db, "organization_member_roles"); n != 0 {
		t.Errorf("organization_member_roles has %d row(s) straight after 000055, want 0. The "+
			"migration must not backfill: it cannot see which schema or database holds the live "+
			"rows, so any INSERT..SELECT it performs may capture the stale copy", n)
	}
	if n := countRows(t, db, "registry_role_templates"); n != 0 {
		t.Errorf("registry_role_templates has %d row(s) straight after 000055, want 0", n)
	}

	// And the down migration is clean.
	if err := m.Migrate(54); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("rolling 000055 back: %v", err)
	}
	var present sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('organization_member_roles')::text`).Scan(&present); err != nil {
		t.Fatalf("probe after rollback: %v", err)
	}
	if present.Valid {
		t.Errorf("organization_member_roles still resolves to %q after the down migration", present.String)
	}
}

// TestMirroredRoleTemplateDeletion_ClearsTheAssignment proves the one role
// change carried entirely by a foreign key. Deleting a template must clear
// role_template_id on the mirrored memberships that held it, exactly as
// 000001_initial_schema's FK does at the source — and must NOT delete the
// membership row with it.
func TestMirroredRoleTemplateDeletion_ClearsTheAssignment(t *testing.T) {
	db, _ := reconcileScratchDB(t, 55)

	orgID, userID, roleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_ = seedPublicIdentity(t, db, orgID, userID, roleID, "publisher")
	if _, err := ReconcileMemberRoles(context.Background(), db, db); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := NewMemberRoleMirror(db).DeleteRoleTemplate(context.Background(), uuid.MustParse(roleID)); err != nil {
		t.Fatalf("DeleteRoleTemplate: %v", err)
	}

	role, ok := mirroredRole(t, db, orgID, userID)
	if !ok {
		t.Fatal("deleting the template deleted the membership row; the FK must be ON DELETE SET NULL, " +
			"not CASCADE — a member who loses a role is still a member")
	}
	if role.Valid {
		t.Errorf("mirrored role_template_id = %q after the template was deleted, want NULL", role.String)
	}
}

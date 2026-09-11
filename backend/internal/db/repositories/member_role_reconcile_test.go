package repositories

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Reconcile tests that need no database.
//
// member_role_reconcile_pg_test.go proves the properties only real PostgreSQL
// can answer -- which SCHEMA a bare table name resolves to under a search_path,
// and what the FK does on delete. Those skip wherever TFR_TEST_DATABASE_URL is
// unset, which is every CI run (issue #886), so the DECISIONS the reconcile
// makes are pinned here instead: what it writes, what it declines to write,
// what it prunes, and what it refuses outright.
//
// Splitting it this way is not duplication. The Postgres file would pass
// vacuously in CI, and a reconcile whose only coverage skips is a reconcile
// nobody is checking on the runs that gate merges.

// mockConn pairs a connection with the mock that scripts it.
//
// The reconcile takes TWO connections -- it reads through identity and writes
// through registry -- so the tests script them separately. That separation is
// the point: an assertion can then say which SIDE a statement landed on, which
// is the whole reason the backfill is Go rather than SQL in the migration.
type mockConn struct {
	db   *sql.DB
	mock sqlmock.Sqlmock
}

func newReconcileMocks(t *testing.T) (identity, registry *mockConn) {
	t.Helper()
	return newMockConn(t), newMockConn(t)
}

func newMockConn(t *testing.T) *mockConn {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &mockConn{db: db, mock: mock}
}

// mustUUID parses a fixed test id, failing the test rather than the assertion
// when the literal is malformed.
func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return id
}

// expectMirrorVerified queues the two to_regclass probes Verify makes.
func expectMirrorVerified(mock sqlmock.Sqlmock) {
	for _, table := range []string{"registry_role_templates", "organization_member_roles"} {
		mock.ExpectQuery("SELECT to_regclass").
			WithArgs(table).
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("public." + table))
	}
}

// expectSourceVerified queues the two probes verifyIdentitySource makes.
func expectSourceVerified(mock sqlmock.Sqlmock) {
	for _, table := range []string{"organization_members", "role_templates"} {
		mock.ExpectQuery("SELECT to_regclass").
			WithArgs(table).
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("identity." + table))
	}
}

var reconcileRoleTemplateCols = []string{"id", "name", "display_name", "description", "scopes", "is_system", "created_at", "updated_at"}

// expectSourceRoleTemplates queues the store's ListRoleTemplates.
func expectSourceRoleTemplates(mock sqlmock.Sqlmock, ids ...string) {
	rows := sqlmock.NewRows(reconcileRoleTemplateCols)
	for i, id := range ids {
		rows.AddRow(id, "role-"+id[:4], "Role", nil, []byte(`["modules:read"]`), false, time.Now(), time.Now())
		_ = i
	}
	mock.ExpectQuery("FROM role_templates").WillReturnRows(rows)
}

// expectSourceMemberships queues readEffectiveMemberships.
func expectSourceMemberships(mock sqlmock.Sqlmock, rows ...[3]interface{}) {
	r := sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id"})
	for _, row := range rows {
		r.AddRow(row[0], row[1], row[2])
	}
	mock.ExpectQuery("SELECT organization_id, user_id, role_template_id FROM organization_members").
		WillReturnRows(r)
}

// expectMirroredMemberships queues readMirroredMemberships.
func expectMirroredMemberships(mock sqlmock.Sqlmock, rows ...[3]interface{}) {
	r := sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id"})
	for _, row := range rows {
		r.AddRow(row[0], row[1], row[2])
	}
	mock.ExpectQuery("SELECT organization_id, user_id, role_template_id FROM organization_member_roles").
		WillReturnRows(r)
}

// expectMirroredTemplateIDs queues readMirroredRoleTemplateIDs.
func expectMirroredTemplateIDs(mock sqlmock.Sqlmock, ids ...string) {
	r := sqlmock.NewRows([]string{"id"})
	for _, id := range ids {
		r.AddRow(id)
	}
	mock.ExpectQuery("SELECT id FROM registry_role_templates").WillReturnRows(r)
}

const (
	recOrgA  = "aaaaaaaa-0000-0000-0000-000000000001"
	recUserA = "bbbbbbbb-0000-0000-0000-000000000001"
	recUserB = "bbbbbbbb-0000-0000-0000-000000000002"
	recRoleA = "cccccccc-0000-0000-0000-000000000001"
	recRoleB = "cccccccc-0000-0000-0000-000000000002"
)

// THE ONE-TIME ADOPTION, and the template ordering it depends on.
//
// An empty mirror with a non-empty source is a deployment that has just gained
// migration 000055's tables. It adopts the source's assignments once, because
// confirming facts alone would leave every principal with no role. Templates go
// first either way: organization_member_roles.role_template_id has a real FK to
// registry_role_templates, so an assignment cannot be written before the
// template it names.
func TestReconcileMemberRoles_AdoptsIntoAnEmptyMirror(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredMemberships(registry.mock) // EMPTY -> adoption
	registry.mock.ExpectExec("INSERT INTO organization_member_roles").
		WithArgs(recOrgA, recUserA, recRoleA).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.SourceRoleTemplates != 1 || report.SourceMemberships != 1 {
		t.Errorf("report = %+v, want 1 template and 1 membership read", report)
	}
	if report.MembershipsAdopted != 1 {
		t.Errorf("MembershipsAdopted = %d, want 1", report.MembershipsAdopted)
	}
	if report.MembershipsConfirmed != 0 {
		t.Errorf("MembershipsConfirmed = %d, want 0 — the adoption path ran, not the steady-state one",
			report.MembershipsConfirmed)
	}
	if report.RoleTemplatesWritten != 1 {
		t.Errorf("RoleTemplatesWritten = %d, want 1", report.RoleTemplatesWritten)
	}
	if err := identity.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("identity connection: %v", err)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// TestReconcileMemberRoles_DoesNotAdoptOnceTheMirrorHasRows IS THE DEFECT
// #1056 IS ABOUT, as a test.
//
// A coupled deployment: the state manager granted its own role, the shared
// library wrote ITS template id into organization_members.role_template_id, and
// registry's mirror holds registry's own decision for the same pair. The old
// reconcile copied identity's id over registry's on every boot, so the principal
// silently held whatever the sibling granted, with registry's scopes for that
// name, granted by nobody here.
//
// The mirror is non-empty, so the adoption may not run: no write of any kind
// reaches organization_member_roles, and the registry decision stands. Asserted
// on the MOCK rather than only on the counters — an unexpected Exec is what a
// restored copy would look like.
func TestReconcileMemberRoles_DoesNotAdoptOnceTheMirrorHasRows(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA, recRoleB)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 1))
	// Identity says B (the sibling's grant); registry says A (its own decision).
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleB})
	expectMirroredMemberships(registry.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	// NO assignment write is staged. Any statement against
	// organization_member_roles now fails this test.
	expectMirroredTemplateIDs(registry.mock, recRoleA, recRoleB)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsAdopted != 0 {
		t.Errorf("MembershipsAdopted = %d, want 0: registry already holds a decision for this pair, "+
			"and identity's column does not get to change it", report.MembershipsAdopted)
	}
	if report.MembershipsConfirmed != 0 {
		t.Errorf("MembershipsConfirmed = %d, want 0 — the pair is already recorded here",
			report.MembershipsConfirmed)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v — a write reached organization_member_roles. "+
			"The boot reconcile copied identity's role opinion again (#1056).", err)
	}
}

// A ROLE CLEARED AT THE SOURCE IS NOT A CHANGE HERE, which is the same property
// pointing the other way. Identity's column going NULL says nothing about what
// registry granted; only a withdrawal of the MEMBERSHIP does, and that arrives
// as a pruned row (below), not as a role edit.
func TestReconcileMemberRoles_ClearingTheSourceRoleLeavesRegistrysAlone(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, nil})
	expectMirroredMemberships(registry.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsAdopted != 0 || report.MembershipsConfirmed != 0 {
		t.Errorf("report = %+v, want no membership writes: a NULL at the source is not a revocation here",
			report)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v — registry's role was cleared because identity's column was", err)
	}
}

// THE STEADY-STATE PATH: identity has a membership registry has no row for, so
// it is recorded with NO role.
//
// Fail-closed, and the direction matters: the principal is a member and holds
// nothing here until somebody grants it here. The alternative — adopting the
// source's role for just this pair — is the defect at one-row scale.
func TestReconcileMemberRoles_ConfirmsAMembershipItHasNoRowFor(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 1))
	// Two memberships at the source; the mirror knows only the first, so it is
	// NOT empty and the adoption may not run.
	expectSourceMemberships(identity.mock,
		[3]interface{}{recOrgA, recUserA, recRoleA},
		[3]interface{}{recOrgA, recUserB, recRoleA})
	expectMirroredMemberships(registry.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	registry.mock.ExpectExec("INSERT INTO organization_member_roles").
		WithArgs(recOrgA, recUserB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsConfirmed != 1 {
		t.Errorf("MembershipsConfirmed = %d, want 1", report.MembershipsConfirmed)
	}
	if report.MembershipsAdopted != 0 {
		t.Errorf("MembershipsAdopted = %d, want 0 — the mirror was not empty", report.MembershipsAdopted)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// An agreeing steady state costs no write at all: two SELECTs and nothing else.
func TestReconcileMemberRoles_SkipsRowsThatAlreadyAgree(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredMemberships(registry.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsConfirmed != 0 || report.MembershipsAdopted != 0 {
		t.Errorf("report = %+v, want no membership write — an unchanged row must cost nothing", report)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// TestReconcileMemberRoles_PrunesRowsTheSourceNoLongerHas covers the direction
// that GRANTS: a mirrored assignment with no source membership.
func TestReconcileMemberRoles_PrunesRowsTheSourceNoLongerHas(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 0))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredMemberships(registry.mock,
		[3]interface{}{recOrgA, recUserA, recRoleA},
		[3]interface{}{recOrgA, recUserB, recRoleA})
	registry.mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(recOrgA, recUserB).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsRemoved != 1 {
		t.Errorf("MembershipsRemoved = %d, want 1", report.MembershipsRemoved)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// TestReconcileMemberRoles_PrunesTemplatesTheSourceNoLongerHas, and does it
// LAST: a template deleted before the assignments are written would null a row
// the same pass had just set, through the FK.
func TestReconcileMemberRoles_PrunesTemplatesTheSourceNoLongerHas(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 0))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredMemberships(registry.mock, [3]interface{}{recOrgA, recUserA, recRoleA})
	expectMirroredTemplateIDs(registry.mock, recRoleA, recRoleB)
	registry.mock.ExpectExec("DELETE FROM registry_role_templates").
		WithArgs(mustUUID(t, recRoleB)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.RoleTemplatesRemoved != 1 {
		t.Errorf("RoleTemplatesRemoved = %d, want 1", report.RoleTemplatesRemoved)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// TestReconcileMemberRoles_OrphanedRoleReferenceIsMirroredAsNoRole: a membership
// naming a template the source does not have is recorded with NO role and
// counted. Mirroring the id would violate the FK and abort the whole boot over
// one inconsistent row; dropping the row would hide it.
func TestReconcileMemberRoles_OrphanedRoleReferenceIsAdoptedAsNoRole(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock, recRoleA)
	registry.mock.ExpectExec("INSERT INTO registry_role_templates").WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceMemberships(identity.mock, [3]interface{}{recOrgA, recUserA, recRoleB})
	expectMirroredMemberships(registry.mock)
	registry.mock.ExpectExec("INSERT INTO organization_member_roles").
		WithArgs(recOrgA, recUserA, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectMirroredTemplateIDs(registry.mock, recRoleA)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.OrphanedRoleRefs != 1 {
		t.Errorf("OrphanedRoleRefs = %d, want 1", report.OrphanedRoleRefs)
	}
	if err := registry.mock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry connection: %v", err)
	}
}

// TestReconcileMemberRoles_SkipsAndCountsUnparseableRows: a membership whose
// identifiers are not UUIDs cannot be represented in registry's columns. It is
// counted and skipped, not fatal — one malformed legacy row must not stop a
// deployment booting.
func TestReconcileMemberRoles_SkipsAndCountsUnparseableRows(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	expectSourceVerified(identity.mock)
	expectSourceRoleTemplates(identity.mock)
	expectSourceMemberships(identity.mock,
		[3]interface{}{"not-a-uuid", recUserA, nil},
		[3]interface{}{recOrgA, "also-not-a-uuid", nil})
	expectMirroredMemberships(registry.mock)
	expectMirroredTemplateIDs(registry.mock)

	report, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles = %v, want the bad rows counted rather than fatal", err)
	}
	if report.UnparseableRows != 2 {
		t.Errorf("UnparseableRows = %d, want 2", report.UnparseableRows)
	}
	if report.SourceMemberships != 0 {
		t.Errorf("SourceMemberships = %d, want 0 — neither row is representable", report.SourceMemberships)
	}
}

// TestReconcileMemberRoles_RefusesWhenTheMirrorIsUnreachable asserts the
// SENTINEL. This is the separate-identity-database topology, and it must be
// distinguishable from any other failure.
func TestReconcileMemberRoles_RefusesWhenTheMirrorIsUnreachable(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	registry.mock.ExpectQuery("SELECT to_regclass").
		WithArgs("registry_role_templates").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

	_, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if !errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("ReconcileMemberRoles = %v, want it to wrap ErrMirrorUnreachable", err)
	}
}

// TestReconcileMemberRoles_RefusesWhenTheSourceDoesNotResolve is the dangerous
// direction: a source that is not there must not be reported as a source with
// no rows, because that empties the mirror and the read cutover then revokes
// everybody at once.
func TestReconcileMemberRoles_RefusesWhenTheSourceDoesNotResolve(t *testing.T) {
	identity, registry := newReconcileMocks(t)

	expectMirrorVerified(registry.mock)
	identity.mock.ExpectQuery("SELECT to_regclass").
		WithArgs("organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

	_, err := ReconcileMemberRoles(context.Background(), identity.db, registry.db)
	if err == nil {
		t.Fatal("ReconcileMemberRoles = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "organization_members") {
		t.Errorf("error = %q, want it to name the table that did not resolve", err)
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error = %q, want it to say it is refusing rather than reporting an empty source", err)
	}
}

// TestReconcileReport_LogValueCarriesEveryCounter keeps the boot log honest: a
// counter added to the report but not to LogValue is a number the operator
// running the divergence query never sees.
func TestReconcileReport_LogValueCarriesEveryCounter(t *testing.T) {
	r := ReconcileReport{
		SourceMemberships: 1, SourceRoleTemplates: 2,
		MembershipsAdopted: 3, MembershipsConfirmed: 9, RoleTemplatesWritten: 4,
		MembershipsRemoved: 5, RoleTemplatesRemoved: 6,
		OrphanedRoleRefs: 7, UnparseableRows: 8,
	}
	attrs := r.LogValue().Group()
	if len(attrs) != 9 {
		t.Fatalf("LogValue has %d attributes, want 9 — one per counter on ReconcileReport", len(attrs))
	}
	seen := map[string]int64{}
	for _, a := range attrs {
		seen[a.Key] = a.Value.Int64()
	}
	for key, want := range map[string]int64{
		"source_memberships": 1, "source_role_templates": 2,
		"memberships_adopted": 3, "memberships_confirmed": 9, "role_templates_written": 4,
		"memberships_removed": 5, "role_templates_removed": 6,
		"orphaned_role_refs": 7, "unparseable_rows": 8,
	} {
		if seen[key] != want {
			t.Errorf("LogValue[%s] = %d, want %d", key, seen[key], want)
		}
	}
}

package repositories

import (
	"context"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Unit tests for the READ half of the cutover
// (sethbacon/terraform-suite-identity#206, phase 3b).
//
// The Postgres file (member_role_equivalence_pg_test.go) proves the two copies
// resolve the same authority. These pin the DECISIONS the read path makes that a
// real database would answer identically either way -- what a missing row means,
// what a failed query means, and which connection the write path reads back
// through -- and they run in CI, which the Postgres file does not.
//
// Every assertion is on an exact value. "No error" would pass for a reader that
// returned nothing at all, which is the failure mode with the largest blast
// radius here: an empty scope set denies, silently and plausibly.

func newReader(t *testing.T) (*MemberRoleReader, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewMemberRoleReader(db), mock
}

// TestReader_RoleFor_NoRowIsNotAnError pins the distinction migration 000055
// built into the schema and the read path depends on: a membership with no
// mirrored row yields (nil, nil), not an error and not an empty role.
//
// It matters because the two are handled differently one layer up: nil is
// reported as divergence and fails closed, while an error is returned to the
// caller and denies with a 500. Collapsing them would either hide a real
// dual-write gap or turn one into an outage.
func TestReader_RoleFor_NoRowIsNotAnError(t *testing.T) {
	reader, mock := newReader(t)
	mock.ExpectQuery("FROM organization_member_roles").
		WithArgs(testOrgID, testUserID).
		WillReturnRows(sqlmock.NewRows(registryRoleCols))

	role, err := reader.RoleFor(context.Background(), testOrgID, testUserID)
	if err != nil {
		t.Fatalf("RoleFor: %v", err)
	}
	if role != nil {
		t.Fatalf("RoleFor = %+v, want nil for a membership with no mirrored row", role)
	}
	// And the nil receiver must fail CLOSED rather than panic: every accessor
	// calls these three on whatever RoleFor returned.
	if got := role.id(); got != nil {
		t.Errorf("nil role id() = %v, want nil", got)
	}
	if got := role.scopes(); len(got) != 0 {
		t.Errorf("nil role scopes() = %v, want empty", got)
	}
	if got := role.namePtr(); got != nil {
		t.Errorf("nil role namePtr() = %v, want nil", got)
	}
}

// TestReader_RoleFor_MirroredRowWithNoRole is the OTHER side of that
// distinction: a row exists and carries no role. It must come back as a non-nil
// MirroredRole with a nil id, because that is "no role here" rather than "not
// mirrored", and only the second is drift.
func TestReader_RoleFor_MirroredRowWithNoRole(t *testing.T) {
	reader, mock := newReader(t)
	mock.ExpectQuery("FROM organization_member_roles").
		WillReturnRows(sqlmock.NewRows(registryRoleCols).AddRow(nil, "", "", []byte(`[]`)))

	role, err := reader.RoleFor(context.Background(), testOrgID, testUserID)
	if err != nil {
		t.Fatalf("RoleFor: %v", err)
	}
	if role == nil {
		t.Fatal("a mirrored row carrying no role came back as nil, which is how " +
			"'this member is entitled to nothing' becomes indistinguishable from " +
			"'the dual-write missed this member'")
	}
	if role.RoleTemplateID != nil {
		t.Errorf("RoleTemplateID = %v, want nil", *role.RoleTemplateID)
	}
	if len(role.Scopes) != 0 {
		t.Errorf("Scopes = %v, want empty", role.Scopes)
	}
}

// TestReader_RoleFor_QueryFailureIsReturned: a failed lookup must NOT be
// absorbed into "no role". An empty scope set denies and looks exactly like an
// unprivileged member, so absorbing it would turn a database fault into a
// plausible-looking authorization answer nobody investigates.
func TestReader_RoleFor_QueryFailureIsReturned(t *testing.T) {
	reader, mock := newReader(t)
	sentinel := errors.New("connection reset")
	mock.ExpectQuery("FROM organization_member_roles").WillReturnError(sentinel)

	role, err := reader.RoleFor(context.Background(), testOrgID, testUserID)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v — a bare non-nil check would also pass for "+
			"a reader that mapped every failure onto 'no role'", err, sentinel)
	}
	if role != nil {
		t.Errorf("role = %+v, want nil alongside the error", role)
	}
}

// TestReader_RolesForUser_KeysByOrganization is the property that keeps the
// cross-organization accessors honest: a user with two memberships must get two
// DISTINCT roles, attached to the right organizations. Keying them wrongly is
// the privilege-escalation shape -- one organization's admin role applied in
// another.
func TestReader_RolesForUser_KeysByOrganization(t *testing.T) {
	reader, mock := newReader(t)
	mock.ExpectQuery(`SELECT omr\.organization_id,.*WHERE omr\.user_id`).
		WithArgs(testUserID).
		WillReturnRows(sqlmock.NewRows(append([]string{"organization_id"}, registryRoleCols...)).
			AddRow(testOrgID, testRoleID, "admin", "Admin", []byte(`["organizations:write"]`)).
			AddRow(testOtherOrg, nil, "", "", []byte(`[]`)))

	roles, err := reader.RolesForUser(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("RolesForUser: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("len = %d, want 2", len(roles))
	}
	first := roles[testOrgID]
	if first == nil || first.RoleTemplateID == nil || *first.RoleTemplateID != testRoleID {
		t.Fatalf("roles[%s] = %+v, want role %s", testOrgID, first, testRoleID)
	}
	if len(first.Scopes) != 1 || first.Scopes[0] != "organizations:write" {
		t.Errorf("roles[%s].Scopes = %v, want [organizations:write]", testOrgID, first.Scopes)
	}
	second := roles[testOtherOrg]
	if second == nil {
		t.Fatalf("roles[%s] missing", testOtherOrg)
	}
	if second.RoleTemplateID != nil {
		t.Errorf("roles[%s].RoleTemplateID = %v, want nil", testOtherOrg, *second.RoleTemplateID)
	}
	if len(second.Scopes) != 0 {
		t.Errorf("roles[%s].Scopes = %v, want empty — the second organization's role must not "+
			"inherit the first's", testOtherOrg, second.Scopes)
	}
}

// TestReader_RolesForUsers_EmptyInputIssuesNoQuery: the bulk read is called once
// per admin user page, including pages where nobody has a membership. Asking the
// database to confirm that `= ANY('{}')` matches nothing is a round trip whose
// answer is already known.
func TestReader_RolesForUsers_EmptyInputIssuesNoQuery(t *testing.T) {
	reader, mock := newReader(t)

	roles, err := reader.RolesForUsers(context.Background(), nil)
	if err != nil {
		t.Fatalf("RolesForUsers: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("len = %d, want 0", len(roles))
	}
	// No expectation was queued, so any statement at all is unexpected.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestReader_GetRoleTemplate_MissReportsTheStoreSentinel: the handlers map
// store.ErrNotFound onto 404. Answering a different error would turn "no such
// role template" into a 500 on every admin screen that looks one up.
func TestReader_GetRoleTemplate_MissReportsTheStoreSentinel(t *testing.T) {
	reader, mock := newReader(t)
	mock.ExpectQuery("FROM registry_role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	tpl, err := reader.GetRoleTemplate(context.Background(), uuid.New())
	if !errors.Is(err, identitystore.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if tpl != nil {
		t.Errorf("tpl = %+v, want nil", tpl)
	}
}

// TestOrganizationRepository_MirrorsTheSourceNotTheMirror is a REGRESSION guard
// for the defect phase 3b creates and phase 3a could not have.
//
// The write path re-reads the membership it just wrote and mirrors what it
// finds. Phase 3a read it back through `r.GetMember`, which was then the store's
// promoted method. Phase 3b overrides GetMember to REPLACE the role with
// whatever registry's tables already hold -- so the same expression now reads
// the mirror, and mirroring that writes the mirror's current value back into
// itself. The dual-write becomes a no-op on every role CHANGE: the source moves,
// the mirror does not, and since reads come from the mirror the change never
// takes effect anywhere. No error, no failing behavioural test.
//
// The fixture is the distinguishing one: the source read-back returns a role
// that is DIFFERENT from what registry holds. A correct implementation mirrors
// the source's; the broken one issues a registry read here and then writes the
// old value.
func TestOrganizationRepository_MirrorsTheSourceNotTheMirror(t *testing.T) {
	repo, mock := newOrgRepo(t)

	const landed = "55555555-5555-5555-5555-555555555555"
	expectSourceMemberInsert(mock)
	expectReadBack(mock, landed)
	// NOTHING between the read-back and the mirror write. If the read-back went
	// through this type's override it would query organization_member_roles
	// here, which no expectation matches.
	expectMirrorAssign(mock, landed)

	asked := testRoleID
	if err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &asked,
		identitystore.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the write path did not mirror the role the SOURCE now holds (%s). "+
			"mirrorMemberFromSource must call r.OrganizationRepository.GetMember, not r.GetMember: "+
			"the override replaces the role with registry's current value, so mirroring it writes "+
			"the mirror back into itself and every role change is silently lost: %v", landed, err)
	}
}

// TestCompareRole_ReportsEachDivergenceKind pins the signal that keeps the
// cutover from going silent between drift-check runs.
//
// Asserted on the METRIC, by value, because the log is not machine-checkable and
// a comparison that quietly did nothing would otherwise look identical to one
// that found agreement.
func TestCompareRole_ReportsEachDivergenceKind(t *testing.T) {
	role := func(id string) *MirroredRole {
		if id == "" {
			return &MirroredRole{Scopes: []string{}}
		}
		return &MirroredRole{RoleTemplateID: &id, Scopes: []string{}}
	}
	ptr := func(s string) *string { return &s }

	cases := []struct {
		name     string
		identity *string
		registry *MirroredRole
		wantKind string // empty means "must not report anything"
	}{
		{"agreeing roles", ptr(testRoleID), role(testRoleID), ""},
		{"both carry no role", nil, role(""), ""},
		{"no mirrored row at all", ptr(testRoleID), nil, DivergenceMissingMirror},
		{"different templates", ptr(testRoleID), role("99999999-9999-9999-9999-999999999999"), DivergenceRoleDiffers},
		{"registry cleared the role", ptr(testRoleID), role(""), DivergenceRoleDiffers},
		{"registry invented a role", nil, role(testRoleID), DivergenceRoleDiffers},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			accessor := "test-" + tc.name
			before := map[string]float64{
				DivergenceMissingMirror: divergenceCount(t, accessor, DivergenceMissingMirror),
				DivergenceRoleDiffers:   divergenceCount(t, accessor, DivergenceRoleDiffers),
			}

			compareRole(context.Background(), accessor, testOrgID, testUserID, tc.identity, tc.registry)

			for _, kind := range []string{DivergenceMissingMirror, DivergenceRoleDiffers} {
				got := divergenceCount(t, accessor, kind) - before[kind]
				want := 0.0
				if kind == tc.wantKind {
					want = 1.0
				}
				if got != want {
					t.Errorf("%s counter moved by %v, want %v", kind, got, want)
				}
			}
		})
	}
}

// divergenceCount reads one counter's current value, by label pair.
func divergenceCount(t *testing.T, accessor, kind string) float64 {
	t.Helper()
	return testutil.ToFloat64(RoleReadDivergenceTotal.WithLabelValues(accessor, kind))
}

// TestDriftInMemberships_ClassifiesEveryDirection pins the classification the
// gate reports, without a database.
//
// The kinds are not interchangeable: an operator reads them to decide whether to
// restart (a mirror that fell behind), to repair identity data (a membership
// naming a template that does not exist), or to investigate a grant the product
// never issued (a mirrored row with no membership). A comparison that found the
// right ROWS under the wrong KINDS would send them to the wrong remedy.
func TestDriftInMemberships_ClassifiesEveryDirection(t *testing.T) {
	tpl := uuid.New()
	other := uuid.New()
	templates := []*models.RoleTemplate{{ID: tpl}, {ID: other}}

	id := func(u uuid.UUID) *string { s := u.String(); return &s }
	missing := uuid.New()

	source := map[memberKey]*string{
		{orgID: "org-agree", userID: "u"}:   id(tpl),
		{orgID: "org-differs", userID: "u"}: id(tpl),
		{orgID: "org-absent", userID: "u"}:  id(tpl),
		{orgID: "org-orphan", userID: "u"}:  id(missing),
	}
	mirrored := map[memberKey]*string{
		{orgID: "org-agree", userID: "u"}:     id(tpl),
		{orgID: "org-differs", userID: "u"}:   id(other),
		{orgID: "org-orphan", userID: "u"}:    nil,
		{orgID: "org-nomembers", userID: "u"}: id(tpl),
	}

	rows := driftInMemberships(source, mirrored, templates)
	got := map[string]string{}
	for _, r := range rows {
		if prev, dup := got[r.OrganizationID]; dup {
			t.Fatalf("organization %s reported twice (%s and %s)", r.OrganizationID, prev, r.Kind)
		}
		got[r.OrganizationID] = r.Kind
	}

	want := map[string]string{
		"org-differs":   DriftRoleDiffers,
		"org-absent":    DriftMembershipNotMirrored,
		"org-orphan":    DriftMembershipRoleMissingTemplate,
		"org-nomembers": DriftMirrorWithoutMembership,
	}
	for org, kind := range want {
		if got[org] != kind {
			t.Errorf("organization %s classified %q, want %q", org, got[org], kind)
		}
	}
	if kind, reported := got["org-agree"]; reported {
		t.Errorf("an agreeing membership was reported as %q — a gate that reports drift on "+
			"correct rows can never be satisfied, so it stops being a gate", kind)
	}
	if len(rows) != len(want) {
		t.Errorf("reported %d row(s), want %d: %v", len(rows), len(want), rows)
	}
}

// TestDriftInTemplates_SeesNameAndScopeDifferences covers the half the SQL
// divergence query phase 3a shipped could not: a template that agrees on id and
// scopes but disagrees on NAME still resolves to a different row for every
// name-keyed lookup.
func TestDriftInTemplates_SeesNameAndScopeDifferences(t *testing.T) {
	same := uuid.New()
	renamed := uuid.New()
	rescoped := uuid.New()
	onlySource := uuid.New()
	onlyMirror := uuid.New()

	source := []*models.RoleTemplate{
		{ID: same, Name: "viewer", Scopes: []string{"modules:read"}},
		{ID: renamed, Name: "publisher", Scopes: []string{"modules:write"}},
		{ID: rescoped, Name: "auditor", Scopes: []string{"audit:read", "modules:read"}},
		{ID: onlySource, Name: "new", Scopes: []string{"modules:read"}},
	}
	mirrored := []*models.RoleTemplate{
		// Reordered scopes: a set, not a list. Reporting this would make the
		// gate un-passable on a correct deployment.
		{ID: same, Name: "viewer", Scopes: []string{"modules:read"}},
		{ID: renamed, Name: "publisher-renamed", Scopes: []string{"modules:write"}},
		{ID: rescoped, Name: "auditor", Scopes: []string{"modules:read"}},
		{ID: onlyMirror, Name: "stale", Scopes: []string{}},
	}

	rows := driftInTemplates(source, mirrored)
	got := map[string]string{}
	for _, r := range rows {
		got[r.RoleTemplateID] = r.Kind
	}
	want := map[uuid.UUID]string{
		renamed:    DriftTemplateNameDiffers,
		rescoped:   DriftTemplateScopesDiffer,
		onlySource: DriftTemplateNotMirrored,
		onlyMirror: DriftMirroredTemplateOrphaned,
	}
	for id, kind := range want {
		if got[id.String()] != kind {
			t.Errorf("template %s classified %q, want %q", id, got[id.String()], kind)
		}
	}
	if kind, reported := got[same.String()]; reported {
		t.Errorf("an identical template was reported as %q", kind)
	}
}

// TestSameScopes_IsSetEquality pins that scope comparison ignores order and
// tolerates nothing else. Order is not meaning; a missing scope is.
func TestSameScopes_IsSetEquality(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"identical", []string{"a", "b"}, []string{"a", "b"}, true},
		{"reordered", []string{"b", "a"}, []string{"a", "b"}, true},
		{"both empty", nil, []string{}, true},
		{"one missing", []string{"a", "b"}, []string{"a"}, false},
		{"one extra", []string{"a"}, []string{"a", "b"}, false},
		{"same length, different member", []string{"a", "b"}, []string{"a", "c"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameScopes(tc.a, tc.b); got != tc.want {
				t.Errorf("sameScopes(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestCheckMemberRoleDrift_RefusesAnUnreachableSource is the "could not check"
// path. It must be an ERROR and never a clean report: a gate that answers "no
// drift" for a database it could not read gates nothing open.
//
// The assertion is on WHICH refusal, not on "an error happened". The first
// version of this test checked `err != nil` and was inert under mutation:
// deleting the source probe entirely still produced an error, because the very
// next statement had no sqlmock expectation and failed for an unrelated reason.
// It reported green for a gate that had stopped checking the thing it names.
func TestCheckMemberRoleDrift_RefusesAnUnreachableSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// to_regclass returns NULL: the table does not resolve on this connection.
	mock.ExpectQuery("to_regclass").WithArgs("organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

	report, err := CheckMemberRoleDrift(context.Background(), db, db)
	if err == nil {
		t.Fatal("CheckMemberRoleDrift returned no error for a source that does not resolve")
	}
	const want = "effective organization_members does not resolve on the identity connection"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %q, want it to name the unresolved SOURCE table (%q). Any other error "+
			"means the source probe did not run and something downstream failed instead", err, want)
	}
	if !report.Clean() {
		t.Errorf("report carried %d row(s) alongside the error; the caller must not be able to "+
			"read a partial comparison as a result", len(report.Rows))
	}
	if report.SourceMemberships != 0 {
		t.Errorf("SourceMemberships = %d, want 0", report.SourceMemberships)
	}
}

// TestCheckMemberRoleDrift_RefusesUnreachableRegistryTables is the same refusal
// on the other connection. Separate, and asserting a DIFFERENT message, because
// the two failures send an operator to different places: an unresolved source
// means the identity connection is wrong, an unresolved mirror means migration
// 000055 has not run where this connection can see it.
func TestCheckMemberRoleDrift_RefusesUnreachableRegistryTables(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// The source resolves...
	for _, table := range identitySourceTables {
		mock.ExpectQuery("to_regclass").WithArgs(table).
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("public." + table))
	}
	// ...and registry's own tables do not.
	mock.ExpectQuery("to_regclass").WithArgs("registry_role_templates").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

	report, err := CheckMemberRoleDrift(context.Background(), db, db)
	if err == nil {
		t.Fatal("CheckMemberRoleDrift returned no error for mirror tables that do not resolve")
	}
	if !errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("err = %v, want it to wrap ErrMirrorUnreachable", err)
	}
	if !report.Clean() {
		t.Errorf("report carried %d row(s) alongside the error", len(report.Rows))
	}
}

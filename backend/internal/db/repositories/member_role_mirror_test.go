package repositories

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Behavioural half of the role-assignment dual-write
// (sethbacon/terraform-suite-identity#206, migration 000055). The structural
// half is member_role_mirror_class_test.go.
//
// Every assertion below is on an EXACT statement and EXACT arguments. A bare
// "no error" would pass for a repository that mirrored nothing at all, which is
// the entire defect this phase can produce.

const (
	testOrgID    = "11111111-1111-1111-1111-111111111111"
	testUserID   = "22222222-2222-2222-2222-222222222222"
	testRoleID   = "33333333-3333-3333-3333-333333333333"
	testOtherOrg = "44444444-4444-4444-4444-444444444444"
)

// expectSourceMemberInsert queues the store's own scoped INSERT.
func expectSourceMemberInsert(mock sqlmock.Sqlmock) {
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// expectReadBack queues the GetMember the wrapper issues to learn what actually
// landed, returning the given role template id (nil for "no role").
func expectReadBack(mock sqlmock.Sqlmock, roleTemplateID interface{}) {
	mock.ExpectQuery("SELECT organization_id, user_id, role_template_id, created_at").
		WithArgs(testOrgID, testUserID).
		WillReturnRows(sqlmock.NewRows(orgMemberCols).
			AddRow(testOrgID, testUserID, roleTemplateID, time.Now()))
}

// expectMirrorAssign queues the mirror upsert with the exact arguments it must
// carry.
func expectMirrorAssign(mock sqlmock.Sqlmock, roleTemplateID interface{}) {
	mock.ExpectExec("INSERT INTO organization_member_roles").
		WithArgs(testOrgID, testUserID, roleTemplateID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func TestOrganizationRepository_AddMemberWithRoleTemplate_MirrorsTheAssignment(t *testing.T) {
	repo, mock := newOrgRepo(t)

	expectSourceMemberInsert(mock)
	expectReadBack(mock, testRoleID)
	expectMirrorAssign(mock, testRoleID)

	role := testRoleID
	if err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &role,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the membership landed but registry's own organization_member_roles was not written: %v", err)
	}
}

// TestOrganizationRepository_AddMemberWithParams_MirrorsTheAssignment is the
// method the IdP group-mapping reconciliation calls. It is overridden separately
// from AddMemberWithRoleTemplate because Go has no virtual dispatch: the store's
// implementation calls the STORE's AddMemberWithRoleTemplate, never the
// wrapper's, so an override that "obviously" comes for free does not.
func TestOrganizationRepository_AddMemberWithParams_MirrorsTheAssignment(t *testing.T) {
	repo, mock := newOrgRepo(t)

	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("org_owner").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(testRoleID))
	expectSourceMemberInsert(mock)
	expectReadBack(mock, testRoleID)
	expectMirrorAssign(mock, testRoleID)

	if err := repo.AddMemberWithParams(context.Background(), testOrgID, testUserID, "org_owner",
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithParams: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("name-based add did not mirror: %v", err)
	}
}

func TestOrganizationRepository_UpdateMemberRoleTemplate_MirrorsTheNewRole(t *testing.T) {
	repo, mock := newOrgRepo(t)

	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectReadBack(mock, testRoleID)
	expectMirrorAssign(mock, testRoleID)

	role := testRoleID
	if err := repo.UpdateMemberRoleTemplate(context.Background(), testOrgID, testUserID, &role,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("UpdateMemberRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("role change did not mirror: %v", err)
	}
}

// TestOrganizationRepository_ClearingARole_MirrorsNULLNotAbsence pins the
// representation migration 000055 chose: a membership with no role is a row
// carrying NULL, not a missing row. If clearing a role deleted the mirror row
// instead, "no role here" and "not mirrored yet" would be the same state and
// the divergence query could not tell them apart.
func TestOrganizationRepository_ClearingARole_MirrorsNULLNotAbsence(t *testing.T) {
	repo, mock := newOrgRepo(t)

	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectReadBack(mock, nil)
	expectMirrorAssign(mock, nil)

	if err := repo.UpdateMemberRoleTemplate(context.Background(), testOrgID, testUserID, nil,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("UpdateMemberRoleTemplate(nil): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("clearing a role did not mirror a NULL assignment: %v", err)
	}
}

// TestOrganizationRepository_MirrorsWhatTheSourceSays_NotTheArgument is why the
// wrapper reads the membership back instead of reusing the caller's value.
//
// The store's writes are scoped and its name-based methods resolve the template
// internally, so the argument is a request and the row is the answer. Here the
// source ends up holding a DIFFERENT template than the one passed in, and the
// mirror must carry the row's value.
func TestOrganizationRepository_MirrorsWhatTheSourceSays_NotTheArgument(t *testing.T) {
	repo, mock := newOrgRepo(t)

	const landed = "55555555-5555-5555-5555-555555555555"
	expectSourceMemberInsert(mock)
	expectReadBack(mock, landed)
	expectMirrorAssign(mock, landed)

	asked := testRoleID
	if err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &asked,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the mirror carried the requested role rather than the one the source holds: %v", err)
	}
}

func TestOrganizationRepository_RemoveMember_ClearsTheMirroredRole(t *testing.T) {
	repo, mock := newOrgRepo(t)

	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testOrgID, testUserID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.RemoveMember(context.Background(), testOrgID, testUserID,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("removal left the mirrored role behind: %v", err)
	}
}

// TestOrganizationRepository_RemoveAllMemberships_ClearsExactlyWhatWasRemoved
// asserts the sweep clears the organizations the store actually emptied and no
// others. A scoped SCIM deprovision must not reach outside its tenant in the
// mirror any more than it does at the source (issue #160).
func TestOrganizationRepository_RemoveAllMemberships_ClearsExactlyWhatWasRemoved(t *testing.T) {
	repo, mock := newOrgRepo(t)

	mock.ExpectQuery("DELETE FROM organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).
			AddRow(testOrgID).AddRow(testOtherOrg))
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testOrgID, testUserID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testOtherOrg, testUserID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	removed, err := repo.RemoveAllMembershipsForUser(context.Background(), testUserID,
		store.OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("RemoveAllMembershipsForUser: %v", err)
	}
	if got := removed.OrganizationIDs(); len(got) != 2 {
		t.Errorf("returned scope = %v, want the two emptied organizations", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the sweep did not clear both mirrored assignments: %v", err)
	}
}

// captureMirrorFailures redirects the default slog logger for the duration of a
// test and returns the mirror-failure messages it recorded.
//
// It exists because sqlmock cannot express "and nothing else ran".
// ExpectationsWereMet only reports expectations that were NOT consumed; an
// EXTRA statement is refused by returning an error to the caller, and the whole
// design here is that the caller swallows mirror errors. A first version of the
// ordering test below asserted ExpectationsWereMet and PASSED with the mirror
// moved in front of the source-error check — the mutation ran the mirror after
// a failed write and nothing noticed. Every mirror attempt that fails goes
// through mirrorFailed, so the log is the observable this property actually has.
func captureMirrorFailures(t *testing.T) func() []string {
	t.Helper()
	var records []string
	prev := slog.Default()
	slog.SetDefault(slog.New(&capturingHandler{msgs: &records}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []string { return records }
}

type capturingHandler struct{ msgs *[]string }

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.msgs = append(*h.msgs, r.Message)
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func mirrorFailureCount(msgs []string) int {
	var n int
	for _, m := range msgs {
		if strings.Contains(m, "mirror write failed") {
			n++
		}
	}
	return n
}

// TestOrganizationRepository_FailedSourceWrite_MirrorsNothing is the ordering
// property. The mirror runs only after the authoritative write succeeded; a
// mirror that ran first, or ran regardless, would record an assignment the
// product never made — and would do so in the table the read cutover switches
// onto.
//
// The mock is queued with the failing INSERT and nothing else, so any statement
// the wrapper issues afterwards is refused — and every refused mirror statement
// is reported through mirrorFailed. Zero such reports is the assertion.
func TestOrganizationRepository_FailedSourceWrite_MirrorsNothing(t *testing.T) {
	repo, mock := newOrgRepo(t)
	failures := captureMirrorFailures(t)

	sourceErr := errors.New("source insert refused")
	mock.ExpectExec("INSERT INTO organization_members").WillReturnError(sourceErr)

	role := testRoleID
	err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &role,
		store.OrgScopeAllOrganizations())
	if err == nil {
		t.Fatal("AddMemberWithRoleTemplate = nil, want the source error propagated")
	}
	if !errors.Is(err, sourceErr) {
		t.Errorf("error = %v, want it to wrap the source error", err)
	}
	if n := mirrorFailureCount(failures()); n != 0 {
		t.Errorf("the mirror was attempted %d time(s) after the source write failed. The mirror must "+
			"run only once the authoritative write has committed; running it regardless records an "+
			"assignment the product never made, in the table the read cutover switches onto", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the source write was not attempted: %v", err)
	}
}

// TestOrganizationRepository_MirrorFailureDoesNotFailTheRequest is the other
// half of that contract, and it is deliberate rather than lax. The
// authoritative write has committed and reads do not come from the mirror, so
// answering an error would make this phase change behaviour on the privilege
// paths — the one thing it must not do. Divergence is caught by the startup
// reconcile and by the query in docs/identity-schema.md.
func TestOrganizationRepository_MirrorFailureDoesNotFailTheRequest(t *testing.T) {
	repo, mock := newOrgRepo(t)
	failures := captureMirrorFailures(t)

	expectSourceMemberInsert(mock)
	expectReadBack(mock, testRoleID)
	mock.ExpectExec("INSERT INTO organization_member_roles").
		WillReturnError(errors.New("relation \"organization_member_roles\" does not exist"))

	role := testRoleID
	if err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &role,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate = %v, want nil: the membership committed and nothing "+
			"reads the mirror, so a mirror failure must not surface as a failed privilege change", err)
	}
	// Absorbed, but never silent — and this is also the positive control for
	// captureMirrorFailures, so the zero-count assertion in the ordering test
	// above cannot pass because the capture is broken.
	if n := mirrorFailureCount(failures()); n != 1 {
		t.Errorf("mirror failures logged = %d, want exactly 1. A divergence that is swallowed without "+
			"a record is one nobody can act on before the read cutover", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected statements: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Role templates
// ---------------------------------------------------------------------------

func TestRBACRepository_CreateRoleTemplate_MirrorsIt(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse(testRoleID)

	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO registry_role_templates").
		WithArgs(id, "publisher", "Publisher", nil, []byte(`["modules:write"]`), false).
		WillReturnResult(sqlmock.NewResult(0, 1))

	tmpl := &models.RoleTemplate{
		ID: id, Name: "publisher", DisplayName: "Publisher",
		Scopes: []string{"modules:write"},
	}
	if err := repo.CreateRoleTemplate(context.Background(), tmpl); err != nil {
		t.Fatalf("CreateRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the template was created but not mirrored: %v", err)
	}
}

// TestRBACRepository_UpdateRoleTemplate_MirrorsTheNewScopes is the role change
// with no statement naming a membership: editing a template's scopes changes
// what every member holding it may do.
func TestRBACRepository_UpdateRoleTemplate_MirrorsTheNewScopes(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse(testRoleID)

	mock.ExpectExec("UPDATE role_templates").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO registry_role_templates").
		WithArgs(id, "publisher", "Publisher", nil, []byte(`["modules:write","providers:write"]`), false).
		WillReturnResult(sqlmock.NewResult(0, 1))

	tmpl := &models.RoleTemplate{
		ID: id, Name: "publisher", DisplayName: "Publisher",
		Scopes: []string{"modules:write", "providers:write"},
	}
	if err := repo.UpdateRoleTemplate(context.Background(), tmpl); err != nil {
		t.Fatalf("UpdateRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the new scope set was not mirrored: %v", err)
	}
}

func TestRBACRepository_DeleteRoleTemplate_MirrorsTheDeletion(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse(testRoleID)

	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM registry_role_templates").
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.DeleteRoleTemplate(context.Background(), id); err != nil {
		t.Fatalf("DeleteRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the deletion was not mirrored: %v", err)
	}
}

// TestRBACRepository_FailedRoleTemplateWrite_MirrorsNothing is the ordering
// property on the template half.
func TestRBACRepository_FailedRoleTemplateWrite_MirrorsNothing(t *testing.T) {
	repo, mock := newRBACRepo(t)

	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnError(errors.New("refused"))

	if err := repo.DeleteRoleTemplate(context.Background(), uuid.MustParse(testRoleID)); err == nil {
		t.Fatal("DeleteRoleTemplate = nil, want the source error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the mirror was written after the source delete failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

// TestMemberRoleMirror_Verify_ReportsAnUnreachableTable asserts the SENTINEL,
// not just an error. The startup check has to tell "the tables are not here"
// (an operator action, and the expected state in a separate-identity-database
// topology) apart from any other failure.
func TestMemberRoleMirror_Verify_ReportsAnUnreachableTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT to_regclass").
		WithArgs("registry_role_templates").
		WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow(nil))

	err = NewMemberRoleMirror(db).Verify(context.Background())
	if !errors.Is(err, ErrMirrorUnreachable) {
		t.Fatalf("Verify() = %v, want it to wrap ErrMirrorUnreachable", err)
	}
}

func TestMemberRoleMirror_Verify_AcceptsResolvedTables(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	for _, table := range []string{"registry_role_templates", "organization_member_roles"} {
		mock.ExpectQuery("SELECT to_regclass").
			WithArgs(table).
			WillReturnRows(sqlmock.NewRows([]string{"to_regclass"}).AddRow("public." + table))
	}

	if err := NewMemberRoleMirror(db).Verify(context.Background()); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Verify did not probe both tables: %v", err)
	}
}

// TestMemberRoleMirror_UpsertRoleTemplate_NeverWritesJSONNull pins the one
// representation trap in the upsert: json.Marshal of a nil []string is the
// literal `null`, a legal jsonb value that every scope reader would then fail
// to unmarshal into a list.
func TestMemberRoleMirror_UpsertRoleTemplate_NeverWritesJSONNull(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO registry_role_templates").
		WithArgs(uuid.MustParse(testRoleID), "empty", "Empty", nil, []byte(`[]`), false).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = NewMemberRoleMirror(db).UpsertRoleTemplate(context.Background(), &models.RoleTemplate{
		ID: uuid.MustParse(testRoleID), Name: "empty", DisplayName: "Empty", Scopes: nil,
	})
	if err != nil {
		t.Fatalf("UpsertRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("scopes were not written as an empty JSON array: %v", err)
	}
}

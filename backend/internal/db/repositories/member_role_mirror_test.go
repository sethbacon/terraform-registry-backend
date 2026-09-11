package repositories

import (
	"context"
	"errors"
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
// expectRegistryTemplateByName stages the lookup every NAME-based write now does
// FIRST, against registry's own templates (#1056). Registry decides what a role
// name means here, so an unknown name must fail with nothing written anywhere.
func expectRegistryTemplateByName(mock sqlmock.Sqlmock, name, id string) {
	rows := sqlmock.NewRows([]string{"id"})
	if id != "" {
		rows.AddRow(id)
	}
	mock.ExpectQuery("SELECT id FROM registry_role_templates WHERE name").WithArgs(name).WillReturnRows(rows)
}

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

	// Registry's own resolution comes FIRST — before identity is touched at all.
	expectRegistryTemplateByName(mock, "org_owner", testRoleID)
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

// THE MIRROR CARRIES THE ROLE THE CALLER ASKED FOR, not the one identity's
// column ended up holding. This inverted in #1056 and the inversion is the fix.
//
// Before, the mirror copied the read-back's role_template_id. In a coupled
// deployment that column is identity's, and identity resolves a role name
// against ITS templates — so a registry grant could land registry's table with
// an id registry did not choose. Registry decides its own roles; the read-back
// is consulted for the membership FACT alone.
func TestOrganizationRepository_MirrorsTheRequestedRole_NotTheSourceColumn(t *testing.T) {
	repo, mock := newOrgRepo(t)

	const landed = "55555555-5555-5555-5555-555555555555"
	expectSourceMemberInsert(mock)
	expectReadBack(mock, landed)         // identity's column says something else...
	expectMirrorAssign(mock, testRoleID) // ...and registry records what was ASKED for.

	asked := testRoleID
	if err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &asked,
		store.OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("AddMemberWithRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the mirror carried identity's role (%s) rather than the requested one (%s). "+
			"Taking the role from the read-back is how the sibling's opinion reached registry's "+
			"table on the write path, the same way the boot reconcile's copy did (#1056): %v",
			landed, testRoleID, err)
	}
}

func TestOrganizationRepository_RemoveMember_ClearsTheMirroredRole(t *testing.T) {
	repo, mock := newOrgRepo(t)

	// REVOCATION: the mirror goes FIRST (#1056), so a failure there returns
	// before identity is touched and nothing has changed anywhere.
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testOrgID, testUserID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM organization_members").
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

	// PRE-PASS, before identity is touched: a platform-wide scope clears the
	// user's assignments everywhere in one statement.
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testUserID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery("DELETE FROM organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).
			AddRow(testOrgID).AddRow(testOtherOrg))
	// POST-PASS over exactly what identity reported removed. Idempotent, and not
	// redundant: a grant racing between the two legs would otherwise leave an
	// assignment behind for a membership that no longer exists.
	mock.ExpectExec("DELETE FROM organization_member_roles").
		WithArgs(testUserID, testOrgID, testOtherOrg).
		WillReturnResult(sqlmock.NewResult(0, 0))

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

// A FAILED SOURCE WRITE MIRRORS NOTHING.
//
// The mirror must run only once the authoritative write has committed; running
// it regardless records an assignment the product never made, in the table every
// authorization decision reads.
//
// ASSERTED ON THE MOCK, not on a log line. Until #1057 a swallowed mirror
// failure was reported through mirrorFailed and the count of those was the
// observable; nothing swallows any more, so that count is always zero and would
// pass whatever the code did. The mock is the stronger statement: no expectation
// is staged for organization_member_roles, so any statement against it fails
// this test outright.
func TestOrganizationRepository_FailedSourceWrite_MirrorsNothing(t *testing.T) {
	repo, mock := newOrgRepo(t)

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
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected statements after the source write failed — the mirror ran anyway: %v", err)
	}
}

// A FAILED MIRROR LEG FAILS THE REQUEST. This inverted in #1056.
//
// It was right to swallow while nothing read these tables, and wrong from the
// moment they became the authority. Concretely: an administrator demotes a
// principal from `admin` to `viewer`, the identity leg commits, the mirror write
// fails, and the old behaviour returned 200 with an audit entry recording the
// demotion — while organization_member_roles still said `admin`, which is the
// table every read resolves against. The principal kept administrator scopes,
// the API said the demotion worked, and nothing surfaced it until a restart.
//
// The error is safe to return because the write is idempotent: the retry it
// invites cannot double-apply.
func TestOrganizationRepository_MirrorFailureFailsTheRequest(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mirrorErr := errors.New("relation \"organization_member_roles\" does not exist")

	expectSourceMemberInsert(mock)
	expectReadBack(mock, testRoleID)
	mock.ExpectExec("INSERT INTO organization_member_roles").WillReturnError(mirrorErr)

	role := testRoleID
	err := repo.AddMemberWithRoleTemplate(context.Background(), testOrgID, testUserID, &role,
		store.OrgScopeAllOrganizations())
	if err == nil {
		t.Fatal("AddMemberWithRoleTemplate = nil, want the mirror failure returned: these tables " +
			"decide authorization, so a swallowed failure is a privilege change that reported " +
			"success and did not happen")
	}
	if !errors.Is(err, mirrorErr) {
		t.Errorf("error = %v, want it to wrap the mirror error so the caller can see the cause", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected statements: %v", err)
	}
}

// TestMemberRoleMirror_ClearUserEverywhere_IsUnscopedByTenant is the GDPR
// erasure's mirror call, and it is deliberately unscoped.
//
// It is the one path that must reach every organization: eraseTx removes the
// subject's memberships with no tenant predicate at all, so a scoped mirror
// delete would leave the erased subject's authorization behind wherever the
// erasure had already removed the membership. The assertion is on the exact
// statement, because "unscoped" is the property and a WHERE clause is how it
// would silently stop being true.
func TestMemberRoleMirror_ClearUserEverywhere_IsUnscopedByTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM organization_member_roles WHERE user_id = \\$1").
		WithArgs(testUserID).
		WillReturnResult(sqlmock.NewResult(0, 3))

	if err := NewMemberRoleMirror(db).ClearUserEverywhere(context.Background(), testUserID); err != nil {
		t.Fatalf("ClearUserEverywhere: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the erased subject's mirrored assignments were not cleared: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Role templates
// ---------------------------------------------------------------------------

func TestRBACRepository_CreateRoleTemplate_MirrorsIt(t *testing.T) {
	repo, mock := newRBACRepo(t)
	id := uuid.MustParse(testRoleID)

	// REGISTRY FIRST since #1057: registry_role_templates is no longer derived,
	// so this write IS the authority change and its failure is returned.
	mock.ExpectExec("INSERT INTO registry_role_templates").
		WithArgs(id, "publisher", "Publisher", nil, []byte(`["modules:write"]`), false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO role_templates").
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

	// REGISTRY FIRST since #1057: registry_role_templates is no longer derived,
	// so this write IS the authority change and its failure is returned.
	mock.ExpectExec("INSERT INTO registry_role_templates").
		WithArgs(id, "publisher", "Publisher", nil, []byte(`["modules:write","providers:write"]`), false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE role_templates").
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

	// REVOCATION, REGISTRY FIRST (#1057): deleting here nulls every assignment
	// that named the template, so a crash between the legs is less privileged.
	mock.ExpectExec("DELETE FROM registry_role_templates").
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.DeleteRoleTemplate(context.Background(), id); err != nil {
		t.Fatalf("DeleteRoleTemplate: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the deletion was not mirrored: %v", err)
	}
}

// A FAILED REGISTRY WRITE TOUCHES IDENTITY NOT AT ALL.
//
// THIS PROPERTY INVERTED IN #1057, with the order it describes. It used to read
// "a failed SOURCE write mirrors nothing", which was the right property while
// identity was written first and registry's table was derived from it. Now
// registry's table is the authority: it is written first, and a failure there
// must return before identity is touched, so the two never diverge with
// registry behind.
//
// The mock carries the assertion — only the registry statement is staged, so any
// statement against identity's role_templates fails this test.
func TestRBACRepository_FailedRegistryWrite_TouchesIdentityNothing(t *testing.T) {
	repo, mock := newRBACRepo(t)

	registryErr := errors.New("refused")
	mock.ExpectExec("DELETE FROM registry_role_templates").WillReturnError(registryErr)

	err := repo.DeleteRoleTemplate(context.Background(), uuid.MustParse(testRoleID))
	if err == nil {
		t.Fatal("DeleteRoleTemplate = nil, want the registry error returned")
	}
	if !errors.Is(err, registryErr) {
		t.Errorf("error = %v, want it to wrap the registry error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("identity was written after the registry delete failed: %v", err)
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

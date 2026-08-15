package repositories

import (
	"context"
	"errors"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var orgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
var orgMemberCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}
var orgMembersWithUserCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}
var orgCreateCols = []string{"id", "created_at", "updated_at"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", "Default Org", nil, nil, time.Now(), time.Now())
}

func emptyOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols)
}

func sampleOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols).
		AddRow("org-1", "user-1", nil, time.Now())
}

func emptyOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols)
}

// ---------------------------------------------------------------------------
// Registry's own role tables (terraform-suite-identity#206, phase 3b)
// ---------------------------------------------------------------------------
//
// Every role-bearing accessor now issues a SECOND query, against registry's own
// organization_member_roles, immediately after the shared store's. The helpers
// below queue it.
//
// The role and scopes they carry MUST match the identity row queued just before,
// or the fixture stops testing the accessor and starts testing a divergence:
// the read path notices the disagreement, logs it at ERROR and increments
// registry_role_read_divergence_total, and the assertion above it silently
// changes meaning. Divergence has its own tests, in
// member_role_divergence_test.go, where it is the subject rather than an
// accident.

// registryRoleCols is MemberRoleReader.mirroredRoleColumns.
var registryRoleCols = []string{
	"role_template_id", "role_template_name", "role_template_display_name", "role_template_scopes",
}

// expectRegistryRoleFor queues the single-membership read (RoleFor). A nil
// scopes argument queues NO ROW, which is how "registry has no mirror for this
// membership" is expressed.
func expectRegistryRoleFor(mock sqlmock.Sqlmock, roleID string, scopes []byte) {
	rows := sqlmock.NewRows(registryRoleCols)
	if scopes != nil {
		rows.AddRow(nullableRole(roleID), "viewer", "Viewer", scopes)
	}
	mock.ExpectQuery(`(?s)FROM organization_member_roles omr.*WHERE omr\.organization_id = \$1 AND omr\.user_id = \$2`).
		WillReturnRows(rows)
}

// expectRegistryRolesForOrg queues the per-organization read (RolesForOrg),
// keyed by user id.
func expectRegistryRolesForOrg(mock sqlmock.Sqlmock, userID, roleID string, scopes []byte) {
	mock.ExpectQuery(`(?s)SELECT omr\.user_id,.*FROM organization_member_roles omr.*WHERE omr\.organization_id = \$1`).
		WillReturnRows(sqlmock.NewRows(append([]string{"user_id"}, registryRoleCols...)).
			AddRow(userID, nullableRole(roleID), "viewer", "Viewer", scopes))
}

// expectRegistryRolesForUser queues the per-user read (RolesForUser), keyed by
// organization id.
func expectRegistryRolesForUser(mock sqlmock.Sqlmock, orgID, roleID string, scopes []byte) {
	mock.ExpectQuery(`(?s)SELECT omr\.organization_id,.*FROM organization_member_roles omr.*WHERE omr\.user_id = \$1`).
		WillReturnRows(sqlmock.NewRows(append([]string{"organization_id"}, registryRoleCols...)).
			AddRow(orgID, nullableRole(roleID), "viewer", "Viewer", scopes))
}

// nullableRole renders an empty role id as SQL NULL, so a fixture can express a
// mirrored membership that carries no role.
func nullableRole(roleID string) interface{} {
	if roleID == "" {
		return nil
	}
	return roleID
}

func newOrgRepo(t *testing.T) (*OrganizationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOrganizationRepository(db), mock
}

func TestCascadeOrganizationRename_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("UPDATE providers SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE namespace_claims SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err != nil {
		t.Fatalf("CascadeOrganizationRename: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Issue #555 (regression): the module/provider namespace cascade must match rows
// by namespace ALONE, not by organization_id. Artifact rows are stamped with the
// default organization at publish time, not the namespace's true owner, so an
// `organization_id = orgID` predicate silently skips a renamed non-default org's
// artifacts -- leaving them pinned to the old namespace while the organization
// row and namespace_claims move, orphaning them from the read path. This asserts
// the modules/providers UPDATEs carry exactly (newName, oldName) and no org_id,
// while the namespace_claims UPDATE (whose rows DO carry the true org) still
// scopes by organization_id.
func TestCascadeOrganizationRename_MatchesArtifactsByNamespaceOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WithArgs("new", "old").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec("UPDATE providers SET namespace").
		WithArgs("new", "old").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("UPDATE namespace_claims SET namespace").
		WithArgs("new", "org-1", "old").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err != nil {
		t.Fatalf("CascadeOrganizationRename: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestCascadeOrganizationRename_ModulesError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err == nil {
		t.Error("expected error when the modules cascade fails, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestCascadeOrganizationRename_ProvidersError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE providers SET namespace").
		WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err == nil {
		t.Error("expected error when the providers cascade fails, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestCascadeOrganizationRename_ClaimsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE providers SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE namespace_claims SET namespace").
		WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err == nil {
		t.Error("expected error when the namespace-claims cascade fails, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestCascadeOrganizationRename_BeginError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin().WillReturnError(context.DeadlineExceeded)

	if err := CascadeOrganizationRename(context.Background(), db, "org-1", "old", "new"); err == nil {
		t.Error("expected error when begin fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetByName / GetDefaultOrganization
// ---------------------------------------------------------------------------

func TestGetByName_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetByName(context.Background(), "default", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
	if org.Name != "default" {
		t.Errorf("Name = %s, want default", org.Name)
	}
}

func TestGetByName_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())

	org, err := repo.GetByName(context.Background(), "missing", OrgScopeAllOrganizations())
	// identity v0.24.0 reports a miss with the store.ErrNotFound sentinel
	// instead of (nil, nil). Assert the SENTINEL, not merely a non-nil error:
	// a bare `err != nil` check would also pass for a real database failure,
	// which callers must not map to 404.
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if org != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestGetDefaultOrganization_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------------

func TestGetByID_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs("org-1").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetByID(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
}

func TestGetByID_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	org, err := repo.GetByID(context.Background(), "missing", OrgScopeAllOrganizations())
	// identity v0.24.0 reports a miss with the store.ErrNotFound sentinel
	// instead of (nil, nil). Assert the SENTINEL, not merely a non-nil error:
	// a bare `err != nil` check would also pass for a real database failure,
	// which callers must not map to 404.
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if org != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// Create (CreateOrganization)
// ---------------------------------------------------------------------------

func TestCreateOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", time.Now(), time.Now()))

	org := &models.Organization{Name: "new-org", DisplayName: "New Org"}
	if err := repo.Create(context.Background(), org); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org.ID != "org-new" {
		t.Errorf("ID = %s, want org-new", org.ID)
	}
}

func TestCreateOrganization_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnError(errDB)

	org := &models.Organization{Name: "new-org", DisplayName: "New Org"}
	if err := repo.Create(context.Background(), org); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestUpdateOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("UPDATE organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	org := &models.Organization{ID: "org-1", Name: "default", DisplayName: "Updated"}
	if err := repo.Update(context.Background(), org, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organizations").
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "org-1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List / Count / Search
// ---------------------------------------------------------------------------

func TestListOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY.*LIMIT").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.List(context.Background(), 20, 0, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

func TestCountOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.Count(context.Background(), OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestSearchOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE.*ILIKE").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.Search(context.Background(), "default", 20, 0, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// ---------------------------------------------------------------------------
// GetMember / AddMember / RemoveMember
// ---------------------------------------------------------------------------

func TestGetMember_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())
	expectRegistryRoleFor(mock, "", []byte(`[]`))

	m, err := repo.GetMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected member, got nil")
	}
}

func TestGetMember_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())

	m, err := repo.GetMember(context.Background(), "org-1", "user-2", OrgScopeAllOrganizations())
	// identity v0.24.0 reports a miss with the store.ErrNotFound sentinel
	// instead of (nil, nil). Assert the SENTINEL, not merely a non-nil error:
	// a bare `err != nil` check would also pass for a real database failure,
	// which callers must not map to 404.
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if m != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestRemoveMember_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListMembersWithUsers
// ---------------------------------------------------------------------------

func TestListMembersWithUsers_Empty(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols))

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("len(members) = %d, want 0", len(members))
	}
}

func TestListMembersWithUsers_WithMember(t *testing.T) {
	repo, mock := newOrgRepo(t)

	scopesJSON := []byte(`["admin:read"]`)
	rows := sqlmock.NewRows(orgMembersWithUserCols).
		AddRow("org-1", "user-1", nil, time.Now(), "Alice", "alice@example.com", nil, nil, scopesJSON)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(rows)
	expectRegistryRolesForOrg(mock, "user-1", "", scopesJSON)

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}
	if members[0].UserName != "Alice" {
		t.Errorf("UserName = %s, want Alice", members[0].UserName)
	}
}

// ---------------------------------------------------------------------------
// GetUserOrganizations
// ---------------------------------------------------------------------------

func TestGetUserOrganizations_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*JOIN organization_members").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.GetUserOrganizations(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberRoleTemplate
// ---------------------------------------------------------------------------

func TestUpdateMemberRoleTemplate_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateMemberRoleTemplate(context.Background(), "org-1", "user-1", nil,
		OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AddMemberWithRoleTemplate
// ---------------------------------------------------------------------------

func TestAddMemberWithRoleTemplate_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithRoleTemplate_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetMemberWithRole
// ---------------------------------------------------------------------------

var orgMemberWithRoleRepoCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email", "role_template_name", "role_template_display_name", "role_template_scopes",
}

func sampleMemberWithRoleRepoRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
		"org-1", "user-1", nil, time.Now(),
		"Alice", "alice@example.com",
		"viewer", "Viewer", []byte(`["modules:read"]`),
	)
}

func TestGetMemberWithRole_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols))

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	// identity v0.24.0 reports a miss with the store.ErrNotFound sentinel
	// instead of (nil, nil). Assert the SENTINEL, not merely a non-nil error:
	// a bare `err != nil` check would also pass for a real database failure,
	// which callers must not map to 404.
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestGetMemberWithRole_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sampleMemberWithRoleRepoRow())
	expectRegistryRoleFor(mock, "", []byte(`["modules:read"]`))

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected member, got nil")
	}
	if m.UserName != "Alice" {
		t.Errorf("user_name = %q, want Alice", m.UserName)
	}
}

// ---------------------------------------------------------------------------
// ListMembers
// ---------------------------------------------------------------------------

var orgMemberRepoCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}

func TestListMembers_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols).
			AddRow("org-1", "user-1", nil, time.Now()))
	expectRegistryRolesForOrg(mock, "user-1", "", []byte(`[]`))

	members, err := repo.ListMembers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}
}

func TestListMembers_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnError(errDB)

	_, err := repo.ListMembers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// AddMemberWithParams
// ---------------------------------------------------------------------------

func TestAddMemberWithParams_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	// Lookup role template by name
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("viewer").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))
	// Insert org member
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAddMemberWithParams_TemplateNotFound: as of terraform-suite-identity
// v0.17.0, an unresolvable role template name is a hard error rather than a
// silent fallback to a nil (no-scopes) role template id — the caller
// explicitly named a role, so an unknown name must not be silently dropped.
func TestAddMemberWithParams_TemplateNotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "nonexistent", OrgScopeAllOrganizations()); err == nil {
		t.Fatal("expected an error for an unknown role template, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls (should not have inserted): %v", err)
	}
}

func TestAddMemberWithParams_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer", OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberRole
// ---------------------------------------------------------------------------

func TestUpdateMemberRole_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-2"))
	mock.ExpectExec("UPDATE organization_members SET role_template_id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateMemberRole_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin", OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error")
	}
}

func TestUpdateMemberRole_TemplateNotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	// An unresolved role name must error rather than silently updating to a
	// nil roleTemplateID.
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "nonexistent", OrgScopeAllOrganizations()); err == nil {
		t.Fatal("expected an error for an unknown role template, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls (should not have updated): %v", err)
	}
}

// ---------------------------------------------------------------------------
// CheckMembership
// ---------------------------------------------------------------------------

func TestCheckMembership_NotMember(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols))

	isMember, roleID, err := repo.CheckMembership(context.Background(), "org-1", "user-99", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isMember {
		t.Error("expected not a member")
	}
	if roleID != nil {
		t.Error("expected nil roleID")
	}
}

func TestCheckMembership_IsMember(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols).AddRow("org-1", "user-1", nil, time.Now()))
	expectRegistryRoleFor(mock, "", []byte(`[]`))

	isMember, _, err := repo.CheckMembership(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isMember {
		t.Error("expected member")
	}
}

// ---------------------------------------------------------------------------
// GetUserOrganizations, error axis. The ListUserOrganizations alias this
// section used to exercise separately was deleted in identity v0.25.0; the
// happy path is covered once, above.
// ---------------------------------------------------------------------------

func TestGetUserOrganizations_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*organization_members").
		WillReturnError(errDB)

	_, err := repo.GetUserOrganizations(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetUserMemberships
// ---------------------------------------------------------------------------

var userMembershipCols = []string{
	"organization_id", "organization_name",
	"role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func TestGetUserMemberships_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).AddRow(
			"org-1", "default", nil, time.Now(),
			"viewer", "Viewer", []byte(`["modules:read"]`),
		))
	expectRegistryRolesForUser(mock, "org-1", "", []byte(`["modules:read"]`))

	memberships, err := repo.GetUserMemberships(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(memberships) != 1 {
		t.Errorf("len = %d, want 1", len(memberships))
	}
	if memberships[0].OrganizationName != "default" {
		t.Errorf("org name = %q, want default", memberships[0].OrganizationName)
	}
}

func TestGetUserMemberships_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnError(errDB)

	_, err := repo.GetUserMemberships(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetUserCombinedScopes
// ---------------------------------------------------------------------------

func TestGetUserCombinedScopes_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).AddRow(
			"org-1", "default", nil, time.Now(),
			"viewer", "Viewer", []byte(`["modules:read","modules:write"]`),
		))
	expectRegistryRolesForUser(mock, "org-1", "", []byte(`["modules:read","modules:write"]`))

	scopes, err := repo.GetUserCombinedScopes(context.Background(), "user-1") //nolint:staticcheck // SA1019: unit test for the deprecated-but-retained method itself
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) == 0 {
		t.Error("expected scopes, got empty")
	}
}

func TestGetUserCombinedScopes_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnError(errDB)

	_, err := repo.GetUserCombinedScopes(context.Background(), "user-1") //nolint:staticcheck // SA1019: unit test for the deprecated-but-retained method itself
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetDefaultOrganization cache hit path
// ---------------------------------------------------------------------------

func TestGetDefaultOrganization_CacheHit(t *testing.T) {
	repo, mock := newOrgRepo(t)

	// First call hits the DB and populates the cache.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org1, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}
	if org1 == nil {
		t.Fatal("first call: expected org, got nil")
	}

	// Second call should return from cache — no new DB query expected.
	org2, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("second call unexpected error: %v", err)
	}
	if org2 == nil {
		t.Fatal("second call: expected org, got nil")
	}
	if org1.ID != org2.ID {
		t.Errorf("cache returned different ID: %q vs %q", org1.ID, org2.ID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (extra DB query occurred): %v", err)
	}
}

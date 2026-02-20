package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var orgCols = []string{"id", "name", "display_name", "created_at", "updated_at"}
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
		AddRow("org-1", "default", "Default Org", time.Now(), time.Now())
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

func newOrgRepo(t *testing.T) (*OrganizationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOrganizationRepository(db), mock
}

// ---------------------------------------------------------------------------
// GetByName / GetDefaultOrganization
// ---------------------------------------------------------------------------

func TestGetByName_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetByName(context.Background(), "default")
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

	org, err := repo.GetByName(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	org, err := repo.GetByID(context.Background(), "org-1")
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

	org, err := repo.GetByID(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	if err := repo.Update(context.Background(), org); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organizations").
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "org-1"); err != nil {
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

	orgs, err := repo.List(context.Background(), 20, 0)
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

	count, err := repo.Count(context.Background())
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

	orgs, err := repo.Search(context.Background(), "default", 20, 0)
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

	m, err := repo.GetMember(context.Background(), "org-1", "user-1")
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

	m, err := repo.GetMember(context.Background(), "org-1", "user-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestAddMember_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	member := &models.OrganizationMember{
		OrganizationID: "org-1",
		UserID:         "user-2",
		CreatedAt:      time.Now(),
	}
	if err := repo.AddMember(context.Background(), member); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoveMember_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RemoveMember(context.Background(), "org-1", "user-1"); err != nil {
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

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1")
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

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1")
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
// GetUserOrganizations / ListUserOrganizations
// ---------------------------------------------------------------------------

func TestGetUserOrganizations_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*JOIN organization_members").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.GetUserOrganizations(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// ---------------------------------------------------------------------------
// UpdateMember
// ---------------------------------------------------------------------------

func TestUpdateMember_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	member := &models.OrganizationMember{
		OrganizationID: "org-1",
		UserID:         "user-1",
	}
	if err := repo.UpdateMember(context.Background(), member); err != nil {
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

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithRoleTemplate_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil)
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

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestGetMemberWithRole_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sampleMemberWithRoleRepoRow())

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1")
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

	members, err := repo.ListMembers(context.Background(), "org-1")
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

	_, err := repo.ListMembers(context.Background(), "org-1")
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

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithParams_TemplateNotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	// Template not found - should still insert with nil roleTemplateID
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "nonexistent"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithParams_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer"); err == nil {
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

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateMemberRole_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin"); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// CheckMembership
// ---------------------------------------------------------------------------

func TestCheckMembership_NotMember(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols))

	isMember, roleID, err := repo.CheckMembership(context.Background(), "org-1", "user-99")
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

	isMember, _, err := repo.CheckMembership(context.Background(), "org-1", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isMember {
		t.Error("expected member")
	}
}

// ---------------------------------------------------------------------------
// ListUserOrganizations (alias for GetUserOrganizations)
// ---------------------------------------------------------------------------

var userOrgCols = []string{"id", "name", "display_name", "created_at", "updated_at"}

func TestListUserOrganizations_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*organization_members").
		WillReturnRows(sqlmock.NewRows(userOrgCols).AddRow("org-1", "default", "Default Org", time.Now(), time.Now()))

	orgs, err := repo.ListUserOrganizations(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len = %d, want 1", len(orgs))
	}
}

func TestListUserOrganizations_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*organization_members").
		WillReturnError(errDB)

	_, err := repo.ListUserOrganizations(context.Background(), "user-1")
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

	scopes, err := repo.GetUserCombinedScopes(context.Background(), "user-1")
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

	_, err := repo.GetUserCombinedScopes(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error")
	}
}

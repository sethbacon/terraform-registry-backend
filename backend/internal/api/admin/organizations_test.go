package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Column definitions for organization SQL mocks
// ---------------------------------------------------------------------------

// orgCols is already defined in providers_test.go (same package), so reuse it.

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

func emptyMembersWithUsersRows() *sqlmock.Rows {
	return sqlmock.NewRows(orgMembersWithUserCols)
}

func sampleOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols).
		AddRow("org-1", "user-1", nil, time.Now())
}

func emptyOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newOrgRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewOrganizationHandlers(&config.Config{}, db)

	r := gin.New()
	r.GET("/organizations", h.ListOrganizationsHandler())
	r.GET("/organizations/search", h.SearchOrganizationsHandler())
	r.GET("/organizations/:id", h.GetOrganizationHandler())
	r.POST("/organizations", h.CreateOrganizationHandler())
	r.PUT("/organizations/:id", h.UpdateOrganizationHandler())
	r.DELETE("/organizations/:id", h.DeleteOrganizationHandler())
	r.GET("/organizations/:id/members", h.ListMembersHandler())
	r.POST("/organizations/:id/members", h.AddMemberHandler())
	r.PUT("/organizations/:id/members/:user_id", h.UpdateMemberHandler())
	r.DELETE("/organizations/:id/members/:user_id", h.RemoveMemberHandler())
	return mock, r
}

// ---------------------------------------------------------------------------
// ListOrganizationsHandler tests
// ---------------------------------------------------------------------------

func TestListOrganizations_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["organizations"] == nil {
		t.Error("response missing 'organizations' key")
	}
}

func TestListOrganizations_DBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetOrganizationHandler tests
// ---------------------------------------------------------------------------

func TestGetOrganization_NotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetOrganization_DBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetOrganization_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// ListMembersWithUsers returns empty
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(emptyMembersWithUsersRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["organization"] == nil {
		t.Error("response missing 'organization' key")
	}
}

// ---------------------------------------------------------------------------
// CreateOrganizationHandler tests
// ---------------------------------------------------------------------------

func TestCreateOrganization_InvalidJSON(t *testing.T) {
	_, r := newOrgRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{}))) // missing required fields

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateOrganization_Conflict(t *testing.T) {
	mock, r := newOrgRouter(t)

	// GetByName finds existing
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sampleOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "default", "display_name": "Default"})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestCreateOrganization_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	// GetByName returns not found
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())
	// Create (INSERT RETURNING)
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "new-org", "display_name": "New Org"})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateOrganizationHandler tests
// ---------------------------------------------------------------------------

func TestUpdateOrganization_NotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	displayName := "Updated"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"display_name": &displayName})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateOrganization_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectExec("UPDATE organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	displayName := "Updated Display"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"display_name": &displayName})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteOrganizationHandler tests
// ---------------------------------------------------------------------------

func TestDeleteOrganization_NotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteOrganization_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectExec("DELETE FROM organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListMembersHandler tests
// ---------------------------------------------------------------------------

func TestListMembers_OrgNotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1/members", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListMembers_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(emptyMembersWithUsersRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1/members", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// AddMemberHandler tests
// ---------------------------------------------------------------------------

func TestAddMember_InvalidJSON(t *testing.T) {
	_, r := newOrgRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{}))) // missing required user_id

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAddMember_OrgNotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAddMember_AlreadyMember(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetMember finds existing
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-1"})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestAddMember_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetMember finds no existing member
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())
	// AddMember
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// GetMemberWithRole will get an unexpected query error → handler returns basic member info (201)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RemoveMemberHandler tests
// ---------------------------------------------------------------------------

func TestRemoveMember_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SearchOrganizationsHandler tests
// ---------------------------------------------------------------------------

func TestSearchOrganizations_MissingQuery(t *testing.T) {
	_, r := newOrgRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSearchOrganizations_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WillReturnRows(sampleOrgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=default", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberHandler tests
// ---------------------------------------------------------------------------

var orgMemberWithRoleCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func sampleMemberWithRoleRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberWithRoleCols).AddRow(
		"org-1", "user-1", nil, time.Now(),
		"Alice", "alice@example.com",
		"viewer", "Viewer", []byte(`["modules:read"]`),
	)
}

func TestUpdateMember_InvalidJSON(t *testing.T) {
	_, r := newOrgRouter(t)
	w := httptest.NewRecorder()
	// Send completely invalid JSON
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString("not-json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateMember_MemberNotFound(t *testing.T) {
	mock, r := newOrgRouter(t)
	// GetMember returns no rows → member == nil → 404
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())

	body := `{"role_template_id": null}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateMember_GetMemberDBError(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnError(errDB)

	body := `{"role_template_id": null}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateMember_UpdateDBError(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())
	// UpdateMember → UpdateMemberRoleTemplate → ExecContext
	mock.ExpectExec("UPDATE organization_members").
		WillReturnError(errDB)

	body := `{"role_template_id": null}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateMember_Success(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// GetMemberWithRole returns member with role info
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())

	body := `{"role_template_id": null}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
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

// sampleOrgMemberRowWithRole returns a member row already assigned roleTemplateID,
// used to exercise the "changing away from a role template" revocation path.
func sampleOrgMemberRowWithRole(roleTemplateID string) *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols).
		AddRow("org-1", "user-1", roleTemplateID, time.Now())
}

func emptyOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newOrgRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newOrgRouterWithRevocation(t, false)
}

// newOrgRouterWithRevocation builds the same router as newOrgRouter but, when
// withRevocation is true, also wires a UserTokenRevocationRepository over the
// same mocked connection, so tests can assert on the revocation calls
// described in issue #559 finding [9].
func newOrgRouterWithRevocation(t *testing.T, withRevocation bool) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	var userRevocations *repositories.UserTokenRevocationRepository
	if withRevocation {
		userRevocations = repositories.NewUserTokenRevocationRepository(db)
	}

	h := NewOrganizationHandlers(&config.Config{}, db, repositories.NewNamespaceClaimRepository(db), userRevocations)

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
	r.GET("/admin/namespaces", h.ListNamespaceClaimsHandler())
	r.GET("/admin/namespaces/:namespace", h.GetNamespaceOwnershipHandler())
	return mock, r
}

// ---------------------------------------------------------------------------
// Namespace ownership read API tests (GET /admin/namespaces[/:namespace])
// ---------------------------------------------------------------------------

func nsClaimRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"})
}

func TestListNamespaceClaims_Success(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims.*ORDER BY").
		WillReturnRows(nsClaimRows().
			AddRow("aceo", "org-a", nil, time.Now()).
			AddRow("azure", "org-a", nil, time.Now()))
	// Both claims share org-a: the org name is resolved once and then cached.
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(orgCols).
			AddRow("org-a", "aceo", "ACEO", nil, nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/namespaces", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	nsList, ok := resp["namespaces"].([]interface{})
	if !ok || len(nsList) != 2 {
		t.Fatalf("expected 2 namespaces, got %v", resp["namespaces"])
	}
	first := nsList[0].(map[string]interface{})
	if first["organization_name"] != "aceo" {
		t.Errorf("organization_name = %v, want aceo", first["organization_name"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations (org name should be cached — a single GetByID): %v", err)
	}
}

func TestGetNamespaceOwnership_Claim(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims.*WHERE namespace").
		WillReturnRows(nsClaimRows().AddRow("aceo", "org-a", nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(orgCols).
			AddRow("org-a", "aceo", "ACEO", nil, nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/namespaces/aceo", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["source"] != "claim" {
		t.Errorf("source = %v, want claim", resp["source"])
	}
	if resp["organization_id"] != "org-a" {
		t.Errorf("organization_id = %v, want org-a", resp["organization_id"])
	}
	if resp["organization_name"] != "aceo" {
		t.Errorf("organization_name = %v, want aceo", resp["organization_name"])
	}
}

func TestGetNamespaceOwnership_ArtifactFallback(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims.*WHERE namespace").
		WillReturnRows(nsClaimRows()) // no claim row
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-b"))
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(orgCols).
			AddRow("org-b", "legacy", "Legacy", nil, nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/namespaces/legacyns", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["source"] != "artifact" {
		t.Errorf("source = %v, want artifact", resp["source"])
	}
	if resp["organization_id"] != "org-b" {
		t.Errorf("organization_id = %v, want org-b", resp["organization_id"])
	}
}

func TestGetNamespaceOwnership_Unclaimed_NotFound(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims.*WHERE namespace").
		WillReturnRows(nsClaimRows()) // no claim
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"})) // no artifacts

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/namespaces/ghost", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (unclaimed, no artifacts): body=%s", w.Code, w.Body.String())
	}
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
	// newOrgRouter's plain requests carry no user_id in context, so the
	// creator-membership branch below is never reached -- no further
	// expectations are queued, and ExpectationsWereMet (implicitly checked by
	// t.Cleanup(db.Close) not being relied upon here) would fail if it were.
}

// newCreateOrgRouterWithUser builds a router with only POST /organizations
// registered, injecting user_id into context first -- exercises the
// "creator is auto-added as org_owner" branch of CreateOrganizationHandler
// (issue #648), which newOrgRouter's unauthenticated requests never reach.
func newCreateOrgRouterWithUser(t *testing.T, userID string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewOrganizationHandlers(&config.Config{}, db, repositories.NewNamespaceClaimRepository(db), nil)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", userID) })
	r.POST("/organizations", h.CreateOrganizationHandler())
	return mock, r
}

// TestCreateOrganizationHandler_GrantsOrgOwnerNotAdmin is a regression test
// for issue #648: the creator of a new organization must be auto-added as
// org_owner, never as the platform-wide admin role template.
func TestCreateOrganizationHandler_GrantsOrgOwnerNotAdmin(t *testing.T) {
	mock, r := newCreateOrgRouterWithUser(t, "creator-1")

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", time.Now(), time.Now()))
	// AddMemberWithParams looks up the role template by name -- asserting
	// WithArgs("org_owner") means a regression back to granting "admin" would
	// leave this expectation unmatched, surfacing as a 500 below rather than
	// a silent false pass.
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("org_owner").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-org-owner"))
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "new-org", "display_name": "New Org"})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations (creator must be added as org_owner): %v", err)
	}
}

// TestCreateOrganizationHandler_AddMemberError_Returns500 is a regression
// test for issue #648: a failure while adding the creator as a member must be
// reported to the caller, not silently swallowed (which would leave the
// creator without any membership in the org they just created).
func TestCreateOrganizationHandler_AddMemberError_Returns500(t *testing.T) {
	mock, r := newCreateOrgRouterWithUser(t, "creator-2")

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", time.Now(), time.Now()))
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("org_owner").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "new-org", "display_name": "New Org"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (membership failure must not be swallowed): body=%s", w.Code, w.Body.String())
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
// Rename tests
// ---------------------------------------------------------------------------

func TestUpdateOrganization_RenameSuccess(t *testing.T) {
	mock, r := newOrgRouter(t)

	// 1. GetByID — return current org (name = "default")
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// 2. GetByName uniqueness check — new name is available
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnRows(emptyOrgRow())
	// 3. Rename (identity) — single UPDATE, no transaction
	mock.ExpectExec("UPDATE organizations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// 4. Cascade to denormalized module/provider namespaces and namespace
	//    ownership claims (domain) — own transaction
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE modules SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE providers SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE namespace_claims SET namespace").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	// 5. Regular Update for remaining fields (display_name / idp_type)
	mock.ExpectExec("UPDATE organizations SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	newName := "new-org-name"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"name": &newName})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateOrganization_RenameConflict(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetByName — name already taken
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnRows(sampleOrgRow())

	taken := "already-taken"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"name": &taken})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateOrganization_RenameInvalidFormat(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())

	// Name with spaces and uppercase — fails ValidateRegistrySegment before any DB call
	badName := "My Bad Name!"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"name": &badName})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateOrganization_RenameSameName(t *testing.T) {
	// Sending the same name as current should be a no-op (no cascade, no conflict check)
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// No rename branch runs; only the regular Update executes
	mock.ExpectExec("UPDATE organizations SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	sameName := "default" // matches sampleOrgRow name
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"name": &sameName})))

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
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("DELETE FROM organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// An organization that still owns namespace claims must not be deletable:
// deleting it would cascade the claim away and let resolveOwnerOrg's
// artifact-row fallback silently re-attribute the namespace to whichever
// (unrelated) organization the mistagged rows point at (#555 review finding).
func TestDeleteOrganization_BlockedByNamespaceClaims(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteOrganization_ClaimCountDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// A namespace whose artifacts already span more than one organization is
// deliberately left unclaimed (ambiguous ownership, admin-only at runtime),
// so the namespace_claims count is 0 for it even though this organization
// still owns rows there directly. Deleting the organization must still be
// blocked, or the shared namespace collapses from ambiguous to unchecked sole
// ownership by whichever organization's rows survive the cascade (#555
// review finding).
func TestDeleteOrganization_BlockedByArtifactOwnership(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteOrganization_ArtifactOwnershipDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
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

// Issue #559 finding [9]: removing a member must revoke their outstanding
// tokens so the removal takes effect immediately rather than waiting out the
// JWT TTL.
func TestRemoveMember_RevokesUserTokens(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)

	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("revocation was not issued: %v", err)
	}
}

// A failed revocation must not turn an otherwise-successful removal into an
// error response — the member removal has already been committed, and the
// revocation failure is logged rather than surfaced (see revokeUserTokens).
func TestRemoveMember_RevocationErrorDoesNotFailRequest(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)

	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 even though revocation failed: body=%s", w.Code, w.Body.String())
	}
}

// captureSlogOutput temporarily redirects the default slog logger to a
// buffer, restoring it on cleanup. Some failure paths in these handlers are
// deliberately best-effort (logged, not surfaced as an error response), so a
// test that only checks the HTTP response cannot tell "no attempt was made"
// apart from "an attempt was made and its error was swallowed" -- sqlmock's
// ExpectationsWereMet only fails on missing expected calls, not on extra,
// unexpected ones, so an accidentally-unconditional call that happens to fail
// would otherwise pass silently. Capturing the log output closes that gap.
func captureSlogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return &buf
}

// Removing a user who was never a member of this org must not revoke their
// tokens: RemoveMember is a plain DELETE with no rows-affected signal, so
// without the membership pre-check an org admin could log out an arbitrary
// user org-wide by targeting a removal that changes nothing. Asserting only
// on the HTTP response and mock.ExpectationsWereMet() isn't enough to prove
// this: if the wasMember guard were accidentally removed, revokeUserTokens
// would still be called, sqlmock would reject the unregistered INSERT and
// return an error to it, and revokeUserTokens swallows that error via
// slog.Error without failing the request -- so this also asserts no such
// log line was emitted, which does distinguish "never attempted" from
// "attempted and silently failed".
func TestRemoveMember_NotAMember_SkipsRevocation(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)
	logs := captureSlogOutput(t)

	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 0))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected extra calls (revocation should have been skipped): %v", err)
	}
	if strings.Contains(logs.String(), "revoke") {
		t.Errorf("a revocation was attempted even though the removed user was never a member; logs: %s", logs.String())
	}
}

// A failed membership check must not block the removal itself (that lookup
// only feeds the revocation decision, not RemoveMember), but must surface
// that the revocation sweep may not have happened rather than returning an
// identical response to the fully-successful case.
func TestRemoveMember_MembershipCheckDBError_StillRemovesButFlagsIncomplete(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)
	logs := captureSlogOutput(t)

	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnError(errDB)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even though the membership check failed: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected extra calls (no confirmed membership means no revocation attempt): %v", err)
	}
	var body struct {
		RevocationIncomplete bool `json:"revocation_incomplete"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v: body=%s", err, w.Body.String())
	}
	if !body.RevocationIncomplete {
		t.Errorf("expected revocation_incomplete=true in the response, got body=%s", w.Body.String())
	}
	if !strings.Contains(logs.String(), "failed to check organization membership") {
		t.Errorf("expected the membership-check failure to be logged; logs: %s", logs.String())
	}
}

// When revocation isn't wired up at all (nil, as in most tests and any
// deployment that hasn't configured it), the membership pre-check must be
// skipped entirely rather than run for no reason.
func TestRemoveMember_NoRevocationWired_SkipsMembershipLookup(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected membership lookup ran with no revocation wired: %v", err)
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

const (
	oldRoleTemplateUUID = "11111111-1111-1111-1111-111111111111"
	newRoleTemplateUUID = "33333333-3333-3333-3333-333333333333"
)

// Issue #559 finding [9]: reassigning a member's role template must revoke
// their outstanding tokens so the new scopes (or lack thereof) take effect
// immediately rather than waiting out the JWT TTL.
func TestUpdateMember_RoleTemplateChanged_RevokesUserTokens(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)
	// checkRoleAssignment looks up the target role template's scopes first.
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`[]`)))
	// Member currently holds oldRoleTemplateUUID; the request reassigns to
	// newRoleTemplateUUID — a real change that must trigger revocation.
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRowWithRole(oldRoleTemplateUUID))
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())

	body := `{"role_template_id": "` + newRoleTemplateUUID + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("revocation was not issued: %v", err)
	}
}

// Reassigning a member to the SAME role template they already hold is a no-op
// for effective scopes, so no revocation should be issued — asserted by NOT
// registering a revocation expectation: sqlmock fails the test if the handler
// tries to run an unexpected exec.
func TestUpdateMember_RoleTemplateUnchanged_SkipsRevocation(t *testing.T) {
	mock, r := newOrgRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`[]`)))
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRowWithRole(oldRoleTemplateUUID))
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())

	body := `{"role_template_id": "` + oldRoleTemplateUUID + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected mock call: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for UpdateOrganizationHandler
// ---------------------------------------------------------------------------

func TestUpdateOrganization_InvalidJSON(t *testing.T) {
	_, r := newOrgRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		bytes.NewBufferString("not-json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateOrganization_GetByIDDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"display_name": "Updated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateOrganization_UpdateDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectExec("UPDATE organizations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1",
		jsonBody(map[string]interface{}{"display_name": "Updated"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for DeleteOrganizationHandler
// ---------------------------------------------------------------------------

func TestDeleteOrganization_GetByIDDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeleteOrganization_DeleteDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("DELETE FROM organizations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for ListOrganizationsHandler
// ---------------------------------------------------------------------------

func TestListOrganizations_CountDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	// List succeeds
	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").
		WillReturnRows(sampleOrgRow())
	// Count fails
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListOrganizations_PaginationDefaults(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// page < 1 and per_page > 100 should be clamped to defaults
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations?page=0&per_page=200", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListOrganizations_NegativePerPage(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY").
		WillReturnRows(sampleOrgRow())
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// per_page < 1 should be reset to 20
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations?per_page=-5", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for AddMemberHandler
// ---------------------------------------------------------------------------

func TestAddMember_GetByIDDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAddMember_GetMemberDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetMember returns error
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAddMember_AddMemberDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetMember finds no existing member
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())
	// AddMember fails
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAddMember_SuccessWithRole(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// GetMember finds no existing member
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())
	// AddMember
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// GetMemberWithRole succeeds
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberWithRoleRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations/org-1/members",
		jsonBody(map[string]string{"user_id": "user-2"})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["member"] == nil {
		t.Error("response missing 'member' key")
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for RemoveMemberHandler
// ---------------------------------------------------------------------------

func TestRemoveMember_DBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for SearchOrganizationsHandler
// ---------------------------------------------------------------------------

func TestSearchOrganizations_DBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=test", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSearchOrganizations_PaginationDefaults(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WillReturnRows(sampleOrgRow())

	// page < 1 and per_page > 100 should be clamped to defaults
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=test&page=0&per_page=200", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestSearchOrganizations_NegativePerPage(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations").
		WillReturnRows(sampleOrgRow())

	// per_page < 1 should be reset to 20
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/search?q=test&per_page=-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for ListMembersHandler
// ---------------------------------------------------------------------------

func TestListMembers_GetByIDDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1/members", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListMembers_ListMembersWithUsersDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sampleOrgRow())
	// ListMembersWithUsers fails
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/org-1/members", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests for UpdateMemberHandler
// ---------------------------------------------------------------------------

func TestUpdateMember_GetMemberWithRoleDBError(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// GetMemberWithRole fails - handler should return basic member info (200)
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnError(errDB)

	body := `{"role_template_id": null}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["member"] == nil {
		t.Error("response missing 'member' key")
	}
}

// ---------------------------------------------------------------------------
// CreateOrganizationHandler — missing error paths
// ---------------------------------------------------------------------------

func TestCreateOrganization_CreateDBError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "new-org", "display_name": "New Org"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestCreateOrganization_ExistenceCheckError(t *testing.T) {
	mock, r := newOrgRouter(t)

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnError(errDB)

	req := httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "new-org", "display_name": "New Org"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

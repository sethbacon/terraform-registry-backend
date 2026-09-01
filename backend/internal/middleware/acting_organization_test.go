package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	idtenantscope "github.com/sethbacon/terraform-suite-identity/identity/tenantscope"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

var organizationColsMW = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}

// withActingOrg sends the suite organization picker's header (issue #437).
func withActingOrg(req *http.Request, orgID string) *http.Request {
	req.Header.Set(idtenantscope.ActingOrganizationHeader, orgID)
	return req
}

// expectOrganizationExists primes the existence check resolveCallerOrg makes on
// a platform admin's explicit organization.
func expectOrganizationExists(mock sqlmock.Sqlmock, orgID string) {
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows(organizationColsMW).
			AddRow(orgID, "org", "Org", nil, nil, time.Now(), time.Now()))
}

func expectOrganizationMissing(mock sqlmock.Sqlmock, orgID string) {
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows(organizationColsMW))
}

func expectUnclaimedNamespace(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols)) // unclaimed
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols)) // no artifacts
}

// expectMembershipsAB primes GetUserMemberships (and the registry-side role
// read that follows it) with modules:write in both organizations.
func expectMembershipsAB(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).
			AddRow(nsOrgA, "Org A", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`)).
			AddRow(nsOrgB, "Org B", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`)))
	expectRegistryRolesForUser(mock,
		registryRoleForOrg{OrganizationID: nsOrgA, RoleTemplateID: "role-pub",
			Name: "publisher", DisplayName: "Publisher", Scopes: []byte(`["modules:write"]`)},
		registryRoleForOrg{OrganizationID: nsOrgB, RoleTemplateID: "role-pub",
			Name: "publisher", DisplayName: "Publisher", Scopes: []byte(`["modules:write"]`)})
}

// expectClaimFor primes the claim insert for org, the re-read, and the
// unconditional post-claim authority check in that org.
func expectClaimFor(mock sqlmock.Sqlmock, org string) {
	mock.ExpectExec("INSERT INTO namespace_claims").
		WithArgs("newteam", org, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("newteam", org, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(memberRow(org, nsUserID, `["modules:write"]`))
	expectMirroredMemberRole(mock, `["modules:write"]`)
}

func formPublishRoute(authz *NamespaceAuthorizer, principal func(c *gin.Context)) *gin.Engine {
	r := gin.New()
	r.POST("/modules",
		contextSetter(principal),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"owner": c.GetString("owner_org_id")}) })
	return r
}

// A platform admin with no form field names the organization through the
// picker's header; it is verified to exist and the claim binds to it.
func TestRequirePublishAccessFromForm_AdminHeaderOrg_Claims(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	expectUnclaimedNamespace(mock)
	expectOrganizationExists(mock, nsOrgB)
	mock.ExpectExec("INSERT INTO namespace_claims").
		WithArgs("newteam", nsOrgB, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("newteam", nsOrgB, nil, time.Now()))

	r := formPublishRoute(authz, withScopesAndUser([]string{string(auth.ScopeAdmin)}, nsUserID))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(multipartRequest(t, map[string]string{"namespace": "newteam", "name": "vpc", "system": "aws"}), nsOrgB))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

// A platform admin naming an organization that does not exist is refused
// before any claim is written — the mistyped-id exposure #437 closes.
func TestRequirePublishAccessFromForm_AdminHeaderUnknownOrg_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	expectUnclaimedNamespace(mock)
	expectOrganizationMissing(mock, nsOrgB)

	r := formPublishRoute(authz, withScopesAndUser([]string{string(auth.ScopeAdmin)}, nsUserID))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(multipartRequest(t, map[string]string{"namespace": "newteam", "name": "vpc", "system": "aws"}), nsOrgB))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations (no claim insert expected): %v", err)
	}
}

// A member of two organizations picks one through the header on the JSON
// publish path; it goes through the same membership check as organization_id.
func TestRequirePublishAccessFromJSON_MemberHeaderOrg_Claims(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	expectUnclaimedNamespace(mock)
	expectMembershipsAB(mock)
	expectClaimFor(mock, nsOrgB)

	r := gin.New()
	r.POST("/admin/modules/create",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"owner": c.GetString("owner_org_id")}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(jsonRequest("/admin/modules/create", `{"namespace":"newteam","name":"vpc","system":"aws"}`), nsOrgB))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

// The form field is the more specific statement and wins over the header.
func TestRequirePublishAccessFromForm_BodyOrgWinsOverHeader(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	expectUnclaimedNamespace(mock)
	expectMembershipsAB(mock)
	expectClaimFor(mock, nsOrgA)

	r := formPublishRoute(authz, withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(multipartRequest(t, map[string]string{
		"namespace": "newteam", "name": "vpc", "system": "aws", "organization_id": nsOrgA,
	}), nsOrgB))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("claim must bind to the form's organization, not the header's: %v", err)
	}
}

// A header naming an organization the caller does not belong to is refused,
// exactly as an organization_id would be: the header is a transport, not an
// authority.
func TestRequirePublishAccessFromForm_HeaderOrg_NotMember_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	expectUnclaimedNamespace(mock)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).
			AddRow(nsOrgA, "Org A", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`)))
	expectRegistryRolesForUser(mock,
		registryRoleForOrg{OrganizationID: nsOrgA, RoleTemplateID: "role-pub",
			Name: "publisher", DisplayName: "Publisher", Scopes: []byte(`["modules:write"]`)})

	r := formPublishRoute(authz, withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(multipartRequest(t, map[string]string{"namespace": "newteam", "name": "vpc", "system": "aws"}), nsOrgB))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations (no claim insert expected): %v", err)
	}
}

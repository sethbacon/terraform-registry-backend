// role_ceiling_test.go tests checkRoleAssignment's per-organization privilege
// ceiling (issue #648): a caller's ability to assign a role must be derived
// from their own scopes WITHIN the target organization, not their flat/global
// scope union across every organization they belong to.
package admin

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// newRoleCeilingHandlers builds an OrganizationHandlers backed by db, with no
// claim/revocation repos -- checkRoleAssignment doesn't touch either.
func newRoleCeilingHandlers(db *sql.DB) *OrganizationHandlers {
	return &OrganizationHandlers{db: db, orgRepo: repositories.NewOrganizationRepository(db)}
}

// newRoleCeilingContext builds a gin.Context shaped the way checkRoleAssignment
// expects: c.Param("id") is the target org, c.Get("user_id")/c.Get("scopes")
// are the authenticated caller's identity and flat/global scopes.
func newRoleCeilingContext(targetOrgID, callerUserID string, globalScopes []string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPut, "/organizations/"+targetOrgID+"/members/"+callerUserID, nil)
	c.Params = gin.Params{{Key: "id", Value: targetOrgID}}
	c.Set("user_id", callerUserID)
	c.Set("scopes", globalScopes)
	return c
}

// TestCheckRoleAssignment_CrossOrgCallerCannotEscalate is the core regression
// test for issue #648: a caller whose flat/global scopes contain
// organizations:write (e.g. from membership in a DIFFERENT organization) must
// NOT be able to assign a role requiring that scope in an org they have no
// membership in.
func TestCheckRoleAssignment_CrossOrgCallerCannotEscalate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	h := newRoleCeilingHandlers(db)

	roleID := "11111111-1111-1111-1111-111111111111"
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`["organizations:write"]`)))
	// Caller has no membership row at all in the target org.
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols))

	c := newRoleCeilingContext("org-b", "caller-1", []string{"organizations:write"})
	chk := h.checkRoleAssignment(c, &roleID)

	if chk.allowed || chk.status != http.StatusForbidden {
		t.Fatalf("cross-org caller must not be allowed to assign this role: got %+v", chk)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

// TestCheckRoleAssignment_SameOrgSufficientScopeAllowed proves the fix does
// not break the legitimate case: a caller whose scopes IN THE TARGET org
// cover the role being assigned is still permitted.
func TestCheckRoleAssignment_SameOrgSufficientScopeAllowed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	h := newRoleCeilingHandlers(db)

	roleID := "22222222-2222-2222-2222-222222222222"
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`["modules:read"]`)))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).AddRow(
			"org-a", "caller-2", "role-1", time.Now(),
			"Caller Two", "caller2@example.com", "org_owner", "Organization Owner",
			[]byte(`["organizations:write","modules:read","modules:write"]`),
		))

	c := newRoleCeilingContext("org-a", "caller-2", nil)
	chk := h.checkRoleAssignment(c, &roleID)

	if !chk.allowed {
		t.Fatalf("same-org sufficient scope must be allowed: got %+v", chk)
	}
}

// TestCheckRoleAssignment_GlobalAdminBypassesPerOrgLookup proves a genuine
// global admin can still assign a role without a per-org membership row -- and,
// critically, without ever querying organization_members: no such expectation
// is queued, so a regression that still performed the per-org lookup would
// surface as an unmatched-query error (giving a 500 and chk.allowed == false),
// not a false pass.
//
// The role is NOT admin-bearing any more. It used to be, on the reasoning that
// "a global admin can assign any role, including another admin role"; migration
// 000054 removed that exception along with the rest of the wildcard's presence
// on role templates. See the test below.
func TestCheckRoleAssignment_GlobalAdminBypassesPerOrgLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	h := newRoleCeilingHandlers(db)

	roleID := "33333333-3333-3333-3333-333333333333"
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`["users:write","organizations:write"]`)))

	c := newRoleCeilingContext("org-c", "caller-3", []string{"admin"})
	chk := h.checkRoleAssignment(c, &roleID)

	if !chk.allowed {
		t.Fatalf("global admin must be allowed to assign a role within its authority: got %+v", chk)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations (admin bypass must skip the per-org DB lookup): %v", err)
	}
}

// TestCheckRoleAssignment_NobodyMayAssignAnAdminBearingTemplate is issue #766's
// recommendation at the unit level, and it applies to the platform
// administrator in particular: RoleScopesPermittedBy answers TRUE for a caller
// holding `admin`, so folding the refusal into the ceiling would have left this
// caller — the only one who could ever create the state PR #850 tolerated —
// able to do it.
//
// The refusal is asserted on its own message rather than on the status, because
// a 403 also comes out of the per-org ceiling and only one of the two holds
// here.
func TestCheckRoleAssignment_NobodyMayAssignAnAdminBearingTemplate(t *testing.T) {
	for _, caller := range []struct {
		name   string
		scopes []string
	}{
		{"platform administrator", []string{"admin"}},
		{"organization owner", []string{"organizations:write"}},
	} {
		t.Run(caller.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			h := newRoleCeilingHandlers(db)

			roleID := "44444444-4444-4444-4444-444444444444"
			// Only the template read is queued. The per-org ceiling lookup must
			// not happen: the answer does not depend on the caller.
			mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
				WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`["admin"]`)))

			c := newRoleCeilingContext("org-c", "caller-4", caller.scopes)
			chk := h.checkRoleAssignment(c, &roleID)

			if chk.allowed {
				t.Fatalf("%s was permitted to assign an admin-bearing template: %+v", caller.name, chk)
			}
			if chk.status != http.StatusForbidden {
				t.Errorf("status = %d, want 403", chk.status)
			}
			if chk.message != adminBearingRefusal {
				t.Errorf("message = %q, want the admin-bearing refusal naming the platform-admins route", chk.message)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet/unexpected expectations (the refusal must not need a per-org lookup): %v", err)
			}
		})
	}
}

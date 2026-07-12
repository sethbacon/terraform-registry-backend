package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// pathOrgRouter builds a gin router mounting mid on a route with an :id path
// parameter (mirroring the /organizations/:id* route shape), injecting scopes
// and user_id into context the way AuthMiddleware does before RequireScope /
// RequireOrgScopeForPathOrg run.
func pathOrgRouter(mid gin.HandlerFunc, scopes []string, userID string) *gin.Engine {
	r := gin.New()
	r.GET("/organizations/:id", func(c *gin.Context) {
		if scopes != nil {
			c.Set("scopes", scopes)
		}
		if userID != "" {
			c.Set("user_id", userID)
		}
	}, mid, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doGetPath(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestRequireOrgScopeForPathOrg_NoScopesInContext(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	w := doGetPath(pathOrgRouter(mid, nil, orgMWUserID), "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScopeForPathOrg_NoUserID(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	// Caller has organizations:write somewhere (flat scope), but no user_id in
	// context -- must not be treated as authorized.
	w := doGetPath(pathOrgRouter(mid, []string{"organizations:write"}, ""), "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireOrgScopeForPathOrg_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnError(orgMWErrDB)

	w := doGetPath(pathOrgRouter(mid, []string{"organizations:write"}, orgMWUserID), "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestRequireOrgScopeForPathOrg_CrossOrgRejected is the core regression test
// for GHSA-hc25-j576-cqm2: a caller who holds organizations:write only via
// membership in a DIFFERENT organization (org A) must be rejected when the
// path targets org B, even though their flat/global combined scope set
// (what RequireScope alone checks) contains organizations:write.
func TestRequireOrgScopeForPathOrg_CrossOrgRejected(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	// The caller's flat scopes (as RequireScope would have already approved)
	// include organizations:write, but GetUserScopesForOrg for org B returns no
	// membership row at all.
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW))

	w := doGetPath(pathOrgRouter(mid, []string{"organizations:write"}, orgMWUserID), "/organizations/org-B")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (cross-org write must be rejected): body=%s", w.Code, w.Body.String())
	}
}

// TestRequireOrgScopeForPathOrg_SameOrgAllowed proves the fix does not break
// the legitimate case: a caller whose organizations:write role assignment IS
// in the target org must still be allowed.
func TestRequireOrgScopeForPathOrg_SameOrgAllowed(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			orgMWOrgID, orgMWUserID, "role-1", time.Now(),
			"User Name", "user@test.com", "user_manager", "User Manager", []byte(`["organizations:write"]`),
		))

	w := doGetPath(pathOrgRouter(mid, []string{"organizations:write"}, orgMWUserID), "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (same-org write must be allowed): body=%s", w.Code, w.Body.String())
	}
}

// TestRequireOrgScopeForPathOrg_InsufficientOrgScope covers a member of the
// target org whose role there doesn't include the required scope (e.g. a
// viewer trying a write action) -- still rejected.
func TestRequireOrgScopeForPathOrg_InsufficientOrgScope(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			orgMWOrgID, orgMWUserID, "role-1", time.Now(),
			"User Name", "user@test.com", "viewer", "Viewer", []byte(`["organizations:read"]`),
		))

	w := doGetPath(pathOrgRouter(mid, []string{"organizations:write"}, orgMWUserID), "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// TestRequireOrgScopeForPathOrg_GlobalAdminBypassesPerOrgCheck proves the
// platform-wide "admin" wildcard scope (granted via the system "admin" role
// template, see docs/adr/001-scope-based-rbac.md) still works across every
// organization regardless of membership there -- no DB lookup should even
// happen for this caller.
func TestRequireOrgScopeForPathOrg_GlobalAdminBypassesPerOrgCheck(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	// No mock.ExpectQuery set up at all -- if the middleware queried the DB
	// for a per-org check, sqlmock would fail the test with an unexpected call.
	w := doGetPath(pathOrgRouter(mid, []string{"admin"}, orgMWUserID), "/organizations/some-other-org")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (global admin must bypass per-org check): body=%s", w.Code, w.Body.String())
	}
}

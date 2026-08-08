package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Fixtures for the RequireOrgScopeForPathOrg tests below.
//
// These lived in rbac_org_test.go, which was deleted along with the unwired
// RequireOrgMembership/RequireOrgScope middlewares (issue #748). This file is
// their only surviving consumer, so they move here rather than into a shared
// helpers file that would again serve exactly one caller.
var orgMWErrDB = errors.New("db error")

const (
	orgMWUserID = "user-111"
	orgMWOrgID  = "org-222"
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

// ---------------------------------------------------------------------------
// Organization axis of the credential-binding class (issue #733)
// ---------------------------------------------------------------------------
//
// The copy this middleware replaced re-derived authority from the caller's USER
// record alone. An API key is bound to exactly one organization at creation,
// and both siblings of this check -- NamespaceAuthorizer.authorizeOrgAccess and
// tenantscope.Resolve -- treat that binding as authoritative for the key; this
// one did not, so a key bound to org A could administer org B whenever its
// owner happened to be a member there. Delegating to authorizeOrgAccessWith is
// what makes the three answer identically.

// orgBoundKeyContext injects the context AuthMiddleware produces for an
// organization-bound API key.
func orgBoundKeyContext(keyOrgID string, scopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner := orgMWUserID
		c.Set("scopes", scopes)
		c.Set("user_id", orgMWUserID)
		c.Set("auth_method", "api_key")
		c.Set("organization_id", keyOrgID)
		c.Set("api_key", &models.APIKey{
			UserID: &owner, OrganizationID: keyOrgID, Scopes: scopes,
		})
	}
}

func TestRequireOrgScopeForPathOrg_KeyBoundToAnotherOrgRejected(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	// No membership lookup should be reached: the key's own binding already
	// answers the question, so sqlmock would fail on an unexpected query.
	_ = mock

	r := gin.New()
	r.GET("/organizations/:id",
		orgBoundKeyContext("org-A", []string{"organizations:write"}),
		mid,
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doGetPath(r, "/organizations/org-B")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (a key bound to org A must not act on org B): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireOrgScopeForPathOrg_KeyBoundToTargetOrgAllowed(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	orgRepo := repositories.NewOrganizationRepository(db)
	mid := RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo)

	// The key's owner is still a member of the bound org with the scope, which
	// is re-verified at the point of use (issue #732).
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			orgMWOrgID, orgMWUserID, "role-1", time.Now(),
			"User Name", "user@test.com", "user_manager", "User Manager", []byte(`["organizations:write"]`),
		))

	r := gin.New()
	r.GET("/organizations/:id",
		orgBoundKeyContext(orgMWOrgID, []string{"organizations:write"}),
		mid,
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doGetPath(r, "/organizations/"+orgMWOrgID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (a key acting on its own organization must still be allowed): body=%s", w.Code, w.Body.String())
	}
}

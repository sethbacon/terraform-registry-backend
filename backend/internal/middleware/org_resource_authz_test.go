package middleware

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

const resourceUUID = "33333333-3333-3333-3333-333333333333"

// resolverFor returns a ResourceOrgResolver with fixed behaviour, plus a
// pointer to a flag recording whether it was called.
func resolverFor(orgID string, found bool, err error) (ResourceOrgResolver, *bool) {
	called := false
	return func(context.Context, string) (string, bool, error) {
		called = true
		return orgID, found, err
	}, &called
}

// resourceRouter mounts the guard on GET /widgets/:id with a terminal handler
// that reports 200, so "reached the handler" is observable.
func resourceRouter(mid gin.HandlerFunc, scopes []string, userID string) *gin.Engine {
	r := gin.New()
	r.GET("/widgets/:id",
		contextSetter(withScopesAndUser(scopes, userID)),
		mid,
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return r
}

func TestRequireOrgScopeForResource_CrossOrg_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	// Caller is not a member of the owning org.
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW))

	resolve, called := resolverFor(nsOrgB, true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (resource owned by another org): body=%s", w.Code, w.Body.String())
	}
	if !*called {
		t.Error("resolver was not called")
	}
}

func TestRequireOrgScopeForResource_SameOrg_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-devops", time.Now(),
			"Dev", "dev@test.com", "devops", "DevOps", []byte(`["scm:manage"]`),
		))

	resolve, _ := resolverFor(nsOrgA, true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (member of owning org with the scope): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireOrgScopeForResource_MemberWithoutScopeInOwningOrg_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	// Member of the owning org, but their role there does not grant scm:manage.
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-viewer", time.Now(),
			"View", "view@test.com", "viewer", "Viewer", []byte(`["scm:read"]`),
		))

	resolve, _ := resolverFor(nsOrgA, true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (flat scope union must not substitute for the scope in the owning org)", w.Code)
	}
}

func TestRequireOrgScopeForResource_AdminWildcard_Allowed(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	// No DB expectation: admin must short-circuit before any membership lookup.
	resolve, _ := resolverFor(nsOrgB, true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeAdmin)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (admin wildcard crosses org boundaries by design)", w.Code)
	}
}

func TestRequireOrgScopeForResource_UnownedResource_DeniedForNonAdmin(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	// organization_id is nullable on these tables; an unowned row must fail
	// closed rather than being treated as "belongs to everyone".
	resolve, _ := resolverFor("", true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (unowned resource is admin-only)", w.Code)
	}
}

func TestRequireOrgScopeForResource_MissingResource_PassesThroughToHandler(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	resolve, _ := resolverFor("", false, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (missing resource left to the handler's 404)", w.Code)
	}
}

func TestRequireOrgScopeForResource_NotUUID_PassesThroughWithoutLookup(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	resolve, called := resolverFor(nsOrgB, true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/not-a-uuid")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (malformed ID left to the handler)", w.Code)
	}
	if *called {
		t.Error("resolver must not be called for a malformed ID")
	}
}

func TestRequireOrgScopeForResource_ResolverError_FailsClosed(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	resolve, _ := resolverFor("", false, errors.New("db down"))
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeSCMManage)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (lookup failure must not fall open)", w.Code)
	}
}

func TestRequireOrgScopeForResource_UnownedResource_AllowedForAdmin(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	// Counterpart to the test above: legacy unowned rows stay reachable by a
	// platform admin, so the fail-closed default is not a lockout.
	resolve, _ := resolverFor("", true, nil)
	r := resourceRouter(authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		[]string{string(auth.ScopeAdmin)}, nsUserID)

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (admin may act on an unowned resource)", w.Code)
	}
}

func TestRequireOrgScopeForResource_NoScopesInContext_Denied(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)
	resolve, _ := resolverFor(nsOrgA, true, nil)

	// Deliberately does NOT go through withScopesAndUser: that helper always
	// sets the "scopes" key, so passing nil would still exercise the
	// empty-slice path rather than the absent-key one this test is about.
	// No sqlmock expectation is registered either — denial must happen before
	// any database round trip.
	r := gin.New()
	r.GET("/widgets/:id",
		contextSetter(func(c *gin.Context) { c.Set("user_id", nsUserID) }),
		authz.RequireOrgScopeForResource(auth.ScopeSCMManage, resolve),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "GET", "/widgets/"+resourceUUID)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (no scopes in context)", w.Code)
	}
}

package middleware

import (
	"bytes"
	"mime/multipart"
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

const (
	nsOrgA   = "org-aaa"
	nsOrgB   = "org-bbb"
	nsUserID = "user-nsauthz"
)

var claimCols = []string{"namespace", "organization_id", "claimed_by", "created_at"}
var artifactOrgCols = []string{"organization_id"}
var userMembershipCols = []string{
	"organization_id", "organization_name", "role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func newNamespaceAuthzTestDeps(t *testing.T) (sqlmock.Sqlmock, *NamespaceAuthorizer) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	orgRepo := repositories.NewOrganizationRepository(db)
	claimRepo := repositories.NewNamespaceClaimRepository(db)
	moduleRepo := repositories.NewModuleRepository(db)
	providerRepo := repositories.NewProviderRepository(db)

	authz := NewNamespaceAuthorizer(orgRepo, claimRepo, moduleRepo, providerRepo)
	return mock, authz
}

func withScopesAndUser(scopes []string, userID string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set("scopes", scopes)
		if userID != "" {
			c.Set("user_id", userID)
		}
	}
}

func withAPIKey(orgID string, scopes []string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set("scopes", scopes)
		c.Set("api_key", &models.APIKey{OrganizationID: orgID, Scopes: scopes})
	}
}

func doNamespaceReq(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

// ---------------------------------------------------------------------------
// RequireNamespaceAccessFromPath — path-carried namespace (delete/deprecate)
// ---------------------------------------------------------------------------

func TestRequireNamespaceAccessFromPath_FailClosed_NoScopes(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system", func(c *gin.Context) {
		// No scopes/user_id set — simulates a context that somehow reached
		// here without authentication having populated it.
	}, authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (fail closed with no scope context): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_CrossOrgPublisher_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	// Namespace "acme" is claimed by org B.
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgB, nil, time.Now()))
	// Caller (publisher scopes, no admin) is not a member of org B.
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (cross-org publisher denied): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_SameOrgPublisher_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub User", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (same-org publisher allowed): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_AdminOverride_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	// Namespace owned by org B, caller has admin scope: no membership lookup
	// should even occur.
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgB, nil, time.Now()))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeAdmin)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (admin crosses org boundary): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

func TestRequireNamespaceAccessFromPath_APIKeyOrgMismatch_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgB, nil, time.Now()))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withAPIKey(nsOrgA, []string{string(auth.ScopeModulesWrite)})),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (API key bound to different org): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_APIKeyOrgMatch_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withAPIKey(nsOrgA, []string{string(auth.ScopeModulesWrite)})),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/acme/vpc/aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (API key org matches owner): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_UnclaimedNoArtifacts_PassesThrough(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols)) // no claim
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols)) // no artifacts either

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/ghost/vpc/aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (nothing exists, handler will 404): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_AmbiguousOwnership_NonAdminDenied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols).AddRow(nsOrgA).AddRow(nsOrgB))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/weird/vpc/aws")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (ambiguous ownership denies non-admin): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_AmbiguousOwnership_AdminAllowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols).AddRow(nsOrgA).AddRow(nsOrgB))

	r := gin.New()
	r.DELETE("/modules/:namespace/:name/:system",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeAdmin)}, nsUserID)),
		authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "DELETE", "/modules/weird/vpc/aws")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (admin can act on ambiguous namespace): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireNamespaceAccessFromPath_EmptyNamespaceParam_FailClosed(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)

	// A route with no :namespace segment at all — c.Param("namespace")
	// naturally returns "" — simulates a route wired up incorrectly.
	r := gin.New()
	r.DELETE("/x", authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := doNamespaceReq(r, "DELETE", "/x")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (missing namespace param fails closed): body=%s", w.Code, w.Body.String())
	}
}

// contextSetter adapts a `func(*gin.Context)` context-seeding helper into a
// gin.HandlerFunc that calls c.Next().
func contextSetter(setup func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		setup(c)
		c.Next()
	}
}

// ---------------------------------------------------------------------------
// RequirePublishAccessFromForm — multipart namespace (module/provider upload)
// ---------------------------------------------------------------------------

func multipartRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("multipart Close: %v", err)
	}
	req := httptest.NewRequest("POST", "/modules", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestRequirePublishAccessFromForm_FirstClaim_BindsToCallerOrg(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols)) // unclaimed
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols)) // no artifacts
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).AddRow(
			nsOrgA, "Org A", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`),
		)) // single membership → unambiguous caller org
	mock.ExpectExec("INSERT INTO namespace_claims").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("newteam", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.POST("/modules",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"namespace": "newteam", "name": "vpc", "system": "aws"}))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (first publish claims namespace): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRequirePublishAccessFromForm_ExistingClaimDifferentOrg_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgB, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW)) // not a member of org B

	r := gin.New()
	r.POST("/modules",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"namespace": "acme", "name": "vpc", "system": "aws"}))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (namespace owned by another org): body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePublishAccessFromForm_ExistingClaimSameOrg_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))

	r := gin.New()
	r.POST("/modules",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"namespace": "acme", "name": "vpc", "system": "aws"}))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (same org allowed to publish new version): body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePublishAccessFromForm_NoNamespaceField_PassesThroughToHandler(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)

	r := gin.New()
	r.POST("/modules",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusBadRequest, gin.H{"error": "missing namespace"}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"name": "vpc", "system": "aws"}))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (handler owns the missing-field validation): body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePublishAccessFromForm_AmbiguousMemberships_NonAdminDenied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).
			AddRow(nsOrgA, "Org A", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`)).
			AddRow(nsOrgB, "Org B", "role-pub", time.Now(), "publisher", "Publisher", []byte(`["modules:write"]`)))

	r := gin.New()
	r.POST("/modules",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"namespace": "newteam", "name": "vpc", "system": "aws"}))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (ambiguous membership can't auto-claim): body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePublishAccessFromForm_APIKeyOrg_FirstClaim(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols))
	mock.ExpectExec("INSERT INTO namespace_claims").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("ci-team", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.POST("/modules",
		contextSetter(withAPIKey(nsOrgA, []string{string(auth.ScopeModulesWrite)})),
		authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, multipartRequest(t, map[string]string{"namespace": "ci-team", "name": "vpc", "system": "aws"}))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (API key org claims directly, no membership query): body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RequirePublishAccessFromJSON — JSON-body namespace (admin create routes)
// ---------------------------------------------------------------------------

func jsonRequest(path, body string) *http.Request {
	req := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRequirePublishAccessFromJSON_BodyRestoredForHandler(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))

	var gotNamespace string
	r := gin.New()
	r.POST("/admin/modules/create",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
		func(c *gin.Context) {
			var body struct {
				Namespace string `json:"namespace"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				t.Fatalf("handler could not re-read body: %v", err)
			}
			gotNamespace = body.Namespace
			c.JSON(http.StatusCreated, gin.H{"ok": true})
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, jsonRequest("/admin/modules/create", `{"namespace":"acme","name":"vpc","system":"aws"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if gotNamespace != "acme" {
		t.Errorf("handler saw namespace %q, want %q (body must be restored)", gotNamespace, "acme")
	}
}

func TestRequirePublishAccessFromJSON_OrgOverrideMismatch_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))

	r := gin.New()
	r.POST("/admin/providers",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeProvidersWrite)}, nsUserID)),
		authz.RequirePublishAccessFromJSON(auth.ScopeProvidersWrite),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, jsonRequest("/admin/providers", `{"namespace":"acme","type":"aws","organization_id":"`+nsOrgB+`"}`))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (organization_id override must match owning org): body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePublishAccessFromJSON_OrgOverrideAdmin_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.POST("/admin/providers",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeAdmin)}, nsUserID)),
		authz.RequirePublishAccessFromJSON(auth.ScopeProvidersWrite),
		func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, jsonRequest("/admin/providers", `{"namespace":"acme","type":"aws","organization_id":"`+nsOrgB+`"}`))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (admin may override organization_id): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RequireModuleAccessByID / RequireModuleUpdateAccess / RequireProviderAccessByID
// ---------------------------------------------------------------------------

var moduleByIDCols = []string{
	"id", "organization_id", "namespace", "name", "system", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
	"deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
}

var providerByIDCols = []string{
	"id", "organization_id", "namespace", "type", "description", "source",
	"created_by", "created_at", "updated_at", "created_by_name",
}

func TestRequireModuleAccessByID_NotUUID_PassesThrough(t *testing.T) {
	_, authz := newNamespaceAuthzTestDeps(t)

	r := gin.New()
	r.POST("/admin/modules/:id/scm",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireModuleAccessByID(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "POST", "/admin/modules/not-a-uuid/scm")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (malformed ID left to handler): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireModuleAccessByID_CrossOrg_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	validUUID := "11111111-1111-1111-1111-111111111111"

	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sqlmock.NewRows(moduleByIDCols).AddRow(
			validUUID, nsOrgB, "acme", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil,
			false, nil, nil, nil,
		))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols)) // no claim row → fall back to artifact org
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW)) // not a member of org B

	r := gin.New()
	r.POST("/admin/modules/:id/scm",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireModuleAccessByID(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "POST", "/admin/modules/"+validUUID+"/scm")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (module owned by another org): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireProviderAccessByID_SameOrg_Allowed(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	validUUID := "22222222-2222-2222-2222-222222222222"

	mock.ExpectQuery("SELECT.*FROM providers").
		WillReturnRows(sqlmock.NewRows(providerByIDCols).AddRow(
			validUUID, nsOrgA, "acme", "aws", nil, nil, nil, time.Now(), time.Now(), nil,
		))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["providers:write"]`),
		))

	r := gin.New()
	r.PUT("/admin/providers/:id",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeProvidersWrite)}, nsUserID)),
		authz.RequireProviderAccessByID(auth.ScopeProvidersWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := doNamespaceReq(r, "PUT", "/admin/providers/"+validUUID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (same org allowed): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireModuleUpdateAccess_MoveToUnclaimedNamespace_ClaimsForCurrentOrg(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	validUUID := "33333333-3333-3333-3333-333333333333"

	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sqlmock.NewRows(moduleByIDCols).AddRow(
			validUUID, nsOrgA, "acme", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil,
			false, nil, nil, nil,
		))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))
	// Target namespace "newhome" is unclaimed and has no artifacts.
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgCols))
	mock.ExpectExec("INSERT INTO namespace_claims").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("newhome", nsOrgA, nil, time.Now()))

	r := gin.New()
	r.PUT("/admin/modules/:id",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireModuleUpdateAccess(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/admin/modules/"+validUUID, bytes.NewBufferString(`{"namespace":"newhome"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (move into unclaimed namespace claims it): body=%s", w.Code, w.Body.String())
	}
}

func TestRequireModuleUpdateAccess_MoveToOtherOrgNamespace_Denied(t *testing.T) {
	mock, authz := newNamespaceAuthzTestDeps(t)
	validUUID := "44444444-4444-4444-4444-444444444444"

	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sqlmock.NewRows(moduleByIDCols).AddRow(
			validUUID, nsOrgA, "acme", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil,
			false, nil, nil, nil,
		))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("acme", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(memberRoleColsMW).AddRow(
			nsOrgA, nsUserID, "role-pub", time.Now(),
			"Pub", "pub@test.com", "publisher", "Publisher", []byte(`["modules:write"]`),
		))
	// Target namespace "rivals" is owned by org B.
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("rivals", nsOrgB, nil, time.Now()))

	r := gin.New()
	r.PUT("/admin/modules/:id",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireModuleUpdateAccess(auth.ScopeModulesWrite),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/admin/modules/"+validUUID, bytes.NewBufferString(`{"namespace":"rivals"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (cannot move module into another org's namespace): body=%s", w.Code, w.Body.String())
	}
}

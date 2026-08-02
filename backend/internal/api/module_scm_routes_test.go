package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Route-wiring regression test for the module-SCM read routes.
//
// GET /admin/modules/:id/scm and .../events read a module_source_repos row
// whose webhook_url embeds the webhook secret (see scm_linking.go's
// webhookCallbackURL construction), and POST /webhooks/scm/:id/:secret is an
// unauthenticated endpoint — possession of that secret IS the credential.
// The four mutations in the same group have always carried
// nsAuthz.RequireModuleAccessByID; these two GETs did not, so any holder of
// the flat modules:write scope could read another organization's link.
//
// This is deliberately a ROUTER-level test driving the real
// registerAPIV1Routes, not a middleware-level one: the defect was in the
// wiring, so a test that mounts the middleware itself would have passed while
// the product was still vulnerable. Same reasoning as
// scim_routes_test.go's comment about avoiding a stand-in gin.Engine.
func TestModuleSCMReadRoutes_CrossOrg_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// auth.GetJWTSecret (via GenerateJWT/ValidateJWT) panics outside dev mode
	// unless this is set — same rationale as scim_routes_test.go.
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	const (
		moduleID = "11111111-1111-1111-1111-111111111111"
		userID   = "user-cross-org"
		otherOrg = "org-b"
	)

	// A caller holding modules:write via membership in some OTHER organization
	// — exactly the flat, org-less scope union issue #652 describes.
	token, err := auth.GenerateJWT(userID, "mallory@example.com",
		[]string{string(auth.ScopeModulesWrite)}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	// Columns mirror middleware/namespace_authz_test.go's fixtures so the
	// authorizer's real queries resolve.
	moduleCols := []string{
		"id", "organization_id", "namespace", "name", "system", "description", "source",
		"created_by", "created_at", "updated_at", "created_by_name",
		"deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
	}
	claimCols := []string{"namespace", "organization_id", "claimed_by", "claimed_at"}
	memberRoleCols := []string{
		"organization_id", "user_id", "role_template_id", "joined_at",
		"name", "email", "role_name", "role_display_name", "role_scopes",
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"link info", "/api/v1/admin/modules/" + moduleID + "/scm"},
		{"webhook events", "/api/v1/admin/modules/" + moduleID + "/scm/events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			nsAuthz := middleware.NewNamespaceAuthorizer(
				repositories.NewOrganizationRepository(db),
				repositories.NewNamespaceClaimRepository(db),
				repositories.NewModuleRepository(db),
				repositories.NewProviderRepository(db),
			)

			// AuthMiddleware resolves the JWT subject before any route runs.
			mock.ExpectQuery("SELECT.*FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(
					[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"},
				).AddRow(userID, "mallory@example.com", "Mallory", nil, time.Now(), time.Now()))

			// The module belongs to org B; the caller is not a member of it.
			mock.ExpectQuery("SELECT.*FROM modules").
				WillReturnRows(sqlmock.NewRows(moduleCols).AddRow(
					moduleID, otherOrg, "acme", "vpc", "aws", nil, nil, nil,
					time.Now(), time.Now(), nil, false, nil, nil, nil,
				))
			mock.ExpectQuery("SELECT.*FROM namespace_claims").
				WillReturnRows(sqlmock.NewRows(claimCols))
			mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
				WillReturnRows(sqlmock.NewRows(memberRoleCols))

			limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
				RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
			})
			defer limiter.Stop()

			r := gin.New()
			// The SCM linking handler is left nil: a correctly-guarded route
			// must reject this cross-org request in middleware and never reach
			// its handler at all. Recovery turns the pre-fix behaviour (request
			// reaches the nil handler) into a clean 500 rather than crashing
			// the test binary, so the assertion below reports it legibly.
			r.Use(gin.Recovery())
			registerAPIV1Routes(r, &apiV1RouteDeps{
				cfg:                &config.Config{},
				userRepo:           repositories.NewUserRepository(db),
				generalRateLimiter: limiter,
				orgRateLimiter:     limiter,
				nsAuthz:            nsAuthz,
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("GET %s: status = %d, want 403 (module owned by another organization); body=%s",
					tc.path, w.Code, w.Body.String())
			}
		})
	}
}

// Class row for the by-id READ axis on the module/provider artifact family
// (issue #719). The class is (org-owned resource) x (access axis), and the
// decisive test is sibling asymmetry: PUT /admin/modules/:id carries
// nsAuthz.RequireModuleUpdateAccess and PUT /admin/providers/:id carries
// nsAuthz.RequireProviderAccessByID, while the GET siblings addressing the
// SAME rows by the SAME id carried only the flat modules:read / providers:read
// scope. Both handlers emit the entire row — organization_id included — and
// their repository calls (GetModuleByID / GetProviderByID) select on the
// primary key with no organization predicate, so any holder of the flat read
// scope could enumerate every organization's artifacts by UUID.
//
// Router-level rather than middleware-level for the same reason as
// TestModuleSCMReadRoutes_CrossOrg_Denied above: the defect was in the wiring,
// so a test that mounts the middleware itself passes while the product leaks.
func TestAdminArtifactByIDReadRoutes_CrossOrg_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	const (
		moduleID   = "44444444-4444-4444-4444-444444444444"
		providerID = "55555555-5555-5555-5555-555555555555"
		userID     = "user-cross-org-read"
		otherOrg   = "org-b"
	)

	moduleCols := []string{
		"id", "organization_id", "namespace", "name", "system", "description", "source",
		"created_by", "created_at", "updated_at", "created_by_name",
		"deprecated", "deprecated_at", "deprecation_message", "successor_module_id",
	}
	providerCols := []string{
		"id", "organization_id", "namespace", "type", "description", "source",
		"created_by", "created_at", "updated_at", "created_by_name",
	}
	claimCols := []string{"namespace", "organization_id", "claimed_by", "claimed_at"}
	memberRoleCols := []string{
		"organization_id", "user_id", "role_template_id", "joined_at",
		"name", "email", "role_name", "role_display_name", "role_scopes",
	}

	for _, tc := range []struct {
		name      string
		path      string
		scope     auth.Scope
		artifact  string // table name fragment the authorizer selects from
		artifactR *sqlmock.Rows
	}{
		{
			name:     "module by id",
			path:     "/api/v1/admin/modules/" + moduleID,
			scope:    auth.ScopeModulesRead,
			artifact: "modules",
			artifactR: sqlmock.NewRows(moduleCols).AddRow(
				moduleID, otherOrg, "acme", "vpc", "aws", nil, nil, nil,
				time.Now(), time.Now(), nil, false, nil, nil, nil,
			),
		},
		{
			name:     "provider by id",
			path:     "/api/v1/admin/providers/" + providerID,
			scope:    auth.ScopeProvidersRead,
			artifact: "providers",
			artifactR: sqlmock.NewRows(providerCols).AddRow(
				providerID, otherOrg, "acme", "aws", nil, nil, nil,
				time.Now(), time.Now(), nil,
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			// A caller holding the flat read scope via membership in some OTHER
			// organization — the same shape as the SCM read case above.
			token, err := auth.GenerateJWT(userID, "mallory@example.com",
				[]string{string(tc.scope)}, time.Hour)
			if err != nil {
				t.Fatalf("GenerateJWT: %v", err)
			}

			nsAuthz := middleware.NewNamespaceAuthorizer(
				repositories.NewOrganizationRepository(db),
				repositories.NewNamespaceClaimRepository(db),
				repositories.NewModuleRepository(db),
				repositories.NewProviderRepository(db),
			)

			mock.ExpectQuery("SELECT.*FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(
					[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"},
				).AddRow(userID, "mallory@example.com", "Mallory", nil, time.Now(), time.Now()))

			// The artifact belongs to org B; the caller is not a member of it.
			mock.ExpectQuery("SELECT.*FROM " + tc.artifact).WillReturnRows(tc.artifactR)
			mock.ExpectQuery("SELECT.*FROM namespace_claims").
				WillReturnRows(sqlmock.NewRows(claimCols))
			mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
				WillReturnRows(sqlmock.NewRows(memberRoleCols))

			limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
				RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
			})
			defer limiter.Stop()

			r := gin.New()
			// Handlers left nil: a correctly-guarded route rejects in
			// middleware and never reaches them. Recovery turns the pre-fix
			// behaviour into a legible 500 instead of a crashed test binary.
			r.Use(gin.Recovery())
			registerAPIV1Routes(r, &apiV1RouteDeps{
				cfg:                &config.Config{},
				userRepo:           repositories.NewUserRepository(db),
				generalRateLimiter: limiter,
				orgRateLimiter:     limiter,
				nsAuthz:            nsAuthz,
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("GET %s: status = %d, want 403 (artifact owned by another organization); body=%s",
					tc.path, w.Code, w.Body.String())
			}
		})
	}
}

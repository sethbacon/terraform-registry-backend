package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Route-wiring regression test for issue #718: every /scm-providers/:id route
// must re-derive the caller's scope in the organization that owns THAT
// provider, not trust the flat org-less scope union in the session JWT.
//
// Driven through the real registerAPIV1Routes rather than a stand-in engine,
// for the same reason as module_scm_routes_test.go: the defect was that the
// guard was absent from the route table, so a middleware-level test would pass
// while the product stayed vulnerable.
func TestSCMProviderRoutes_CrossOrg_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	const (
		providerID = "44444444-4444-4444-4444-444444444444"
		otherOrgID = "55555555-5555-5555-5555-555555555555"
		userID     = "user-scm-cross-org"
	)

	// Mallory holds both SCM scopes — via membership in some OTHER organization.
	token, err := auth.GenerateJWT(userID, "mallory@example.com",
		[]string{string(auth.ScopeSCMRead), string(auth.ScopeSCMManage)}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	for _, tc := range []struct {
		name, method, path string
	}{
		{"read provider", http.MethodGet, "/api/v1/scm-providers/" + providerID},
		{"update provider", http.MethodPut, "/api/v1/scm-providers/" + providerID},
		{"delete provider", http.MethodDelete, "/api/v1/scm-providers/" + providerID},
		{"verify credentials", http.MethodPost, "/api/v1/scm-providers/" + providerID + "/verify"},
		{"save PAT", http.MethodPost, "/api/v1/scm-providers/" + providerID + "/token"},
		{"revoke oauth", http.MethodDelete, "/api/v1/scm-providers/" + providerID + "/oauth/token"},
		{"list repositories", http.MethodGet, "/api/v1/scm-providers/" + providerID + "/repositories"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			// AuthMiddleware resolves the JWT subject.
			mock.ExpectQuery("SELECT.*FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(
					[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"},
				).AddRow(userID, "mallory@example.com", "Mallory", nil, time.Now(), time.Now()))

			// The provider belongs to another organization...
			mock.ExpectQuery("SELECT \\* FROM scm_providers WHERE id").
				WillReturnRows(sqlmock.NewRows([]string{"id", "organization_id", "provider_type", "name", "base_url", "auth_mode", "created_at", "updated_at"}).
					AddRow(providerID, otherOrgID, "github", "gh", "https://github.com", "oauth_user", time.Now(), time.Now()))
			// ...and Mallory is not a member of it.
			mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
				WillReturnRows(sqlmock.NewRows([]string{
					"organization_id", "user_id", "role_template_id", "joined_at",
					"name", "email", "role_name", "role_display_name", "role_scopes",
				}))

			sqlxDB := sqlx.NewDb(db, "sqlmock")
			nsAuthz := middleware.NewNamespaceAuthorizer(
				repositories.NewOrganizationRepository(db),
				repositories.NewNamespaceClaimRepository(db),
				repositories.NewModuleRepository(db),
				repositories.NewProviderRepository(db),
			)

			limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
				RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
			})
			defer limiter.Stop()

			r := gin.New()
			// Handlers are left nil: a correctly-guarded route rejects in
			// middleware and never reaches one. Recovery turns the unguarded
			// case into a legible 500 instead of crashing the test binary.
			r.Use(gin.Recovery())
			registerAPIV1Routes(r, &apiV1RouteDeps{
				cfg:                &config.Config{},
				userRepo:           repositories.NewUserRepository(db),
				generalRateLimiter: limiter,
				orgRateLimiter:     limiter,
				nsAuthz:            nsAuthz,
				scmRepo:            repositories.NewSCMRepository(sqlxDB),
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			// CSRFMiddleware allows Bearer for non-browser origins; no Origin
			// header is set, so these behave as API clients.
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403 (provider owned by another organization); body=%s",
					tc.method, tc.path, w.Code, w.Body.String())
			}
		})
	}
}

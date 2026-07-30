package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// TestRegisterSCIMRoutes_RateLimitRunsAheadOfScopeCheck is a regression test
// for the scimGroup middleware-ordering defect (follow-up to issue #666): a
// SCIM request that authenticates successfully but lacks the scim:provision
// scope must still pass through PrincipalRateLimitMiddleware /
// OrgRateLimitMiddleware, matching every other authenticated mutating route
// in this file (see registerSCIMRoutes / authenticatedGroup).
//
// Unlike a stand-in gin.Engine, this drives registerSCIMRoutes — the exact
// function registerAPIV1Routes calls to mount /scim/v2 — so it fails if the
// .Use() order in router_routes.go ever regresses to registering
// RequireScope before the rate-limit/audit middleware: in that broken
// ordering, RequireScope aborts the chain before the rate limiter runs, so
// the limiter's counter is never incremented and no request in this test
// would ever see 429.
func TestRegisterSCIMRoutes_RateLimitRunsAheadOfScopeCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// auth.GetJWTSecret (invoked by GenerateJWT/ValidateJWT) panics outside
	// dev mode unless TFR_JWT_SECRET is set; no other test in this package
	// exercises the JWT path, so it is safe to set here.
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	userRepo := repositories.NewUserRepository(db)

	// registerSCIMRoutes wires both PrincipalRateLimitMiddleware and
	// OrgRateLimitMiddleware onto the same generalRateLimiter/principal key,
	// so each request consumes 2 tokens from the shared bucket (one per
	// middleware). BurstSize 4 lets exactly the first two requests through.
	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 60, BurstSize: 4, CleanupInterval: time.Minute,
	})
	defer limiter.Stop()

	r := gin.New()
	registerSCIMRoutes(r, &apiV1RouteDeps{
		cfg:                &config.Config{},
		userRepo:           userRepo,
		generalRateLimiter: limiter,
		orgRateLimiter:     limiter,
	})

	// A valid JWT with no scopes: AuthMiddleware succeeds (sets user_id, so
	// every request shares one rate-limit principal/bucket) but
	// RequireScope(scim:provision) will reject it.
	token, err := auth.GenerateJWT("user-1", "svc@example.com", nil, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	userCols := []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}
	const requests = 3 // burst size is 2: the 3rd request must hit the rate limit
	for i := 0; i < requests; i++ {
		mock.ExpectQuery("SELECT.*FROM users WHERE id").
			WillReturnRows(sqlmock.NewRows(userCols).
				AddRow("user-1", "svc@example.com", "Service", nil, time.Now(), time.Now()))
	}

	var codes []int
	for i := 0; i < requests; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}

	if codes[0] != http.StatusForbidden || codes[1] != http.StatusForbidden {
		t.Fatalf("codes = %v, want first two requests = 403 (authenticated, missing scope)", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want third request = 429 (rate limit reached before the scope check runs)", codes)
	}
}

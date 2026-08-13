package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// The platform-admin carrier, end to end through the REAL route tree (issue
// #766, PR 1).
//
// The middleware tests assert the elevation lands in the request context. This
// asserts the point of the whole design: because the elevation happens at ONE
// insertion point, an existing, untouched `auth.HasScope(scopes,
// auth.ScopeAdmin)` site starts answering from the carrier with no edit of its
// own.
//
// The site under test is api/admin/dev.go:161 — deliberately, because the
// design calls it out by name: "Dev login / impersonation must consult the
// carrier, or DEV_MODE becomes a way to mint platform-admin without a grant."
// It consults it here through the same middleware every other site does, which
// is why dev.go itself needed no change.
//
// The session presented below carries NO scopes at all. Every route in this
// tree is reached with an org-less scope union that would have refused it
// before the carrier existed.

// carrierDevRouter mounts the real /api/v1 route tree in DEV_MODE with a
// carrier repository wired in, and returns the engine plus the identity mock
// (userRepo + the dev handlers' own repositories share it) and the carrier
// mock.
func carrierDevRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DEV_MODE", "true")
	t.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	idDB, idMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { idDB.Close() })

	paDB, paMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (platform_admins): %v", err)
	}
	t.Cleanup(func() { paDB.Close() })

	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 600, BurstSize: 600, CleanupInterval: time.Minute,
	})
	t.Cleanup(limiter.Stop)

	r := gin.New()
	r.Use(gin.Recovery())
	registerAPIV1Routes(r, &apiV1RouteDeps{
		cfg:                &config.Config{},
		db:                 idDB,
		identityDB:         idDB,
		userRepo:           repositories.NewUserRepository(idDB),
		orgRepo:            repositories.NewOrganizationRepository(idDB),
		platformAdminRepo:  repositories.NewPlatformAdminRepository(paDB),
		generalRateLimiter: limiter,
		orgRateLimiter:     limiter,
	})
	return r, idMock, paMock
}

// expectSessionUserLoad queues AuthMiddleware's user load for the JWT path.
func expectSessionUserLoad(mock sqlmock.Sqlmock, userID string) {
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
			AddRow(userID, "carrier@example.com", "Carrier Admin", nil, time.Now(), time.Now()))
}

func carrierDevRequest(t *testing.T, r *gin.Engine, userID string) *httptest.ResponseRecorder {
	t.Helper()
	return carrierDevRequestWithScopes(t, r, userID, []string{})
}

func carrierDevRequestWithScopes(t *testing.T, r *gin.Engine, userID string, scopes []string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := auth.GenerateJWT(userID, "carrier@example.com", scopes, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dev/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// A carrier grant admits the caller at an admin check that was not edited.
func TestPlatformAdminCarrier_AdmitsAtAnUneditedHasScopeSite(t *testing.T) {
	r, idMock, paMock := carrierDevRouter(t)

	expectSessionUserLoad(idMock, "user-carrier")
	paMock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WithArgs("user-carrier").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	// Past the gate, ListUsersForImpersonationHandler lists users. An empty
	// page is a complete, successful answer and keeps the assertion on the
	// authorization outcome rather than on fixture data.
	idMock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	idMock.ExpectQuery("SELECT id, email, name, oidc_sub").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}))

	if w := carrierDevRequest(t, r, "user-carrier"); w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/dev/users = %d, want 200: a carrier grant did not reach "+
			"the untouched admin check at api/admin/dev.go:161. body=%s", w.Code, w.Body.String())
	}
	if err := paMock.ExpectationsWereMet(); err != nil {
		t.Errorf("the carrier was not consulted on the session path: %v", err)
	}
}

// The negative control, and the reason the test above proves anything: the
// SAME request with no carrier row is refused with exactly 403 — the status
// dev.go answers with — not a 500 from an incidental mock miss.
func TestPlatformAdminCarrier_WithoutAGrantTheSameRequestIsRefused(t *testing.T) {
	r, idMock, paMock := carrierDevRouter(t)

	expectSessionUserLoad(idMock, "user-plain")
	paMock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WithArgs("user-plain").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := carrierDevRequest(t, r, "user-plain")
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /api/v1/dev/users = %d, want 403 (no carrier row, no admin scope): body=%s",
			w.Code, w.Body.String())
	}
	if err := idMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet identity expectations: %v", err)
	}
}

// THE BREAKING CHANGE, asserted where an operator meets it (issue #766,
// migration 000054).
//
// A session token carrying `admin` in its scope union — exactly what
// GetUserCombinedScopes minted for anyone holding the seeded `admin` role
// template, and what every live pre-upgrade session still carries — reaches the
// same untouched auth.HasScope(scopes, auth.ScopeAdmin) site and is REFUSED,
// because the principal has no carrier row.
//
// Exactly 403, not "not 200": a 500 from an incidental mock miss would satisfy
// a weaker check while proving nothing, and 403 is the status dev.go answers
// with. The negative control above supplies no scopes at all; this one supplies
// the wildcard, so the only thing separating the two is the strip.
func TestPlatformAdminCarrier_AdminScopeInTheTokenNoLongerAdmits(t *testing.T) {
	r, idMock, paMock := carrierDevRouter(t)

	expectSessionUserLoad(idMock, "user-template-admin")
	paMock.ExpectQuery("SELECT EXISTS.*FROM platform_admins").
		WithArgs("user-template-admin").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := carrierDevRequestWithScopes(t, r, "user-template-admin", []string{"admin"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /api/v1/dev/users = %d, want 403: a session holding `admin` through the scope union "+
			"still administers the platform, so authority has not moved to the carrier. body=%s",
			w.Code, w.Body.String())
	}
	if err := paMock.ExpectationsWereMet(); err != nil {
		t.Errorf("the carrier was not consulted on the session path: %v", err)
	}
	if err := idMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet identity expectations — the handler ran: %v", err)
	}
}

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Issue #740 — the /api/v1/dev family.
//
// POST /api/v1/dev/login takes no credential and returns a 24-hour admin
// session. It was mounted on EVERY router, in production too, with
// DevModeMiddleware turning it into a 403 per request. That is one env var
// away from answering — and the same DEV_MODE independently disables the
// TFR_JWT_SECRET production fail-fast, so a single stray value both opens the
// door and weakens the key that guards everything behind it.
//
// The fix registers the group only when IsDevMode() holds at startup. A route
// that does not exist cannot be reached by a misconfiguration, a middleware
// ordering mistake, or a refactor that drops the guard. DevModeMiddleware
// stays as a second, independent check.
//
// These tests drive the real registerAPIV1Routes, so they see the actual
// mounting decision rather than a stand-in engine.

// devRoutePaths is the complete /dev family. A route added to the group
// without a row here is caught by TestDevRoutes_TableCoversTheWholeDevFamily.
var devRoutePaths = []struct {
	method  string
	path    string
	mutates bool // cookie-authenticated state change => must be behind CSRF
}{
	{"GET", "/api/v1/dev/status", false},
	{"POST", "/api/v1/dev/login", false}, // pre-auth, no session to forge against
	{"GET", "/api/v1/dev/users", false},  // authenticated, but a safe method
	{"POST", "/api/v1/dev/impersonate/:user_id", true},
}

// devModeRouter registers the real v1 route tree with DEV_MODE set to devMode
// and returns the engine plus the registered route set.
func devModeRouter(t *testing.T, devMode string) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DEV_MODE", devMode)
	t.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 600, BurstSize: 600, CleanupInterval: time.Minute,
	})
	t.Cleanup(limiter.Stop)

	r := gin.New()
	r.Use(gin.Recovery())
	registerAPIV1Routes(r, &apiV1RouteDeps{
		cfg:                &config.Config{},
		db:                 db,
		userRepo:           repositories.NewUserRepository(db),
		orgRepo:            repositories.NewOrganizationRepository(db),
		generalRateLimiter: limiter,
		orgRateLimiter:     limiter,
	})
	return r, mock
}

// registeredDevRoutes returns method+path for every mounted route under /dev.
func registeredDevRoutes(r *gin.Engine) map[string]bool {
	out := map[string]bool{}
	for _, ri := range r.Routes() {
		if strings.HasPrefix(ri.Path, "/api/v1/dev/") {
			out[ri.Method+" "+ri.Path] = true
		}
	}
	return out
}

func TestDevRoutes_AreNotRegisteredAtAllWithoutDevMode(t *testing.T) {
	r, _ := devModeRouter(t, "")

	if got := registeredDevRoutes(r); len(got) != 0 {
		t.Errorf("dev routes are mounted without DEV_MODE: %v", got)
	}

	// 404, not 403. A 403 is DevModeMiddleware answering, which means the
	// handler is still wired and one env var away from running. 404 is the
	// assertion that there is nothing there to gate.
	for _, rt := range devRoutePaths {
		concrete := strings.Replace(rt.path, ":user_id", "some-user", 1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(rt.method, concrete, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d in production, want 404 (route must not exist)",
				rt.method, concrete, w.Code)
		}
	}
}

func TestDevRoutes_AreRegisteredInDevMode(t *testing.T) {
	// The other direction. Without this, deleting the routes outright would
	// pass the test above — the guard has to be a condition, not a removal.
	r, _ := devModeRouter(t, "true")

	got := registeredDevRoutes(r)
	for _, rt := range devRoutePaths {
		if key := rt.method + " " + rt.path; !got[key] {
			t.Errorf("%s is not mounted under DEV_MODE=true; mounted: %v", key, got)
		}
	}
}

func TestDevRoutes_TableCoversTheWholeDevFamily(t *testing.T) {
	// devRoutePaths drives the CSRF assertion below, so a route added to the
	// group but not to the table would be silently unexamined. Bidirectional:
	// this fails on a new route AND on a stale row (via the test above).
	r, _ := devModeRouter(t, "true")

	known := map[string]bool{}
	for _, rt := range devRoutePaths {
		known[rt.method+" "+rt.path] = true
	}
	for key := range registeredDevRoutes(r) {
		if !known[key] {
			t.Errorf("%s is mounted but missing from devRoutePaths — add a row "+
				"(set mutates:true if it is a cookie-authenticated state change)", key)
		}
	}
}

// TestDevMutatingRoutes_RejectCookieAuthWithoutCSRF is the second half of #740.
//
// The /dev group sits outside authenticatedGroup, so it never inherited that
// group's CSRFMiddleware. POST /dev/impersonate/:user_id is cookie-
// authenticated and swaps the caller's session to another user: without CSRF,
// any page a logged-in dev admin visits could silently re-point their session.
//
// Cookie auth specifically — Bearer and API-key callers are exempt by design
// (see middleware/csrf.go), so a Bearer-token request would pass with the
// middleware removed and prove nothing.
func TestDevMutatingRoutes_RejectCookieAuthWithoutCSRF(t *testing.T) {
	for _, rt := range devRoutePaths {
		if !rt.mutates {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			r, mock := devModeRouter(t, "true")

			token, err := auth.GenerateJWT("dev-admin", "admin@example.com",
				[]string{string(auth.ScopeAdmin)}, time.Hour)
			if err != nil {
				t.Fatalf("GenerateJWT: %v", err)
			}
			mock.ExpectQuery("SELECT.*FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(
					[]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
					AddRow("dev-admin", "admin@example.com", "Dev Admin", nil,
						time.Now(), time.Now()))

			concrete := strings.Replace(rt.path, ":user_id", "victim-user", 1)
			req := httptest.NewRequest(rt.method, concrete, nil)
			// Cookie, not Authorization: this is the browser-driven shape the
			// double-submit check exists for.
			req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: token})
			req.Header.Set("Origin", "https://evil.example")

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with a session cookie and no CSRF token = %d, want 403",
					rt.method, concrete, w.Code)
			}
		})
	}
}

// TestDevModeDetection_RequiresExplicitOptIn pins the values that mount the
// group. Anything outside this set must not, or "DEV_MODE=false" reads as
// enabled somewhere down the line.
func TestDevModeDetection_RequiresExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true}, {"1", true},
		{"", false}, {"false", false}, {"0", false},
		{"TRUE", false}, {"yes", false}, {"dev", false},
	} {
		t.Run("DEV_MODE="+tc.value, func(t *testing.T) {
			old, had := os.LookupEnv("DEV_MODE")
			t.Cleanup(func() {
				if had {
					os.Setenv("DEV_MODE", old)
				} else {
					os.Unsetenv("DEV_MODE")
				}
			})
			os.Setenv("DEV_MODE", tc.value)
			if got := admin.IsDevMode(); got != tc.want {
				t.Errorf("IsDevMode() with DEV_MODE=%q = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

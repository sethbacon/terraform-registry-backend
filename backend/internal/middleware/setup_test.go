package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newOIDCConfigRepo(t *testing.T) (*repositories.OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func newSetupRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	repo, mock := newOIDCConfigRepo(t)
	r := gin.New()
	r.Use(SetupTokenMiddleware(repo))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return mock, r
}

// newFullSetupRouter mounts SetupTokenMiddleware under the real /api/v1/setup
// route prefix with one handler per real route, so c.FullPath() inside the
// middleware matches production (see featureSetupAllowedPaths).
func newFullSetupRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	repo, mock := newOIDCConfigRepo(t)
	r := gin.New()
	group := r.Group("/api/v1/setup")
	group.Use(SetupTokenMiddleware(repo))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	group.POST("/validate-token", ok)
	group.POST("/oidc/test", ok)
	group.POST("/oidc", ok)
	group.POST("/ldap/test", ok)
	group.POST("/ldap", ok)
	group.POST("/storage/test", ok)
	group.POST("/storage", ok)
	group.POST("/admin", ok)
	group.POST("/scanning", ok)
	group.POST("/scanning/test", ok)
	group.POST("/scanning/install", ok)
	group.POST("/complete", ok)
	group.PUT("/ui-theme", ok)
	return mock, r
}

func doFullSetupRequest(r *gin.Engine, path, authHeader string) *httptest.ResponseRecorder {
	return doFullSetupRequestMethod(r, http.MethodPost, path, authHeader)
}

func doFullSetupRequestMethod(r *gin.Engine, method, path, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

func doSetupRequest(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — setup already completed
// ---------------------------------------------------------------------------

func TestSetupMiddleware_SetupCompleted(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))
	// HasPendingFeatureSetup check — no pending features
	mock.ExpectQuery(`SELECT setup_completed AND \(NOT scanning_configured\) FROM system_settings`).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(false))

	w := doSetupRequest(r, "SetupToken valid-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — setup completed check error
// ---------------------------------------------------------------------------

func TestSetupMiddleware_SetupCheckError(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnError(errors.New("db down"))

	w := doSetupRequest(r, "SetupToken valid-token")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — missing authorization header
// ---------------------------------------------------------------------------

func TestSetupMiddleware_MissingHeader(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))

	w := doSetupRequest(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — wrong scheme (Bearer instead of SetupToken)
// ---------------------------------------------------------------------------

func TestSetupMiddleware_WrongScheme(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))

	w := doSetupRequest(r, "Bearer some-jwt")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — no stored hash (no token generated)
// ---------------------------------------------------------------------------

func TestSetupMiddleware_NoStoredHash(t *testing.T) {
	mock, r := newSetupRouter(t)
	// setup_completed = false
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	// setup_token_hash is NULL
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(nil))

	w := doSetupRequest(r, "SetupToken some-token")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — hash retrieval error
// ---------------------------------------------------------------------------

func TestSetupMiddleware_HashRetrievalError(t *testing.T) {
	mock, r := newSetupRouter(t)
	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnError(errors.New("connection lost"))

	w := doSetupRequest(r, "SetupToken some-token")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — wrong token
// ---------------------------------------------------------------------------

func TestSetupMiddleware_WrongToken(t *testing.T) {
	mock, r := newSetupRouter(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-token"), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "SetupToken wrong-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — valid token
// ---------------------------------------------------------------------------

func TestSetupMiddleware_ValidToken(t *testing.T) {
	mock, r := newSetupRouter(t)

	token := "my-valid-setup-token"
	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "SetupToken "+token)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — case-insensitive scheme
// ---------------------------------------------------------------------------

func TestSetupMiddleware_CaseInsensitiveScheme(t *testing.T) {
	mock, r := newSetupRouter(t)

	token := "my-valid-setup-token"
	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

	w := doSetupRequest(r, "setuptoken "+token)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (scheme should be case-insensitive)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — rate limiter unit tests
// ---------------------------------------------------------------------------

func TestSetupRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := newSetupRateLimiter()
	for i := 0; i < setupMaxAttempts; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
}

func TestSetupRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := newSetupRateLimiter()
	for i := 0; i < setupMaxAttempts; i++ {
		rl.allow("1.2.3.4")
	}
	if rl.allow("1.2.3.4") {
		t.Error("attempt beyond limit should be blocked")
	}
}

func TestSetupRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := newSetupRateLimiter()
	// Exhaust limit for IP-A
	for i := 0; i < setupMaxAttempts; i++ {
		rl.allow("10.0.0.1")
	}
	// IP-B should still be allowed
	if !rl.allow("10.0.0.2") {
		t.Error("different IP should have independent rate limit")
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — pending-feature re-arm scoping (issue #649)
// ---------------------------------------------------------------------------

// TestSetupMiddleware_PendingFeature_BlocksIdentityEndpoints is the negative
// (attack-path) test: even when setup is completed AND a feature is pending
// (HasPendingFeatureSetup=true), identity/admin/storage endpoints must stay
// permanently disabled -- a re-minted setup token for the pending feature
// must not be able to reconfigure OIDC, LDAP, storage, mint an admin, or
// change the UI theme. Covers each route's /test sibling too (e.g.
// /oidc/test), not just the save endpoint, since both are registered on the
// same setupGroup and gated by the same featureSetupAllowedPaths lookup.
//
// The Authorization header carries a real, correctly bcrypt-hashed setup
// token (mocked identically to the positive AllowsScanningEndpoint case
// below), not a throwaway string -- so the 403 asserted here demonstrates
// that the route-scoping gate itself blocks a validly-reminted token,
// rather than merely reflecting an unrelated sqlmock "unexpected query"
// 500 that would occur regardless of whether the gate exists. If the
// featureSetupAllowedPaths gate were ever removed, this exact setup would
// let the request reach the token check and legitimately succeed with 200.
func TestSetupMiddleware_PendingFeature_BlocksIdentityEndpoints(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/setup/oidc"},
		{http.MethodPost, "/api/v1/setup/oidc/test"},
		{http.MethodPost, "/api/v1/setup/ldap"},
		{http.MethodPost, "/api/v1/setup/ldap/test"},
		{http.MethodPost, "/api/v1/setup/storage"},
		{http.MethodPost, "/api/v1/setup/storage/test"},
		{http.MethodPost, "/api/v1/setup/admin"},
		{http.MethodPut, "/api/v1/setup/ui-theme"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			mock, r := newFullSetupRouter(t)
			token := "re-minted-setup-token"
			hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

			mock.ExpectQuery("SELECT setup_completed FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))
			mock.ExpectQuery(`SELECT setup_completed AND \(NOT scanning_configured\) FROM system_settings`).
				WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))
			// Registered but expected to go unconsumed: the route-scoping gate
			// must abort with 403 before ever reaching the token-hash check. If
			// the gate is removed, the middleware would query this hash next,
			// the valid token below would match it, and the request would
			// wrongly succeed with 200 -- which is exactly the exploit #649 fixed.
			mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

			w := doFullSetupRequestMethod(r, tc.method, tc.path, "SetupToken "+token)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403 (a valid re-minted setup token must not reach this endpoint)", tc.method, tc.path, w.Code)
			}
		})
	}
}

// TestSetupMiddleware_PendingFeature_AllowsScanningEndpoint is the positive
// (legit-path) counterpart: with setup completed and a feature pending, the
// pending feature's own routes (scanning, validate-token, complete) remain
// reachable with a valid setup token.
func TestSetupMiddleware_PendingFeature_AllowsScanningEndpoint(t *testing.T) {
	for _, path := range []string{"/api/v1/setup/scanning", "/api/v1/setup/scanning/test", "/api/v1/setup/scanning/install", "/api/v1/setup/validate-token", "/api/v1/setup/complete"} {
		t.Run(path, func(t *testing.T) {
			mock, r := newFullSetupRouter(t)
			token := "feature-setup-token"
			hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)

			mock.ExpectQuery("SELECT setup_completed FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))
			mock.ExpectQuery(`SELECT setup_completed AND \(NOT scanning_configured\) FROM system_settings`).
				WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))
			mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
				WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(string(hash)))

			w := doFullSetupRequest(r, path, "SetupToken "+token)
			if w.Code != http.StatusOK {
				t.Errorf("path %s: status = %d, want 200", path, w.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SetupTokenMiddleware — rate limit returns 429
// ---------------------------------------------------------------------------

func TestSetupMiddleware_RateLimitExceeded(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	r := gin.New()
	r.Use(SetupTokenMiddleware(repo))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Make setupMaxAttempts + 1 requests (each needs completed check)
	for i := 0; i <= setupMaxAttempts; i++ {
		mock.ExpectQuery("SELECT setup_completed FROM system_settings").
			WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(false))
	}

	var lastCode int
	for i := 0; i <= setupMaxAttempts; i++ {
		w := doSetupRequest(r, "SetupToken any-token")
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after exceeding rate limit, status = %d, want 429", lastCode)
	}
}

package api

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

// Issue #764 — POST /api/v1/auth/logout must leave the presented JWT unusable.
//
// The invariant under test is "a completed logout ends the session", and the
// only observable that carries it is the token's fate on the NEXT request. The
// endpoint has always cleared the auth and CSRF cookies, so a test that asserts
// cookie-clearing passes whether or not the JWT was revoked — which is exactly
// why the gap survived: the route was mounted on the public group, nothing
// populated the claims the handler revokes from, and the revocation branch was
// unreachable while the endpoint reported success.
//
// Driven through the real registerAPIV1Routes rather than a stand-in engine
// because the defect lived in the wiring: a test that mounts the middleware
// itself passes while the product still hands back a live token. Same reasoning
// as module_scm_routes_test.go and scim_routes_test.go.

const (
	logoutTestUserID = "user-logout-764"
	logoutTestEmail  = "logout@example.com"
)

var logoutTestUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

var logoutTestMembershipCols = []string{
	"organization_id", "organization_name",
	"role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

// revocationLedger is the state the revocation store would hold. It records
// every JTI written by RevokeToken so the later "is this token revoked?" lookup
// can be answered from what the logout request ACTUALLY persisted, rather than
// from a hardcoded true. Without that link the replay assertion would pass on a
// build where nothing is ever revoked.
type revocationLedger struct {
	mu   sync.Mutex
	jtis map[string]struct{}
}

func newRevocationLedger() *revocationLedger {
	return &revocationLedger{jtis: map[string]struct{}{}}
}

// Match implements sqlmock.Argument: it accepts any JTI and records it.
func (l *revocationLedger) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.jtis[s] = struct{}{}
	return true
}

func (l *revocationLedger) revoked(jti string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.jtis[jti]
	return ok
}

func logoutTestUserRows() *sqlmock.Rows {
	return sqlmock.NewRows(logoutTestUserCols).
		AddRow(logoutTestUserID, logoutTestEmail, "Logout Test", nil, time.Now(), time.Now())
}

// expectRevocationLookup programs the revoked-tokens probe both auth
// middlewares make, answering it from the ledger.
func expectRevocationLookup(mock sqlmock.Sqlmock, ledger *revocationLedger, jti string) {
	mock.ExpectQuery("SELECT EXISTS.*FROM revoked_tokens WHERE jti").
		WithArgs(jti).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(ledger.revoked(jti)))
}

// expectSessionLoad programs the queries an accepted session runs on
// GET /api/v1/auth/me: AuthMiddleware's user load, then MeHandler's
// GetUserWithOrgRoles (user + memberships).
func expectSessionLoad(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM users WHERE id").WillReturnRows(logoutTestUserRows())
	mock.ExpectQuery("SELECT.*FROM users WHERE id").WillReturnRows(logoutTestUserRows())
	mock.ExpectQuery("FROM organization_members").
		WillReturnRows(sqlmock.NewRows(logoutTestMembershipCols))
}

func TestLogout_RevokesPresentedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// auth.GetJWTSecret panics outside dev mode without this — same rationale
	// as module_scm_routes_test.go.
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	validToken, err := auth.GenerateJWT(logoutTestUserID, logoutTestEmail, nil, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	validClaims, err := auth.ValidateJWT(validToken)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	expiredToken, err := auth.GenerateJWT(logoutTestUserID, logoutTestEmail, nil, -time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT (expired): %v", err)
	}

	for _, tc := range []struct {
		name string
		// token presented on the logout request; "" means no session cookie.
		token string
		// replay: re-present the same token on an authenticated route
		// afterwards and require it to be rejected.
		replay bool
	}{
		{
			// The defect: this row is the only one that can see it.
			name:   "valid session logs out then reuses the token",
			token:  validToken,
			replay: true,
		},
		{
			// Logout is reachable without a session (cookie already gone,
			// second tab, bookmarked POST) and must still tear down.
			name:  "logout with no token at all",
			token: "",
		},
		{
			// An expired token cannot be revoked (its claims do not validate);
			// logout must complete rather than fail the caller.
			name:  "logout with an expired token",
			token: expiredToken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			// Requests interleave middleware and handler queries; match on
			// shape, not sequence.
			mock.MatchExpectationsInOrder(false)

			ledger := newRevocationLedger()

			limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
				RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
			})
			defer limiter.Stop()

			tokenRepo := repositories.NewTokenRepository(db)
			cfg := &config.Config{}
			cfg.Server.PublicURL = "https://registry.example.com"
			authHandlers, err := admin.NewAuthHandlers(cfg, db, nil, tokenRepo,
				auth.NewMemoryStateStore(time.Hour))
			if err != nil {
				t.Fatalf("NewAuthHandlers: %v", err)
			}

			r := gin.New()
			r.Use(gin.Recovery())
			registerAPIV1Routes(r, &apiV1RouteDeps{
				cfg:                cfg,
				db:                 db,
				authHandlers:       authHandlers,
				userRepo:           repositories.NewUserRepository(db),
				tokenRepo:          tokenRepo,
				authRateLimiter:    limiter,
				generalRateLimiter: limiter,
				orgRateLimiter:     limiter,
			})

			// Control: before logging out, the token is a working session.
			if tc.replay {
				expectRevocationLookup(mock, ledger, validClaims.JTI)
				expectSessionLoad(mock)
				if code, _ := doAuthedMe(r, tc.token); code != http.StatusOK {
					t.Fatalf("pre-logout GET /api/v1/auth/me: status = %d, want 200 "+
						"(the replay assertion is meaningless unless the token works first)", code)
				}
			}

			// Logout.
			if tc.token == validToken {
				expectRevocationLookup(mock, ledger, validClaims.JTI)
				mock.ExpectQuery("SELECT.*FROM users WHERE id").WillReturnRows(logoutTestUserRows())
				// The write under test. The ledger argument records the JTI
				// that reaches the revocation store.
				mock.ExpectExec("INSERT INTO revoked_tokens").
					WithArgs(ledger, sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			}

			code, body := doLogout(r, tc.token)
			if code != http.StatusOK {
				t.Fatalf("POST /api/v1/auth/logout: status = %d, want 200; body=%s", code, body)
			}
			if !strings.Contains(body, "redirect_url") {
				t.Errorf("logout body = %s, want a redirect_url", body)
			}

			if !tc.replay {
				return
			}

			// The assertion that matters: the same token, presented again to
			// an authenticated route, must be rejected. The revoked-tokens
			// probe is answered from the ledger, so this can only pass if the
			// logout request actually wrote the JTI to the store.
			expectRevocationLookup(mock, ledger, validClaims.JTI)
			expectSessionLoad(mock)

			code, body = doAuthedMe(r, tc.token)
			if code != http.StatusUnauthorized {
				t.Errorf("post-logout GET /api/v1/auth/me: status = %d, want 401 "+
					"(the JWT survived logout and is still a valid session); body=%s", code, body)
			}
			if !strings.Contains(strings.ToLower(body), "revoked") {
				t.Errorf("post-logout GET /api/v1/auth/me: body = %s, want rejection on revocation", body)
			}
			if !ledger.revoked(validClaims.JTI) {
				t.Errorf("logout did not write the session JTI to the revocation store")
			}
		})
	}
}

// doLogout POSTs the real logout route with the double-submit CSRF pair the
// public group requires, optionally carrying a session cookie.
func doLogout(r *gin.Engine, token string) (int, string) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	const csrf = "csrf-token-value"
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	req.Header.Set(middleware.CSRFHeaderName, csrf)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: token})
	}
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// doAuthedMe presents the token to an authenticated route.
func doAuthedMe(r *gin.Engine, token string) (int, string) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: token})
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

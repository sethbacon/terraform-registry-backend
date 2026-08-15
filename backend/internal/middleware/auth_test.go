package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Helpers for JWT path tests (separate mocks for userRepo + orgRepo)
// ---------------------------------------------------------------------------

var jwtUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

var jwtMembershipCols = []string{
	"organization_id", "organization_name",
	"role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func newUserRepo(t *testing.T) (*repositories.UserRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (user): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewUserRepository(db), mock
}

func newOrgRepo(t *testing.T) (*repositories.OrganizationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (org): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOrganizationRepository(db), mock
}

func newAuthRouterWithJWT(t *testing.T, userMock, orgMock sqlmock.Sqlmock,
	userRepo *repositories.UserRepository, orgRepo *repositories.OrganizationRepository) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func generateTestJWT(t *testing.T, userID string) string {
	t.Helper()
	token, err := auth.GenerateJWT(userID, "test@example.com", nil, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return token
}

// newAuthRouter builds a router with AuthMiddleware using nil repos.
// nil repos are safe for early-exit paths that abort before any repo call.
func newAuthRouter() *gin.Engine {
	r := gin.New()
	r.Use(AuthMiddleware(nil, nil, nil, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// newOptionalAuthRouter builds a router with OptionalAuthMiddleware using nil repos.
func newOptionalAuthRouter() *gin.Engine {
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, nil, nil, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doAuthRequest(r *gin.Engine, authHeader string) int {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w.Code
}

// ---------------------------------------------------------------------------
// AuthMiddleware — early-exit paths (no repository calls needed)
// ---------------------------------------------------------------------------

func TestAuthMiddleware_MissingHeaderAndCookie(t *testing.T) {
	if code := doAuthRequest(newAuthRouter(), ""); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

func TestAuthMiddleware_NonBearerPrefix(t *testing.T) {
	if code := doAuthRequest(newAuthRouter(), "Basic dXNlcjpwYXNz"); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

func TestAuthMiddleware_EmptyToken(t *testing.T) {
	// "Bearer " with only whitespace → trimmed to empty → falls through to cookie
	// No cookie set either → 401
	if code := doAuthRequest(newAuthRouter(), "Bearer   "); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

// ---------------------------------------------------------------------------
// AuthMiddleware — cookie-based authentication
// ---------------------------------------------------------------------------

func TestAuthMiddleware_CookieAuth_InvalidJWT(t *testing.T) {
	r := newAuthRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: "not-a-valid-jwt"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("cookie with invalid JWT: status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_CookieAuth_ValidJWT(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)

	r := gin.New()
	var capturedAuthMethod string
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) {
		if am, ok := c.Get("auth_method"); ok {
			capturedAuthMethod = am.(string)
		}
		c.Status(http.StatusOK)
	})

	// Ensure JWT secret is initialized
	_ = auth.ValidateJWTSecret()
	token := generateTestJWT(t, "user-123")

	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-123", "test@example.com", "Test", "sub-123", time.Now(), time.Now()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: token})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cookie with valid JWT: status = %d, want 200", w.Code)
	}
	if capturedAuthMethod != "jwt_cookie" {
		t.Errorf("auth_method = %q, want %q", capturedAuthMethod, "jwt_cookie")
	}
}

func TestAuthMiddleware_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)

	r := gin.New()
	var capturedAuthMethod string
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) {
		if am, ok := c.Get("auth_method"); ok {
			capturedAuthMethod = am.(string)
		}
		c.Status(http.StatusOK)
	})

	_ = auth.ValidateJWTSecret()
	token := generateTestJWT(t, "user-456")

	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-456", "test@example.com", "Test", "sub-456", time.Now(), time.Now()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: "different-cookie-value"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if capturedAuthMethod != "jwt" {
		t.Errorf("auth_method = %q, want %q (header should take precedence)", capturedAuthMethod, "jwt")
	}
}

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware — early-exit paths (passes through, never aborts)
// ---------------------------------------------------------------------------

func TestOptionalAuthMiddleware_MissingHeader(t *testing.T) {
	// No auth header → passes through with 200
	if code := doAuthRequest(newOptionalAuthRouter(), ""); code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth passes through)", code)
	}
}

func TestOptionalAuthMiddleware_NonBearerPrefix(t *testing.T) {
	// Invalid format → passes through with 200
	if code := doAuthRequest(newOptionalAuthRouter(), "Basic dXNlcjpwYXNz"); code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth passes through)", code)
	}
}

func TestOptionalAuthMiddleware_EmptyToken(t *testing.T) {
	// "Bearer " with only whitespace → passes through with 200
	if code := doAuthRequest(newOptionalAuthRouter(), "Bearer   "); code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth passes through)", code)
	}
}

// ---------------------------------------------------------------------------
// authenticateAPIKey (unexported helper)
// ---------------------------------------------------------------------------

func newTestAPIKeyRepo(t *testing.T) (*repositories.APIKeyRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewAPIKeyRepository(db), mock
}

// GetAPIKeysByPrefix uses 12 columns (no user_name join)
var apiKeyPrefixCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "expiry_notification_sent_at", "created_at",
}

func TestAuthenticateAPIKey_DBError(t *testing.T) {
	repo, mock := newTestAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnError(errors.New("db error"))

	key, err := authenticateAPIKey(context.Background(), "some-key", "prefix", repo)
	if err == nil {
		t.Error("expected error")
	}
	if key != nil {
		t.Error("expected nil key on error")
	}
}

func TestAuthenticateAPIKey_NoKeysFound(t *testing.T) {
	repo, mock := newTestAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols))

	key, err := authenticateAPIKey(context.Background(), "some-key", "prefix", repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no keys found")
	}
}

func TestAuthenticateAPIKey_KeyDoesNotMatch(t *testing.T) {
	repo, mock := newTestAPIKeyRepo(t)
	// Use a hash that won't match "some-key"
	badHash := "$2a$04$notarealhashatall"
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", "user-1", "org-1", "Test Key", nil, badHash, "prefix",
			[]byte(`["read"]`), nil, nil, nil, time.Now(),
		))

	key, err := authenticateAPIKey(context.Background(), "some-key", "prefix", repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when hash does not match")
	}
}

func TestAuthenticateAPIKey_KeyMatches(t *testing.T) {
	repo, mock := newTestAPIKeyRepo(t)

	// Generate a real bcrypt hash at minimum cost for speed
	providedKey := "tfr_test_secret"
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(providedKey), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	validHash := string(hashBytes)

	// Verify our own hash to ensure auth.ValidateAPIKey will return true
	if !auth.ValidateAPIKey(providedKey, validHash) {
		t.Fatalf("ValidateAPIKey returned false for our own hash")
	}

	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", "user-1", "org-1", "Test Key", nil, validHash, "prefix",
			[]byte(`["read"]`), nil, nil, nil, time.Now(),
		))

	key, err := authenticateAPIKey(context.Background(), providedKey, "prefix", repo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Error("expected key to be returned for matching hash")
	}
}

// ---------------------------------------------------------------------------
// AuthMiddleware with mocked repos (API key paths)
// ---------------------------------------------------------------------------

func newAuthRouterWithRepos(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	repo, mock := newTestAPIKeyRepo(t)

	r := gin.New()
	r.Use(AuthMiddleware(nil, nil, repo, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return mock, r
}

func TestAuthMiddleware_APIKeyDBError(t *testing.T) {
	mock, r := newAuthRouterWithRepos(t)
	// GetAPIKeysByPrefix will be called with prefix = token[:10]
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnError(errors.New("db error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-token-12345")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAuthMiddleware_APIKeyNotFound(t *testing.T) {
	mock, r := newAuthRouterWithRepos(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-token-12345")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_ExpiredAPIKey(t *testing.T) {
	mock, r := newAuthRouterWithRepos(t)

	// Generate a valid bcrypt hash matching our token
	token := "tfr_test_expired"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)

	// Create an expired time
	expiredAt := time.Now().Add(-time.Hour)

	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", "user-1", "org-1", "Test Key", nil, validHash, "tfr_test_",
			[]byte(`["read"]`), &expiredAt, nil, nil, time.Now(),
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// AuthMiddleware — JWT path
// ---------------------------------------------------------------------------

func TestAuthMiddleware_JWT_ValidUser(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, orgMock := newOrgRepo(t)
	r := newAuthRouterWithJWT(t, userMock, orgMock, userRepo, orgRepo)

	token := generateTestJWT(t, "user-1")

	// GetUserByID returns a user
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-1", "test@example.com", "Test User", nil, time.Now(), time.Now()))

	// GetUserCombinedScopes → GetUserMemberships returns empty (no org memberships)
	orgMock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(jwtMembershipCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: JWT valid user", w.Code)
	}
}

func TestAuthMiddleware_JWT_UserNotFound(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	r := newAuthRouterWithJWT(t, userMock, nil, userRepo, orgRepo)

	token := generateTestJWT(t, "nonexistent-user")

	// GetUserByID returns nil (no rows = user not found)
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: user not found", w.Code)
	}
}

func TestAuthMiddleware_JWT_DBError(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	r := newAuthRouterWithJWT(t, userMock, nil, userRepo, orgRepo)

	token := generateTestJWT(t, "user-1")

	// GetUserByID returns DB error → 500
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnError(errors.New("db error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: DB error loading user", w.Code)
	}
}

func TestAuthMiddleware_JWT_WithScopes(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, orgMock := newOrgRepo(t)
	r := newAuthRouterWithJWT(t, userMock, orgMock, userRepo, orgRepo)

	token := generateTestJWT(t, "user-1")

	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-1", "admin@example.com", "Admin", nil, time.Now(), time.Now()))

	orgMock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(jwtMembershipCols).AddRow(
			"org-1", "default", nil, time.Now(),
			"admin", "Admin", []byte(`["admin"]`),
		))

	// Also register a route that checks scopes (noop, just demonstrates scopes are set)
	r.GET("/check", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// AuthMiddleware — API key with valid user (loads user from userRepo)
// ---------------------------------------------------------------------------

func TestAuthMiddleware_APIKeyWithUser(t *testing.T) {
	// Create separate mocks for each repo
	apiKeyDB, apiKeyMock, _ := sqlmock.New()
	t.Cleanup(func() { apiKeyDB.Close() })
	apiKeyRepo := repositories.NewAPIKeyRepository(apiKeyDB)

	userDB, userMock, _ := sqlmock.New()
	t.Cleanup(func() { userDB.Close() })
	userRepo := repositories.NewUserRepository(userDB)

	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, apiKeyRepo, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_apikey_test123"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-1"

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", &userID, "org-1", "Test Key", nil, validHash, "tfr_apikey",
			[]byte(`["modules:read"]`), nil, nil, nil, time.Now(),
		))

	// userRepo.GetUserByID loads the user linked to the API key
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-1", "test@example.com", "Test User", nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: API key with user load", w.Code)
	}
}

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware — authenticated paths (JWT + API key)
// Unlike AuthMiddleware these must always return 200 regardless of auth status.
// ---------------------------------------------------------------------------

func TestOptionalAuthMiddleware_ValidJWT_SetsUser(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, orgMock := newOrgRepo(t)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := generateTestJWT(t, "user-1")

	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-1", "test@example.com", "Test User", nil, time.Now(), time.Now()))

	orgMock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(jwtMembershipCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth always passes through)", w.Code)
	}
}

// Issue #559 finding [4]: a revoked token must not silently grant identity on
// the optional-auth path — assert it falls through as unauthenticated instead
// of setting user context (unlike AuthMiddleware, which aborts with 401).
func TestOptionalAuthMiddleware_JWTRevoked_ContinuesUnauthenticated(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	tokenRepo, tokenMock := newTokenRepo(t)

	token := generateTestJWT(t, "user-1")

	tokenMock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	var userWasSet bool
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo, tokenRepo, nil, nil))
	r.GET("/", func(c *gin.Context) {
		_, userWasSet = c.Get("user")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth always passes through)", w.Code)
	}
	if userWasSet {
		t.Error("user should not be set in context for a revoked token")
	}
	_ = userMock // user lookup is not expected to run — revocation check short-circuits first
}

func TestOptionalAuthMiddleware_ValidJWT_UserNotFound_PassesThrough(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := generateTestJWT(t, "nonexistent-user")

	// User not found — optional middleware continues without aborting
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (user not found should not abort)", w.Code)
	}
}

func TestOptionalAuthMiddleware_APIKey_Valid_SetsContext(t *testing.T) {
	apiKeyDB, apiKeyMock, _ := sqlmock.New()
	t.Cleanup(func() { apiKeyDB.Close() })
	apiKeyRepo := repositories.NewAPIKeyRepository(apiKeyDB)

	userDB, userMock, _ := sqlmock.New()
	t.Cleanup(func() { userDB.Close() })
	userRepo := repositories.NewUserRepository(userDB)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, apiKeyRepo, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_optional_test9"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-2"

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-2", &userID, "org-1", "CI Key", nil, validHash, "tfr_optio",
			[]byte(`["modules:read"]`), nil, nil, nil, time.Now(),
		))

	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-2", "ci@example.com", "CI Bot", nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (valid optional API key)", w.Code)
	}
}

func TestOptionalAuthMiddleware_APIKey_Expired_PassesThrough(t *testing.T) {
	apiKeyDB, apiKeyMock, _ := sqlmock.New()
	t.Cleanup(func() { apiKeyDB.Close() })
	apiKeyRepo := repositories.NewAPIKeyRepository(apiKeyDB)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, nil, apiKeyRepo, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_expired_key9"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-3"
	expiredAt := time.Now().Add(-time.Hour)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-3", &userID, "org-1", "Expired Key", nil, validHash, "tfr_expir",
			[]byte(`["modules:read"]`), &expiredAt, nil, nil, time.Now(),
		))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	// Expired key — optional auth passes through rather than aborting
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (expired key should not abort in optional middleware)", w.Code)
	}
}

func TestOptionalAuthMiddleware_APIKey_NoMatch_PassesThrough(t *testing.T) {
	apiKeyDB, apiKeyMock, _ := sqlmock.New()
	t.Cleanup(func() { apiKeyDB.Close() })
	apiKeyRepo := repositories.NewAPIKeyRepository(apiKeyDB)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, nil, apiKeyRepo, nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Return empty rows — no matching key
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt-and-no-match00")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no key found, passes through)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// JWT revocation paths
// ---------------------------------------------------------------------------

func newTokenRepo(t *testing.T) (*repositories.TokenRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (token): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewTokenRepository(db), mock
}

// newAuthRouterWithRevocation builds a router with AuthMiddleware wired to a real tokenRepo.
func newAuthRouterWithRevocation(t *testing.T,
	userRepo *repositories.UserRepository, userMock sqlmock.Sqlmock,
	orgRepo *repositories.OrganizationRepository,
	tokenRepo *repositories.TokenRepository,
) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, tokenRepo, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestAuthMiddleware_JWTRevoked(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	tokenRepo, tokenMock := newTokenRepo(t)

	token := generateTestJWT(t, "user-1")

	// IsTokenRevoked returns true
	tokenMock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	// userRepo not called (aborted before)
	_ = userMock

	r := newAuthRouterWithRevocation(t, userRepo, userMock, orgRepo, tokenRepo)

	if code := doAuthRequest(r, "Bearer "+token); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (revoked token)", code)
	}
}

func TestAuthMiddleware_JWTRevocationDBError(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	tokenRepo, tokenMock := newTokenRepo(t)

	token := generateTestJWT(t, "user-1")

	// IsTokenRevoked returns a DB error
	tokenMock.ExpectQuery("SELECT EXISTS").
		WillReturnError(errors.New("db error"))

	_ = userMock

	r := newAuthRouterWithRevocation(t, userRepo, userMock, orgRepo, tokenRepo)

	if code := doAuthRequest(r, "Bearer "+token); code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (revocation DB error)", code)
	}
}

// ---------------------------------------------------------------------------
// Per-user revoke-all watermark (issue #559 finding [9])
//
// Unlike JTI revocation (a denylist of specific tokens), the watermark
// invalidates every token issued to a user before a point in time — used when
// a member's role template changes, a member is removed from an organization,
// or a role template's scopes are edited, none of which have a JTI to revoke
// individually.
// ---------------------------------------------------------------------------

func newUserRevocationRepo(t *testing.T) (*repositories.UserTokenRevocationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (user revocation): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewUserTokenRevocationRepository(db), mock
}

func TestAuthMiddleware_RevokeAllWatermark_Aborts(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	userRevocations, revMock := newUserRevocationRepo(t)

	token := generateTestJWT(t, "user-1")

	revMock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	_ = userMock // user lookup is not expected to run — the watermark check aborts first

	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, userRevocations, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	if code := doAuthRequest(r, "Bearer "+token); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (token predates revoke-all watermark)", code)
	}
}

func TestAuthMiddleware_RevokeAllWatermark_DBError(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	userRevocations, revMock := newUserRevocationRepo(t)

	token := generateTestJWT(t, "user-1")

	revMock.ExpectQuery("SELECT EXISTS").
		WillReturnError(errors.New("db error"))
	_ = userMock

	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, userRevocations, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	if code := doAuthRequest(r, "Bearer "+token); code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (watermark check DB error)", code)
	}
}

func TestAuthMiddleware_RevokeAllWatermark_NotRevoked_PassesThrough(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	userRevocations, revMock := newUserRevocationRepo(t)

	token := generateTestJWT(t, "user-1")

	revMock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).AddRow(
			"user-1", "test@example.com", "Test User", nil, time.Now(), time.Now()))

	r := gin.New()
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, userRevocations, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	if code := doAuthRequest(r, "Bearer "+token); code != http.StatusOK {
		t.Errorf("status = %d, want 200 (token postdates watermark)", code)
	}
}

func TestOptionalAuthMiddleware_RevokeAllWatermark_ContinuesUnauthenticated(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)
	userRevocations, revMock := newUserRevocationRepo(t)

	token := generateTestJWT(t, "user-1")

	revMock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo, nil, userRevocations, nil))
	var userWasSet bool
	r.GET("/", func(c *gin.Context) {
		_, userWasSet = c.Get("user")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (optional auth always passes through)", w.Code)
	}
	if userWasSet {
		t.Error("user should not be set in context for a token predating the revoke-all watermark")
	}
	_ = userMock // user lookup is not expected to run — the watermark check short-circuits first
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AuthMiddleware / OptionalAuthMiddleware — an organization-bound API key is
// re-derived where the binding is ESTABLISHED, not only where the namespace
// authorizer happens to look (issues #732, #736).
//
// api_keys freezes organization_id AND scopes at creation, and the middleware
// copies both into the request context for every route. The re-verification
// used to live only inside NamespaceAuthorizer.authorizeOrgAccess, which wraps
// module/provider mutations and nothing else, so every other authenticated
// route — the admin surface, /apikeys, SCIM — consumed the frozen snapshot with
// no check at all.
// ---------------------------------------------------------------------------

var memberWithRoleCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

// expectKeyOwnerMembership queues the GetMemberWithRole lookup the middleware
// now makes for an org-bound key. A nil scopes slice means "no such member".
func expectKeyOwnerMembership(mock sqlmock.Sqlmock, orgID, userID string, roleScopes []byte) {
	q := mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN")
	if roleScopes == nil {
		// No membership: the store answers ErrNotFound and the accessor returns
		// before it ever asks registry's tables, so no mirrored read follows.
		q.WillReturnRows(sqlmock.NewRows(memberWithRoleCols))
		return
	}
	q.WillReturnRows(sqlmock.NewRows(memberWithRoleCols).AddRow(
		orgID, userID, "rt-1", time.Now(),
		"Test User", "test@example.com",
		"viewer", "Viewer", roleScopes))
	// Same template, same scopes: the membership this fixture describes is
	// unchanged, only the table the ROLE half of it is read from.
	expectRegistryRoleFor(mock, "rt-1", "viewer", "Viewer", roleScopes)
}

// ---------------------------------------------------------------------------
// Registry's own role tables (sethbacon/terraform-suite-identity#206, phase 3b)
//
// repositories.OrganizationRepository still asks the shared identity store for
// the membership FACT -- which is what every `organization_members` expectation
// in this package supplies, and why none of them may be dropped -- and then
// issues ONE MORE query against registry's own `organization_member_roles` /
// `registry_role_templates`, returning THAT role. So a fixture that seeds a
// member row has to seed the mirrored role immediately after it, on the same
// mock, in the same order.
//
// The mirrored row must carry the SAME role_template_id and the SAME scopes as
// the identity row it follows. A different value is the DIVERGENCE case:
// compareRole logs an ERROR and increments registry_role_read_divergence_total,
// and the authorization outcome silently becomes a statement about drift rather
// than about the access-control rule the test was written for.
// ---------------------------------------------------------------------------

// registryRoleCols is member_role_reader.go's mirroredRoleColumns projection:
// role_template_id (nullable), name, display_name, scopes (JSON array).
var registryRoleCols = []string{"role_template_id", "name", "display_name", "scopes"}

// expectRegistryRoleFor queues the single-membership read (MemberRoleReader
// .RoleFor) that follows GetMember and GetMemberWithRole -- and, through them,
// CheckMembership and GetUserScopesForOrg. A nil scopes slice means registry
// holds no mirrored row for the membership, which confers nothing.
func expectRegistryRoleFor(mock sqlmock.Sqlmock, roleTemplateID, name, displayName string, scopes []byte) {
	rows := sqlmock.NewRows(registryRoleCols)
	if scopes != nil {
		rows.AddRow(roleTemplateID, name, displayName, scopes)
	}
	mock.ExpectQuery(`SELECT omr\.role_template_id.*FROM organization_member_roles.*WHERE omr\.organization_id = \$1 AND omr\.user_id = \$2`).
		WillReturnRows(rows)
}

// registryRoleForOrg is one organization's mirrored role in a whole-user read.
type registryRoleForOrg struct {
	OrganizationID string
	RoleTemplateID string
	Name           string
	DisplayName    string
	Scopes         []byte
}

// expectRegistryRolesForUser queues the whole-user read (MemberRoleReader
// .RolesForUser) that follows GetUserMemberships -- and, through it,
// GetUserCombinedScopes and OrgScopeForUser. The store's own read runs first
// and this one only when that returned at least one membership, so pass one
// registryRoleForOrg per membership the store fixture seeded.
func expectRegistryRolesForUser(mock sqlmock.Sqlmock, roles ...registryRoleForOrg) {
	rows := sqlmock.NewRows(append([]string{"organization_id"}, registryRoleCols...))
	for _, role := range roles {
		rows.AddRow(role.OrganizationID, role.RoleTemplateID, role.Name, role.DisplayName, role.Scopes)
	}
	mock.ExpectQuery(`SELECT omr\.organization_id,.*FROM organization_member_roles.*WHERE omr\.user_id = \$1`).
		WillReturnRows(rows)
}

// apiKeyAuthRouter wires AuthMiddleware over mocked repositories and returns
// the router plus the api-key and org mocks. handler observes the resolved
// context.
func apiKeyAuthRouter(t *testing.T, handler gin.HandlerFunc) (*gin.Engine, sqlmock.Sqlmock, sqlmock.Sqlmock) {
	t.Helper()
	apiKeyDB, apiKeyMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (apikey): %v", err)
	}
	t.Cleanup(func() { apiKeyDB.Close() })
	userDB, userMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (user): %v", err)
	}
	t.Cleanup(func() { userDB.Close() })
	orgRepo, orgMock := newOrgRepo(t)

	// The user load only runs once the key survives re-verification, so it is
	// registered unconditionally and simply goes unused on the reject paths.
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(jwtUserCols).
			AddRow("user-1", "test@example.com", "Test User", nil, time.Now(), time.Now()))

	r := gin.New()
	r.Use(AuthMiddleware(nil, repositories.NewUserRepository(userDB),
		repositories.NewAPIKeyRepository(apiKeyDB), orgRepo, nil, nil, nil))
	r.GET("/", handler)
	return r, apiKeyMock, orgMock
}

// expectAPIKeyLookup queues the prefix lookup that authenticates the bearer
// token, returning an org-bound key with the given owner and frozen scopes.
func expectAPIKeyLookup(mock sqlmock.Sqlmock, token string, userID *string, scopes []byte) {
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", userID, "org-1", "CI Key", nil, string(hashBytes), token[:10],
			scopes, nil, nil, nil, time.Now(),
		))
}

func doKeyRequest(r *gin.Engine, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	return w
}

// The headline case: the key's owner has been removed from the organization it
// is bound to. Nothing about the key itself changed, and no namespace
// middleware is in the chain, so before this the request was served with the
// full frozen scope set.
func TestAuthMiddleware_OrgBoundAPIKey_OwnerRemoved_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reached := false
	token := "tfr_stalekey_1"
	userID := "user-1"
	r, keyMock, orgMock := apiKeyAuthRouter(t, func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:write"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, nil)

	if w := doKeyRequest(r, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (owner is no longer a member): body=%s", w.Code, w.Body.String())
	}
	if reached {
		t.Error("the handler ran for a key whose owner had left the bound organization")
	}
}

// A key with no owning user is refused rather than treated as an organization
// service credential: identity.api_keys.user_id is ON DELETE SET NULL, so a
// userless row means the owner was deleted, not that a service account exists.
func TestAuthMiddleware_OrgBoundAPIKey_NoOwningUser_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	token := "tfr_orphaned_1"
	r, keyMock, _ := apiKeyAuthRouter(t, func(c *gin.Context) { c.Status(http.StatusOK) })
	expectAPIKeyLookup(keyMock, token, nil, []byte(`["modules:write"]`))
	// No membership lookup is registered: there is no owner to look up, and the
	// refusal must not depend on one.

	if w := doKeyRequest(r, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (userless key): body=%s", w.Code, w.Body.String())
	}
}

// The owner is still a member but has been downgraded. The key keeps working
// for what the owner still holds and loses exactly the scopes they lost — the
// frozen list is intersected with the current role template, by scope
// semantics rather than by string equality.
func TestAuthMiddleware_OrgBoundAPIKey_OwnerDowngraded_ScopesNarrowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got []string
	token := "tfr_downgrd_1"
	userID := "user-1"
	r, keyMock, orgMock := apiKeyAuthRouter(t, func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:read","modules:write"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, []byte(`["modules:read"]`))

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the key is still valid for what the owner retains): body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:read" {
		t.Errorf("scopes = %v, want [modules:read]: a downgraded owner's key must not keep serving the scope snapshot", got)
	}
}

// A member whose role template grants the admin wildcard keeps every scope on
// the key: the intersection is by scope semantics (auth.HasScope), not by set
// membership, so "admin" still covers "modules:write".
func TestAuthMiddleware_OrgBoundAPIKey_AdminRoleTemplate_KeepsScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got []string
	token := "tfr_adminky_1"
	userID := "user-1"
	r, keyMock, orgMock := apiKeyAuthRouter(t, func(c *gin.Context) {
		if v, ok := c.Get("scopes"); ok {
			got, _ = v.([]string)
		}
		c.Status(http.StatusOK)
	})
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:write"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, []byte(`["admin"]`))

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "modules:write" {
		t.Errorf("scopes = %v, want [modules:write]: an admin role template retains every key scope", got)
	}
}

// OptionalAuthMiddleware guards optionally-authenticated public endpoints, so a
// stale key must not abort the request — it must continue UNAUTHENTICATED, the
// same downgrade a revoked JWT gets. Private artifacts then stop resolving.
func TestOptionalAuthMiddleware_OrgBoundAPIKey_OwnerRemoved_ContinuesUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	apiKeyDB, keyMock, _ := sqlmock.New()
	t.Cleanup(func() { apiKeyDB.Close() })
	orgRepo, orgMock := newOrgRepo(t)

	var keyWasSet bool
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, nil, repositories.NewAPIKeyRepository(apiKeyDB), orgRepo, nil, nil, nil))
	r.GET("/", func(c *gin.Context) {
		_, keyWasSet = c.Get("api_key")
		c.Status(http.StatusOK)
	})

	token := "tfr_optstal_1"
	userID := "user-1"
	expectAPIKeyLookup(keyMock, token, &userID, []byte(`["modules:read"]`))
	expectKeyOwnerMembership(orgMock, "org-1", userID, nil)

	if w := doKeyRequest(r, token); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (optional auth always passes through): body=%s", w.Code, w.Body.String())
	}
	if keyWasSet {
		t.Error("a key whose owner had left the bound organization was still installed in the request context")
	}
}

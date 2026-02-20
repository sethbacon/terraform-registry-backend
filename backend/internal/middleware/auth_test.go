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
	r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func generateTestJWT(t *testing.T, userID string) string {
	t.Helper()
	token, err := auth.GenerateJWT(userID, "test@example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return token
}

// newAuthRouter builds a router with AuthMiddleware using nil repos.
// nil repos are safe for early-exit paths that abort before any repo call.
func newAuthRouter() *gin.Engine {
	r := gin.New()
	r.Use(AuthMiddleware(nil, nil, nil, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// newOptionalAuthRouter builds a router with OptionalAuthMiddleware using nil repos.
func newOptionalAuthRouter() *gin.Engine {
	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, nil, nil, nil))
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

func TestAuthMiddleware_MissingHeader(t *testing.T) {
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
	// "Bearer " with only whitespace → trimmed to empty → 401
	if code := doAuthRequest(newAuthRouter(), "Bearer   "); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
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

// GetAPIKeysByPrefix uses 11 columns (no user_name join)
var apiKeyPrefixCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "created_at",
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
			[]byte(`["read"]`), nil, nil, time.Now(),
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
			[]byte(`["read"]`), nil, nil, time.Now(),
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
	r.Use(AuthMiddleware(nil, nil, repo, nil))
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
			[]byte(`["read"]`), &expiredAt, nil, time.Now(),
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
	r.Use(AuthMiddleware(nil, userRepo, apiKeyRepo, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_apikey_test123"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-1"

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-1", &userID, "org-1", "Test Key", nil, validHash, "tfr_apikey",
			[]byte(`["modules:read"]`), nil, nil, time.Now(),
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
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo))
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

func TestOptionalAuthMiddleware_ValidJWT_UserNotFound_PassesThrough(t *testing.T) {
	userRepo, userMock := newUserRepo(t)
	orgRepo, _ := newOrgRepo(t)

	r := gin.New()
	r.Use(OptionalAuthMiddleware(nil, userRepo, nil, orgRepo))
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
	r.Use(OptionalAuthMiddleware(nil, userRepo, apiKeyRepo, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_optional_test9"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-2"

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-2", &userID, "org-1", "CI Key", nil, validHash, "tfr_optio",
			[]byte(`["modules:read"]`), nil, nil, time.Now(),
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
	r.Use(OptionalAuthMiddleware(nil, nil, apiKeyRepo, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := "tfr_expired_key9"
	hashBytes, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	validHash := string(hashBytes)
	userID := "user-3"
	expiredAt := time.Now().Add(-time.Hour)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyPrefixCols).AddRow(
			"key-3", &userID, "org-1", "Expired Key", nil, validHash, "tfr_expir",
			[]byte(`["modules:read"]`), &expiredAt, nil, time.Now(),
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
	r.Use(OptionalAuthMiddleware(nil, nil, apiKeyRepo, nil))
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

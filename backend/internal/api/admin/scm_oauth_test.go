package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"

	// Register the GitHub connector so that BuildConnector works for "github"
	// provider types in integration-style tests.
	_ "github.com/terraform-registry/terraform-registry/internal/scm/github"
)

func mustParseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		panic("mustParseUUID: " + err.Error())
	}
	return id
}

// ---------------------------------------------------------------------------
// Router helper for SCM OAuth handlers
// ---------------------------------------------------------------------------

func newSCMOAuthRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	r := gin.New()
	r.GET("/scm-providers/:id/oauth/authorize", h.InitiateOAuth)
	r.GET("/scm-providers/:id/oauth/callback", h.HandleOAuthCallback)
	r.DELETE("/scm-providers/:id/oauth/token", h.RevokeOAuth)
	r.POST("/scm-providers/:id/oauth/refresh", h.RefreshToken)
	r.POST("/scm-providers/:id/token", h.SavePATToken)
	r.GET("/scm-providers/:id/oauth/status", h.GetTokenStatus)
	r.GET("/scm-providers/:id/repositories", h.ListRepositories)

	return mock, r
}

// ---------------------------------------------------------------------------
// InitiateOAuth — early-exit paths
// ---------------------------------------------------------------------------

func TestInitiateOAuth_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/not-a-uuid/oauth/authorize", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestInitiateOAuth_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)
	// Valid UUID but no user_id in context → 401
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/authorize", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleOAuthCallback — early-exit paths
// ---------------------------------------------------------------------------

func TestHandleOAuthCallback_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/bad-uuid/oauth/callback?code=abc&state=x:y", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestHandleOAuthCallback_MissingCode(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/callback?state=x:y", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing code)", w.Code)
	}
}

func TestHandleOAuthCallback_InvalidState(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	// State without ":" → invalid format
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/callback?code=abc&state=badstate", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid state)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RevokeOAuth — early-exit paths
// ---------------------------------------------------------------------------

func TestRevokeOAuth_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		"/scm-providers/not-a-uuid/oauth/token", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestRevokeOAuth_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/token", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken — early-exit paths
// ---------------------------------------------------------------------------

func TestRefreshToken_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/bad-uuid/oauth/refresh", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestRefreshToken_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/refresh", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SavePATToken — early-exit paths
// ---------------------------------------------------------------------------

func TestSavePATToken_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/bad-uuid/token", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestSavePATToken_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/00000000-0000-0000-0000-000000000001/token", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetTokenStatus — early-exit paths
// ---------------------------------------------------------------------------

func TestGetTokenStatus_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/bad-uuid/oauth/status", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestGetTokenStatus_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/00000000-0000-0000-0000-000000000001/oauth/status", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ListRepositories — early-exit paths
// ---------------------------------------------------------------------------

func TestListRepositories_InvalidProviderID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/bad-uuid/repositories", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID)", w.Code)
	}
}

func TestListRepositories_NoUserID(t *testing.T) {
	_, r := newSCMOAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/00000000-0000-0000-0000-000000000001/repositories", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// NewSCMOAuthHandlers
// ---------------------------------------------------------------------------

func TestNewSCMOAuthHandlers(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)
	if h == nil {
		t.Fatal("NewSCMOAuthHandlers returned nil")
	}
}

// ---------------------------------------------------------------------------
// GetTokenStatus — with token found (covered path)
// ---------------------------------------------------------------------------

var scmOAuthTokenCols = []string{
	"id", "user_id", "scm_provider_id", "access_token_encrypted",
	"refresh_token_encrypted", "token_type", "expires_at", "scopes",
	"created_at", "updated_at",
}

func TestGetTokenStatus_TokenFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	providerID := "00000000-0000-0000-0000-000000000001"
	userUUID := "00000000-0000-0000-0000-000000000002"

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userUUID) // string UUID
		c.Next()
	})
	r.GET("/scm-providers/:id/oauth/status", h.GetTokenStatus)

	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols).AddRow(
			"00000000-0000-0000-0000-000000000010",
			userUUID,
			providerID,
			"encrypted-token",
			nil,
			"bearer",
			nil,
			nil,
			time.Now(),
			time.Now(),
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+providerID+"/oauth/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (token found): body=%s", w.Code, w.Body.String())
	}
}

func TestGetTokenStatus_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	providerID := "00000000-0000-0000-0000-000000000001"
	userUUID := "00000000-0000-0000-0000-000000000002"

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userUUID)
		c.Next()
	})
	r.GET("/scm-providers/:id/oauth/status", h.GetTokenStatus)

	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+providerID+"/oauth/status", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (DB error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// InitiateOAuth — provider DB paths
// ---------------------------------------------------------------------------

func newSCMOAuthRouterWithUser(t *testing.T, userUUID string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userUUID)
		c.Next()
	})
	r.GET("/scm-providers/:id/oauth/authorize", h.InitiateOAuth)
	r.GET("/scm-providers/:id/oauth/callback", h.HandleOAuthCallback)
	r.POST("/scm-providers/:id/token", h.SavePATToken)
	return mock, r
}

const oauthUserUUID = "00000000-0000-0000-0000-000000000002"
const oauthProviderID = "00000000-0000-0000-0000-000000000001"

func oauthSCMProviderRow(providerType string) *sqlmock.Rows {
	return sqlmock.NewRows(scmProvCols).AddRow(
		oauthProviderID, "00000000-0000-0000-0000-000000000000", providerType, "Test Provider",
		nil, nil, "client-id",
		"encrypted-secret", "webhook-secret",
		true, time.Now(), time.Now(),
	)
}

func TestInitiateOAuth_ProviderNotFound(t *testing.T) {
	mock, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols)) // empty → provider == nil → 404

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/authorize", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (provider not found)", w.Code)
	}
}

func TestInitiateOAuth_PATBasedProvider(t *testing.T) {
	// "bitbucket_dc" is PAT-based: IsPATBased() returns true.
	// InitiateOAuth returns 200 with auth_method="pat" without calling tokenCipher.
	mock, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRow("bitbucket_dc"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/authorize", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (PAT provider): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// HandleOAuthCallback — additional paths
// ---------------------------------------------------------------------------

func TestHandleOAuthCallback_InvalidUserIDInState(t *testing.T) {
	// State has ":" but first part is not a UUID.
	_, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/callback?code=abc&state=not-a-uuid:providerid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid user ID in state)", w.Code)
	}
}

func TestHandleOAuthCallback_ProviderNotFound(t *testing.T) {
	mock, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)
	state := oauthUserUUID + ":" + oauthProviderID

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/callback?code=abc&state="+state, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (provider not found): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SavePATToken — additional paths
// ---------------------------------------------------------------------------

func TestSavePATToken_MissingBody(t *testing.T) {
	// Valid UUID + user_id but empty body → ShouldBindJSON fails → 400.
	_, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing body)", w.Code)
	}
}

func TestSavePATToken_ProviderNotFound(t *testing.T) {
	mock, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	body := strings.NewReader(`{"access_token":"mytoken"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (provider not found): body=%s", w.Code, w.Body.String())
	}
}

func TestSavePATToken_NotPATBasedProvider(t *testing.T) {
	// "github" uses OAuth, not PAT → 400 when SavePATToken is called.
	mock, r := newSCMOAuthRouterWithUser(t, oauthUserUUID)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRow("github"))

	body := strings.NewReader(`{"access_token":"mytoken"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (not PAT-based provider): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RevokeOAuth — token found and deleted
// ---------------------------------------------------------------------------

func TestRevokeOAuth_TokenDeleted(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	providerID := "00000000-0000-0000-0000-000000000001"
	userUUID := "00000000-0000-0000-0000-000000000002"

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userUUID)
		c.Next()
	})
	r.DELETE("/scm-providers/:id/oauth/token", h.RevokeOAuth)

	// RevokeOAuth calls DeleteUserToken directly (no SELECT first)
	mock.ExpectExec("DELETE FROM scm_oauth_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		"/scm-providers/"+providerID+"/oauth/token", nil))

	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 200 or 204 (revoke success): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// splitString helper — additional unit tests
// (base cases are in scm_oauth_helpers_test.go)
// ---------------------------------------------------------------------------

func TestSplitString_LeadingSeparator(t *testing.T) {
	// Leading separator should be ignored (no empty strings).
	result := splitString(",repo,admin", ",")
	want := []string{"repo", "admin"}
	if len(result) != len(want) {
		t.Fatalf("splitString got %d items, want %d: %v", len(result), len(want), result)
	}
	for i := range want {
		if result[i] != want[i] {
			t.Errorf("splitString[%d] = %q, want %q", i, result[i], want[i])
		}
	}
}

func TestSplitString_DifferentSeparator(t *testing.T) {
	result := splitString("a:b:c", ":")
	want := []string{"a", "b", "c"}
	if len(result) != len(want) {
		t.Fatalf("splitString got %d items, want %d: %v", len(result), len(want), result)
	}
	for i := range want {
		if result[i] != want[i] {
			t.Errorf("splitString[%d] = %q, want %q", i, result[i], want[i])
		}
	}
}

func TestSplitString_OnlySeparators(t *testing.T) {
	result := splitString(",,,", ",")
	if len(result) != 0 {
		t.Errorf("splitString(\",,,\", \",\") = %v, want empty slice", result)
	}
}

// ---------------------------------------------------------------------------
// Router helper with a real TokenCipher
// ---------------------------------------------------------------------------

func newSCMOAuthRouterWithCipher(t *testing.T, userUUID string, tc *crypto.TokenCipher) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	cfg := &config.Config{
		Server: config.ServerConfig{
			BaseURL: "http://localhost:8080",
		},
	}
	h := NewSCMOAuthHandlers(cfg, scmRepo, nil, tc)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userUUID)
		c.Next()
	})
	r.GET("/scm-providers/:id/oauth/authorize", h.InitiateOAuth)
	r.POST("/scm-providers/:id/token", h.SavePATToken)
	r.POST("/scm-providers/:id/oauth/refresh", h.RefreshToken)
	r.GET("/scm-providers/:id/oauth/status", h.GetTokenStatus)
	r.DELETE("/scm-providers/:id/oauth/token", h.RevokeOAuth)
	r.GET("/scm-providers/:id/repositories", h.ListRepositories)
	r.GET("/scm-providers/:id/repositories/:owner/:repo/tags", h.ListRepositoryTags)
	r.GET("/scm-providers/:id/repositories/:owner/:repo/branches", h.ListRepositoryBranches)
	return mock, r
}

// oauthCipher returns a test TokenCipher for SCM OAuth tests.
func oauthCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	tc, err := crypto.NewTokenCipher(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

// oauthSCMProviderRowEncrypted creates a provider row where client_secret_encrypted
// is encrypted with the given cipher so the handler can decrypt it.
func oauthSCMProviderRowEncrypted(t *testing.T, tc *crypto.TokenCipher, providerType string) *sqlmock.Rows {
	t.Helper()
	encSecret, err := tc.Seal("test-client-secret")
	if err != nil {
		t.Fatalf("tc.Seal: %v", err)
	}
	return sqlmock.NewRows(scmProvCols).AddRow(
		oauthProviderID, "00000000-0000-0000-0000-000000000000", providerType, "Test Provider",
		nil, nil, "test-client-id",
		encSecret, "webhook-secret",
		true, time.Now(), time.Now(),
	)
}

// ---------------------------------------------------------------------------
// SavePATToken — success path (PAT-based provider, cipher, save succeeds)
// ---------------------------------------------------------------------------

func TestSavePATToken_Success(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetProvider returns a bitbucket_dc (PAT-based) provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "bitbucket_dc"))

	// GetUserToken returns no existing token (sql.ErrNoRows → nil, nil)
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	// SaveUserToken — INSERT … ON CONFLICT
	mock.ExpectExec("INSERT INTO scm_oauth_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := strings.NewReader(`{"access_token":"my-pat-token"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (SavePATToken success): body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Personal Access Token saved") {
		t.Errorf("body does not contain expected message: %s", w.Body.String())
	}
}

func TestSavePATToken_SuccessUpdate(t *testing.T) {
	// When a token already exists, it should upsert (update) the token.
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "bitbucket_dc"))

	// GetUserToken returns an existing token
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols).AddRow(
			"00000000-0000-0000-0000-000000000010",
			oauthUserUUID,
			oauthProviderID,
			"old-encrypted-token",
			nil,
			"pat",
			nil,
			nil,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(-24*time.Hour),
		))

	// SaveUserToken — INSERT … ON CONFLICT → updates
	mock.ExpectExec("INSERT INTO scm_oauth_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := strings.NewReader(`{"access_token":"my-new-pat-token"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (SavePATToken upsert): body=%s", w.Code, w.Body.String())
	}
}

func TestSavePATToken_CheckExistingTokenDBError(t *testing.T) {
	// When GetUserToken returns an error, the handler should return 500.
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "bitbucket_dc"))

	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnError(errDB)

	body := strings.NewReader(`{"access_token":"my-pat-token"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (DB error on GetUserToken): body=%s", w.Code, w.Body.String())
	}
}

func TestSavePATToken_SaveDBError(t *testing.T) {
	// When SaveUserToken returns an error, the handler should return 500.
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "bitbucket_dc"))

	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	mock.ExpectExec("INSERT INTO scm_oauth_tokens").
		WillReturnError(errDB)

	body := strings.NewReader(`{"access_token":"my-pat-token"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/token", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (DB error on SaveUserToken): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetTokenStatus — no token found → connected=false
// ---------------------------------------------------------------------------

func TestGetTokenStatus_NoToken(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetUserToken returns no rows → nil, nil
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/status", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if connected, ok := resp["connected"].(bool); !ok || connected {
		t.Errorf("connected = %v, want false", resp["connected"])
	}
}

// ---------------------------------------------------------------------------
// GetTokenStatus — token found with scopes and expires_at
// ---------------------------------------------------------------------------

func TestGetTokenStatus_TokenFoundWithScopesAndExpiry(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	expiresAt := time.Now().Add(1 * time.Hour)
	scopes := "repo,read:user"

	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols).AddRow(
			"00000000-0000-0000-0000-000000000010",
			oauthUserUUID,
			oauthProviderID,
			"encrypted-token",
			nil,
			"bearer",
			expiresAt,
			scopes,
			time.Now(),
			time.Now(),
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/status", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if connected, ok := resp["connected"].(bool); !ok || !connected {
		t.Errorf("connected = %v, want true", resp["connected"])
	}
	if resp["token_type"] != "bearer" {
		t.Errorf("token_type = %v, want \"bearer\"", resp["token_type"])
	}
}

// ---------------------------------------------------------------------------
// RevokeOAuth — DB error on delete
// ---------------------------------------------------------------------------

func TestRevokeOAuth_DBError(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	mock.ExpectExec("DELETE FROM scm_oauth_tokens").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		"/scm-providers/"+oauthProviderID+"/oauth/token", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (delete DB error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RefreshToken — token not found
// ---------------------------------------------------------------------------

func TestRefreshToken_TokenNotFound(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetUserToken returns empty result → nil, nil → 404
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/oauth/refresh", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (token not found): body=%s", w.Code, w.Body.String())
	}
}

func TestRefreshToken_ProviderNotFound(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	encToken, _ := tc.Seal("access-token")

	// GetUserToken returns a token
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols).AddRow(
			"00000000-0000-0000-0000-000000000010",
			oauthUserUUID,
			oauthProviderID,
			encToken,
			nil,
			"bearer",
			nil,
			nil,
			time.Now(),
			time.Now(),
		))

	// GetProvider returns empty → provider not found → 404
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/oauth/refresh", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (provider not found): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// InitiateOAuth — success path for OAuth provider (GitHub)
// ---------------------------------------------------------------------------

func TestInitiateOAuth_OAuthProviderSuccess(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// Return a GitHub (OAuth-based) provider with a properly encrypted client secret.
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "github"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/authorize", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (OAuth success): body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	authURL, ok := resp["authorization_url"].(string)
	if !ok || authURL == "" {
		t.Errorf("authorization_url missing or empty in response: %v", resp)
	}
	if _, ok := resp["state"].(string); !ok {
		t.Errorf("state missing in response: %v", resp)
	}
	// Verify the state format is "userID:providerID"
	expectedState := fmt.Sprintf("%s:%s", oauthUserUUID, oauthProviderID)
	if resp["state"] != expectedState {
		t.Errorf("state = %q, want %q", resp["state"], expectedState)
	}
}

// ---------------------------------------------------------------------------
// ListRepositories — provider not found path (with user)
// ---------------------------------------------------------------------------

func TestListRepositories_ProviderNotFound(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetProvider returns empty → 404
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (provider not found): body=%s", w.Code, w.Body.String())
	}
}

func TestListRepositories_NotConnected(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetProvider returns a valid provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "github"))

	// GetUserToken returns empty → not connected
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (not connected): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListRepositoryTags — early-exit paths
// ---------------------------------------------------------------------------

func TestListRepositoryTags_InvalidProviderID(t *testing.T) {
	tc := oauthCipher(t)
	_, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/bad-uuid/repositories/owner/repo/tags", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID): body=%s", w.Code, w.Body.String())
	}
}

func TestListRepositoryTags_NoUserID(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	r := gin.New()
	// No user_id middleware
	r.GET("/scm-providers/:id/repositories/:owner/:repo/tags", h.ListRepositoryTags)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories/owner/repo/tags", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id): body=%s", w.Code, w.Body.String())
	}
}

func TestListRepositoryTags_MissingOwnerOrRepo(t *testing.T) {
	// Gin will not match a route with empty path segments, so the endpoint
	// returns 404 for missing owner/repo. Instead, test the buildConnectorWithToken
	// error path by having GetProvider return empty.
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetProvider returns empty → buildConnectorWithToken returns error
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	// GetUserToken won't be called because GetProvider fails first

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories/myowner/myrepo/tags", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (buildConnectorWithToken error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListRepositoryBranches — early-exit paths
// ---------------------------------------------------------------------------

func TestListRepositoryBranches_InvalidProviderID(t *testing.T) {
	tc := oauthCipher(t)
	_, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/bad-uuid/repositories/owner/repo/branches", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid UUID): body=%s", w.Code, w.Body.String())
	}
}

func TestListRepositoryBranches_NoUserID(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, nil)

	r := gin.New()
	// No user_id middleware
	r.GET("/scm-providers/:id/repositories/:owner/:repo/branches", h.ListRepositoryBranches)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories/owner/repo/branches", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id): body=%s", w.Code, w.Body.String())
	}
}

func TestListRepositoryBranches_BuildConnectorError(t *testing.T) {
	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	// GetProvider returns empty → buildConnectorWithToken returns error
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/repositories/myowner/myrepo/branches", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (buildConnectorWithToken error): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// getUserIDFromContext — coverage for uuid.UUID type via HTTP handler
// ---------------------------------------------------------------------------

func TestGetTokenStatus_UserIDAsUUIDType(t *testing.T) {
	// The existing tests pass user_id as a string. This test passes it as
	// a uuid.UUID to exercise the uuid.UUID case via an HTTP handler flow.
	tc := oauthCipher(t)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock"))
	h := NewSCMOAuthHandlers(&config.Config{}, scmRepo, nil, tc)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Set user_id as uuid.UUID, not string
		c.Set("user_id", mustParseUUID(oauthUserUUID))
		c.Next()
	})
	r.GET("/scm-providers/:id/oauth/status", h.GetTokenStatus)

	// GetUserToken returns empty → connected=false
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/scm-providers/"+oauthProviderID+"/oauth/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (UUID type user_id): body=%s", w.Code, w.Body.String())
	}
}

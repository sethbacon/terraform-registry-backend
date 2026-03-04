package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

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

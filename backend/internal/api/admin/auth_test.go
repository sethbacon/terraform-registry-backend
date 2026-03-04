package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newAuthRouter(t *testing.T) (*AuthHandlers, sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{}
	// OIDC and AzureAD disabled (zero values)

	h, err := NewAuthHandlers(cfg, db, nil)
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}

	r := gin.New()
	r.GET("/auth/login", h.LoginHandler())
	r.GET("/auth/callback", h.CallbackHandler())
	r.GET("/auth/refresh", h.RefreshHandler())
	r.GET("/auth/me", h.MeHandler())

	return h, mock, r
}

// ---------------------------------------------------------------------------
// NewAuthHandlers
// ---------------------------------------------------------------------------

func TestNewAuthHandlers_NilProviders(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{} // OIDC and AzureAD disabled
	h, err := NewAuthHandlers(cfg, db, nil)
	if err != nil {
		t.Fatalf("NewAuthHandlers error: %v", err)
	}
	if h == nil {
		t.Fatal("NewAuthHandlers returned nil")
	}
}

// ---------------------------------------------------------------------------
// LoginHandler — early-exit paths (no provider configured)
// ---------------------------------------------------------------------------

func TestLoginHandler_OIDCNotConfigured(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=oidc", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (OIDC not configured)", w.Code)
	}
}

func TestLoginHandler_AzureADNotConfigured(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=azuread", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (AzureAD not configured)", w.Code)
	}
}

func TestLoginHandler_InvalidProvider(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=unknown", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid provider)", w.Code)
	}
}

func TestLoginHandler_DefaultProviderOIDC(t *testing.T) {
	_, _, r := newAuthRouter(t)

	// No provider query → defaults to "oidc" → not configured → 400
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (default OIDC not configured)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CallbackHandler — early-exit paths
// ---------------------------------------------------------------------------

func TestCallbackHandler_InvalidState(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=nonexistent", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid state)", w.Code)
	}
}

func TestCallbackHandler_ExpiredState(t *testing.T) {
	_, _, r := newAuthRouter(t)
	h := r.Routes()[2].HandlerFunc // unused, access via handler directly

	// Add an expired session state manually
	_ = h
	// Instead, trigger via HTTP with known state
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=", nil))

	// Empty state → not found in store → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty state)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RefreshHandler — unauthenticated path
// ---------------------------------------------------------------------------

func TestRefreshHandler_NotAuthenticated(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/refresh", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id in context)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RefreshHandler — with user in context
// ---------------------------------------------------------------------------

var authUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func TestRefreshHandler_UserNotFound(t *testing.T) {
	_, mock, _ := newAuthRouter(t)
	db, mock2, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/refresh", h.RefreshHandler())

	// GetUserByID returns nil (no rows)
	mock2.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(authUserCols))
	_ = mock

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/refresh", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (user not found)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// MeHandler — unauthenticated path
// ---------------------------------------------------------------------------

func TestMeHandler_NotAuthenticated(t *testing.T) {
	_, _, r := newAuthRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no user_id in context)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// MeHandler — with user in context
// ---------------------------------------------------------------------------

var meUserWithOrgRolesCols = []string{
	"id", "email", "name", "oidc_sub", "created_at", "updated_at",
}

func TestMeHandler_UserNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/me", h.MeHandler())

	// GetUserWithOrgRoles → returns nil
	mock.ExpectQuery("SELECT.*FROM users").
		WillReturnRows(sqlmock.NewRows(meUserWithOrgRolesCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	// User not found → 404
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (user not found): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// generateState (via LoginHandler, indirectly)
// ---------------------------------------------------------------------------

func TestGenerateState_NotEmpty(t *testing.T) {
	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState() error: %v", err)
	}
	if state == "" {
		t.Error("generateState() returned empty string")
	}
	if len(state) < 32 {
		t.Errorf("generateState() length = %d, want >= 32", len(state))
	}
}

func TestGenerateState_Unique(t *testing.T) {
	s1, _ := generateState()
	s2, _ := generateState()
	if s1 == s2 {
		t.Error("generateState() returned same value twice (not unique)")
	}
}

// ---------------------------------------------------------------------------
// Expired session cleanup (tests that CallbackHandler checks expiry)
// ---------------------------------------------------------------------------

func TestCallbackHandler_ExpiredSession(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	// Manually inject an expired session into the store
	expiredState := "test-expired-state"
	h.sessionStore[expiredState] = &SessionState{
		State:        expiredState,
		CreatedAt:    time.Now().Add(-20 * time.Minute), // 20 minutes old
		ProviderType: "oidc",
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=testcode&state="+expiredState, nil))

	// Expired session → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (expired session state)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// MeHandler — success path (user found, no memberships)
// ---------------------------------------------------------------------------

var meOrgMembershipCols = []string{
	"organization_id", "organization_name",
	"role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func TestMeHandler_Success_NoMemberships(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/me", h.MeHandler())

	// GetUserByID (called by GetUserWithOrgRoles)
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("user-1", "me@example.com", "Me User", nil, time.Now(), time.Now()))
	// Memberships query returns empty
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(meOrgMembershipCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (MeHandler success): body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["user"] == nil {
		t.Error("response missing 'user'")
	}
}

func TestMeHandler_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/me", h.MeHandler())

	// GetUserByID returns error
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RefreshHandler — success path
// ---------------------------------------------------------------------------

func TestRefreshHandler_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/refresh", h.RefreshHandler())

	// GetUserByID returns a user
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("user-1", "refresh@example.com", "Refresh User", nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/refresh", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (refresh success): body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["token"] == nil {
		t.Error("response missing 'token'")
	}
}

// ---------------------------------------------------------------------------
// deriveFrontendURL
// ---------------------------------------------------------------------------

func TestDeriveFrontendURL_PublicURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://app.example.com/"
	got := deriveFrontendURL(cfg)
	if got != "https://app.example.com" {
		t.Errorf("deriveFrontendURL = %q, want %q", got, "https://app.example.com")
	}
}

func TestDeriveFrontendURL_OIDCRedirectURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.OIDC.RedirectURL = "https://app.example.com/api/v1/auth/callback"
	got := deriveFrontendURL(cfg)
	if got != "https://app.example.com" {
		t.Errorf("deriveFrontendURL = %q, want %q", got, "https://app.example.com")
	}
}

func TestDeriveFrontendURL_AzureADRedirectURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.AzureAD.RedirectURL = "https://azure.example.com/callback"
	got := deriveFrontendURL(cfg)
	if got != "https://azure.example.com" {
		t.Errorf("deriveFrontendURL = %q, want %q", got, "https://azure.example.com")
	}
}

func TestDeriveFrontendURL_BaseURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.BaseURL = "http://localhost:8080/"
	got := deriveFrontendURL(cfg)
	if got != "http://localhost:8080" {
		t.Errorf("deriveFrontendURL = %q, want %q", got, "http://localhost:8080")
	}
}

func TestDeriveFrontendURL_Empty(t *testing.T) {
	cfg := &config.Config{}
	got := deriveFrontendURL(cfg)
	if got != "" {
		t.Errorf("deriveFrontendURL = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// SetOIDCProvider
// ---------------------------------------------------------------------------

func TestSetOIDCProvider_Nil(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	h, _ := NewAuthHandlers(&config.Config{}, db, nil)
	h.SetOIDCProvider(nil)

	if got := h.oidcProvider.Load(); got != nil {
		t.Error("expected oidcProvider to be nil after SetOIDCProvider(nil)")
	}
}

// ---------------------------------------------------------------------------
// resolveGroupClaimName — nil repo falls back to cfg
// ---------------------------------------------------------------------------

func TestResolveGroupClaimName_NilRepo_UsesConfig(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupClaimName = "groups"
	h, _ := NewAuthHandlers(cfg, db, nil)

	got := h.resolveGroupClaimName(context.Background())
	if got != "groups" {
		t.Errorf("resolveGroupClaimName = %q, want %q", got, "groups")
	}
}

func TestResolveGroupClaimName_NilRepo_Empty(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	h, _ := NewAuthHandlers(&config.Config{}, db, nil)
	got := h.resolveGroupClaimName(context.Background())
	if got != "" {
		t.Errorf("resolveGroupClaimName = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// resolveGroupMappingConfig — nil repo falls back to cfg
// ---------------------------------------------------------------------------

func TestResolveGroupMappingConfig_NilRepo(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupClaimName = "grps"
	cfg.Auth.OIDC.DefaultRole = "viewer"
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil)

	cn, mappings, dr := h.resolveGroupMappingConfig(context.Background())
	if cn != "grps" {
		t.Errorf("claimName = %q, want %q", cn, "grps")
	}
	if dr != "viewer" {
		t.Errorf("defaultRole = %q, want %q", dr, "viewer")
	}
	if len(mappings) != 1 || mappings[0].Group != "admins" {
		t.Errorf("mappings = %v, want [{admins acme admin}]", mappings)
	}
}

func TestResolveGroupMappingConfig_NilRepo_Empty(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	h, _ := NewAuthHandlers(&config.Config{}, db, nil)
	cn, mappings, dr := h.resolveGroupMappingConfig(context.Background())
	if cn != "" || dr != "" || len(mappings) != 0 {
		t.Errorf("expected empty values, got cn=%q dr=%q mappings=%v", cn, dr, mappings)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — early-exit when nothing configured
// ---------------------------------------------------------------------------

func TestApplyGroupMappings_NoMappingsNoDefaultRole(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	h, _ := NewAuthHandlers(&config.Config{}, db, nil)
	err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"})
	if err != nil {
		t.Errorf("applyGroupMappings: expected nil error, got %v", err)
	}
}

func TestApplyGroupMappings_EmptyGroupsNoDefault(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	// DefaultRole is empty, so unmatched users are not assigned to any org
	h, _ := NewAuthHandlers(cfg, db, nil)
	err := h.applyGroupMappings(context.Background(), "user-1", []string{})
	if err != nil {
		t.Errorf("applyGroupMappings: expected nil error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// LogoutHandler — nil OIDC provider, redirects to frontend home
// ---------------------------------------------------------------------------

func TestLogoutHandler_NoOIDC_RedirectsToHome(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://app.example.com"
	h, _ := NewAuthHandlers(cfg, db, nil)

	r := gin.New()
	r.GET("/auth/logout", h.LogoutHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://app.example.com/" {
		t.Errorf("Location = %q, want %q", loc, "https://app.example.com/")
	}
}

func TestLogoutHandler_BaseURL_Fallback(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Server.BaseURL = "http://localhost:8080"
	h, _ := NewAuthHandlers(cfg, db, nil)

	r := gin.New()
	r.GET("/auth/logout", h.LogoutHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "http://localhost:8080/" {
		t.Errorf("Location = %q, want %q", loc, "http://localhost:8080/")
	}
}

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
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

	h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	// Manually inject an expired session into the store
	expiredState := "test-expired-state"
	h.stateStore.Save(context.Background(), expiredState, &auth.SessionState{
		State:        expiredState,
		CreatedAt:    time.Now().Add(-20 * time.Minute), // 20 minutes old
		ProviderType: "oidc",
	}, time.Hour)

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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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

	h, _ := NewAuthHandlers(&config.Config{}, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	got := h.resolveGroupClaimName(context.Background())
	if got != "groups" {
		t.Errorf("resolveGroupClaimName = %q, want %q", got, "groups")
	}
}

func TestResolveGroupClaimName_NilRepo_Empty(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	h, _ := NewAuthHandlers(&config.Config{}, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

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

	h, _ := NewAuthHandlers(&config.Config{}, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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

	h, _ := NewAuthHandlers(&config.Config{}, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

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
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

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

// ---------------------------------------------------------------------------
// MeHandler — success path with memberships and role template
// ---------------------------------------------------------------------------

func TestMeHandler_SuccessWithMemberships(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r.GET("/auth/me", h.MeHandler())

	// GetUserByID
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("user-1", "member@example.com", "Member User", nil, time.Now(), time.Now()))
	// Memberships query returns one membership with role template
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(meOrgMembershipCols).
			AddRow("org-1", "acme", "role-1", time.Now(), "admin", "Administrator", `["admin","write","read"]`))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	memberships, ok := resp["memberships"].([]interface{})
	if !ok || len(memberships) != 1 {
		t.Fatalf("memberships = %v, want slice of length 1", resp["memberships"])
	}
	m := memberships[0].(map[string]interface{})
	if m["organization_name"] != "acme" {
		t.Errorf("organization_name = %v, want acme", m["organization_name"])
	}
	if m["role_template"] == nil {
		t.Error("role_template should not be nil for membership with role")
	}
	// Primary role template should be set for backward compatibility
	if resp["role_template"] == nil {
		t.Error("top-level role_template should not be nil")
	}
}

// ---------------------------------------------------------------------------
// CallbackHandler — unknown provider type in session
// ---------------------------------------------------------------------------

func TestCallbackHandler_UnknownProviderType(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	// Inject a session with unknown provider type
	h.stateStore.Save(context.Background(), "test-state", &auth.SessionState{
		State:        "test-state",
		CreatedAt:    time.Now(),
		ProviderType: "unknown",
	}, time.Hour)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state=test-state", nil))

	// Unknown provider → 400 (via callbackError with JSON since no frontendBase)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (unknown provider type): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CallbackHandler — OIDC provider not configured during callback
// ---------------------------------------------------------------------------

func TestCallbackHandler_OIDCProviderNotConfigured(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	h.stateStore.Save(context.Background(), "oidc-state", &auth.SessionState{
		State:        "oidc-state",
		CreatedAt:    time.Now(),
		ProviderType: "oidc",
	}, time.Hour)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state=oidc-state", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (OIDC not configured): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CallbackHandler — AzureAD provider not configured during callback
// ---------------------------------------------------------------------------

func TestCallbackHandler_AzureADProviderNotConfigured(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	h.stateStore.Save(context.Background(), "azure-state", &auth.SessionState{
		State:        "azure-state",
		CreatedAt:    time.Now(),
		ProviderType: "azuread",
	}, time.Hour)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state=azure-state", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (AzureAD not configured): body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CallbackHandler — error redirects to frontend when frontendBase is set
// ---------------------------------------------------------------------------

func TestCallbackHandler_ErrorRedirectsToFrontend(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://app.example.com"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	r := gin.New()
	r.GET("/auth/callback", h.CallbackHandler())

	// Invalid state with frontendBase configured → redirect to frontend error page
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/callback?code=abc&state=badstate", nil))

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect to frontend error)", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}
	if !strings.Contains(loc, "app.example.com") || !strings.Contains(loc, "error=") {
		t.Errorf("Location = %q, want redirect to app.example.com with error params", loc)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — group matches, adds new member
// ---------------------------------------------------------------------------

var authOrgCols = []string{"id", "name", "display_name", "created_at", "updated_at"}
var authMemberCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}

func TestApplyGroupMappings_MatchingGroup_AddMember(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "developers", Organization: "acme", Role: "editor"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetByName("acme") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-1", "acme", "Acme Corp", time.Now(), time.Now()))

	// CheckMembership → GetMember → not found (no rows)
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols))

	// AddMemberWithParams → lookup role template
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("editor").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))

	// AddMemberWithRoleTemplate → INSERT
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"developers"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — group matches, updates existing member
// ---------------------------------------------------------------------------

func TestApplyGroupMappings_MatchingGroup_UpdateMember(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetByName("acme") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-1", "acme", "Acme Corp", time.Now(), time.Now()))

	// CheckMembership → GetMember → found (is already a member)
	roleID := "rt-old"
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols).
			AddRow("org-1", "user-1", &roleID, time.Now()))

	// UpdateMemberRole → lookup role template
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin"))

	// UpdateMemberRoleTemplate → UPDATE
	mock.ExpectExec("UPDATE organization_members.*SET role_template_id").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — no match, default role fallback adds member
// ---------------------------------------------------------------------------

func TestApplyGroupMappings_DefaultRoleFallback(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	cfg.Auth.OIDC.DefaultRole = "viewer"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// No group matches → falls through to default role

	// GetDefaultOrganization → GetByName("default") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-default", "default", "Default Org", time.Now(), time.Now()))

	// CheckMembership → GetMember → not found
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols))

	// AddMemberWithParams → lookup role template
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("viewer").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-viewer"))

	// INSERT
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"unmatched-group"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — org not found, skips gracefully
// ---------------------------------------------------------------------------

func TestApplyGroupMappings_OrgNotFound_Skipped(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "devs", Organization: "nonexistent", Role: "editor"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetByName("nonexistent") → not found (no rows)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows(authOrgCols))

	// Skips gracefully — no error, no membership changes
	err := h.applyGroupMappings(context.Background(), "user-1", []string{"devs"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// resolveGroupClaimName / resolveGroupMappingConfig — with DB-backed oidcConfigRepo
// ---------------------------------------------------------------------------

// newOIDCConfigRepo creates an OIDCConfigRepository backed by a fresh sqlmock.
func newOIDCConfigRepo(t *testing.T) (*repositories.OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func TestResolveGroupClaimName_WithDB_ReturnsDBValue(t *testing.T) {
	mainDB, _, _ := sqlmock.New()
	defer mainDB.Close()

	oidcRepo, oidcMock := newOIDCConfigRepo(t)

	extraCfg, _ := json.Marshal(map[string]interface{}{
		"group_claim_name": "db_groups",
	})
	oidcMock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			uuid.New(), "test", "generic_oidc", "https://example.com",
			"client-id", "secret-enc", "https://example.com/cb",
			[]byte(`["openid"]`), true,
			extraCfg, time.Now(), time.Now(), nil, nil,
		))

	h, err := NewAuthHandlers(&config.Config{}, mainDB, oidcRepo, nil, auth.NewMemoryStateStore(time.Hour))
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}

	got := h.resolveGroupClaimName(context.Background())
	if got != "db_groups" {
		t.Errorf("resolveGroupClaimName = %q, want %q", got, "db_groups")
	}
}

func TestResolveGroupClaimName_WithDB_EmptyClaimFallsBackToCfg(t *testing.T) {
	// DB config has no group_claim_name → fall back to static config value.
	mainDB, _, _ := sqlmock.New()
	defer mainDB.Close()

	oidcRepo, oidcMock := newOIDCConfigRepo(t)

	oidcMock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			uuid.New(), "test", "generic_oidc", "https://example.com",
			"client-id", "secret-enc", "https://example.com/cb",
			[]byte(`["openid"]`), true,
			[]byte(`{}`), time.Now(), time.Now(), nil, nil,
		))

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupClaimName = "static_groups"

	h, err := NewAuthHandlers(cfg, mainDB, oidcRepo, nil, auth.NewMemoryStateStore(time.Hour))
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}

	got := h.resolveGroupClaimName(context.Background())
	if got != "static_groups" {
		t.Errorf("resolveGroupClaimName = %q, want %q", got, "static_groups")
	}
}

func TestResolveGroupMappingConfig_WithDB_ReturnsMappings(t *testing.T) {
	mainDB, _, _ := sqlmock.New()
	defer mainDB.Close()

	oidcRepo, oidcMock := newOIDCConfigRepo(t)

	extraCfg, _ := json.Marshal(map[string]interface{}{
		"group_claim_name": "grps",
		"default_role":     "viewer",
		"group_mappings": []map[string]string{
			{"group": "admins", "organization": "acme", "role": "admin"},
		},
	})
	oidcMock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			uuid.New(), "test", "generic_oidc", "https://example.com",
			"client-id", "secret-enc", "https://example.com/cb",
			[]byte(`["openid"]`), true,
			extraCfg, time.Now(), time.Now(), nil, nil,
		))

	h, err := NewAuthHandlers(&config.Config{}, mainDB, oidcRepo, nil, auth.NewMemoryStateStore(time.Hour))
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}

	cn, mappings, dr := h.resolveGroupMappingConfig(context.Background())
	if cn != "grps" {
		t.Errorf("claimName = %q, want grps", cn)
	}
	if dr != "viewer" {
		t.Errorf("defaultRole = %q, want viewer", dr)
	}
	if len(mappings) != 1 || mappings[0].Group != "admins" || mappings[0].Role != "admin" {
		t.Errorf("mappings = %v, want [{admins acme admin}]", mappings)
	}
}

// ---------------------------------------------------------------------------
// applyGroupMappings — error paths
// ---------------------------------------------------------------------------

func TestApplyGroupMappings_CheckMembershipError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetByName("acme") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-1", "acme", "Acme Corp", time.Now(), time.Now()))

	// CheckMembership → DB error
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnError(errDB)

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"})
	if err == nil {
		t.Error("expected error from CheckMembership failure, got nil")
	}
}

func TestApplyGroupMappings_DefaultRole_OrgNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.DefaultRole = "viewer"
	// No mappings → no match → goes to default role path
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetDefaultOrganization → GetByName("default") → DB error
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WillReturnError(errDB)

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"other"})
	if err == nil {
		t.Error("expected error when default org not found, got nil")
	}
}

func TestApplyGroupMappings_DefaultRole_UpdateMember(t *testing.T) {
	// Existing member → UpdateMemberRole path in default-role fallback
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.DefaultRole = "editor"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetDefaultOrganization → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-default", "default", "Default", time.Now(), time.Now()))

	// CheckMembership → is member (returns a row)
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols).
			AddRow("org-default", "user-1", "rt-1", time.Now()))

	// UpdateMemberRole → role template lookup
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("editor").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-editor"))

	// UpdateMemberRole → UPDATE
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"other"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

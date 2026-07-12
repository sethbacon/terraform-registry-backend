package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/azuread"
	ldappkg "github.com/terraform-registry/terraform-registry/internal/auth/ldap"
	oidcpkg "github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	samlpkg "github.com/terraform-registry/terraform-registry/internal/auth/saml"
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

// TestLoginHandler_OIDCSuccess proves the BeginAuth (nonce + PKCE) path: a
// configured OIDC provider redirects with a nonce/PKCE-bearing authorization
// URL, and the generated Nonce/CodeVerifier are persisted to the state store
// keyed by the state token, so the callback can bind verification to this
// specific login attempt.
func TestLoginHandler_OIDCSuccess(t *testing.T) {
	h, _, r := newAuthRouter(t)

	mockOIDC := oidcpkg.NewOIDCProviderForTest(&oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://issuer.example.com/authorize",
		},
		RedirectURL: "https://registry.example.com/callback",
		Scopes:      []string{"openid", "email"},
	})
	h.oidcProvider.Store(mockOIDC)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=oidc", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "code_challenge=") {
		t.Errorf("Location missing PKCE code_challenge param, got: %s", location)
	}
	if !strings.Contains(location, "state=") {
		t.Errorf("Location missing state param, got: %s", location)
	}

	// Extract the state token and confirm the session state store actually
	// persisted a non-empty Nonce and CodeVerifier for it.
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("could not extract state param from Location")
	}
	saved, err := h.stateStore.Load(context.Background(), state)
	if err != nil || saved == nil {
		t.Fatalf("stateStore.Load(%q) = %v, %v; want a saved session state", state, saved, err)
	}
	if saved.Nonce == "" {
		t.Error("saved session state has empty Nonce")
	}
	if saved.CodeVerifier == "" {
		t.Error("saved session state has empty CodeVerifier")
	}
}

// TestLoginHandler_AzureADSuccess mirrors TestLoginHandler_OIDCSuccess for the
// Azure AD provider path.
func TestLoginHandler_AzureADSuccess(t *testing.T) {
	h, _, r := newAuthRouter(t)

	mockOIDC := oidcpkg.NewOIDCProviderForTest(&oauth2.Config{
		ClientID: "azure-client",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
		},
		RedirectURL: "https://registry.example.com/callback",
		Scopes:      []string{"openid", "email"},
	})
	h.azureADProvider = azuread.NewAzureADProviderForTest(mockOIDC, "tenant-abc")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=azuread", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "code_challenge=") {
		t.Errorf("Location missing PKCE code_challenge param, got: %s", location)
	}

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	state := u.Query().Get("state")
	saved, err := h.stateStore.Load(context.Background(), state)
	if err != nil || saved == nil {
		t.Fatalf("stateStore.Load(%q) = %v, %v; want a saved session state", state, saved, err)
	}
	if saved.Nonce == "" {
		t.Error("saved session state has empty Nonce")
	}
	if saved.CodeVerifier == "" {
		t.Error("saved session state has empty CodeVerifier")
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
	if _, ok := resp["token"]; ok {
		t.Error("response must not contain 'token' — session is cookie-only")
	}
	if resp["expires_in"] == nil {
		t.Error("response missing 'expires_in'")
	}
	assertSessionCookies(t, w)
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

var authOrgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
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
			AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))

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
			AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))

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

	// No current group matches → managed org "acme" is reconciled (user is not a
	// member, so it is a no-op), then the default-role fallback adds the user to
	// the unmanaged default org.

	// Managed org reconcile: GetByName("acme") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-acme", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
	// CheckMembership(acme) → not a member → nothing to revoke
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols))

	// GetDefaultOrganization → GetByName("default") → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-default", "default", "Default Org", nil, nil, time.Now(), time.Now()))

	// CheckMembership(default) → not found
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
			AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))

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

func TestApplyGroupMappings_DefaultRole_ExistingMemberNotOverwritten(t *testing.T) {
	// First-login-only default_role: an existing member's manually-granted role
	// must NOT be overwritten by the default-role fallback on subsequent logins.
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.DefaultRole = "editor"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetDefaultOrganization → found
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-default", "default", "Default", nil, nil, time.Now(), time.Now()))

	// CheckMembership → is member (returns a row) → fallback is a no-op.
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols).
			AddRow("org-default", "user-1", "rt-manual", time.Now()))

	// No role-template lookup and no UPDATE/INSERT must follow.

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"other"})
	if err != nil {
		t.Errorf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ProvidersHandler — Phase 2 enterprise identity
// ---------------------------------------------------------------------------

func TestProvidersHandler_NoProviders(t *testing.T) {
	_, _, r := newAuthRouter(t)
	r.GET("/auth/providers", func(c *gin.Context) {
		// Already registered below
	})

	// Use a fresh handler with no providers
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	rr := gin.New()
	rr.GET("/auth/providers", h.ProvidersHandler())

	w := httptest.NewRecorder()
	rr.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/providers", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	providers, ok := resp["providers"].([]interface{})
	if !ok {
		t.Fatalf("providers is not a list: %v", resp["providers"])
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
}

func TestProvidersHandler_WithSAMLAndLDAP(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// Inject SAML and LDAP providers directly (bypassing real construction)
	h.samlProviders = map[string]*samlpkg.Provider{
		"okta":  {},
		"azure": {},
	}
	h.ldapProvider = &ldappkg.Provider{}

	r := gin.New()
	r.GET("/auth/providers", h.ProvidersHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/providers", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	providers := resp["providers"].([]interface{})
	// Expect 2 SAML + 1 LDAP = 3 providers
	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d: %v", len(providers), providers)
	}

	typeCount := map[string]int{}
	for _, p := range providers {
		pm := p.(map[string]interface{})
		typeCount[pm["type"].(string)]++
	}
	if typeCount["saml"] != 2 {
		t.Errorf("expected 2 saml providers, got %d", typeCount["saml"])
	}
	if typeCount["ldap"] != 1 {
		t.Errorf("expected 1 ldap provider, got %d", typeCount["ldap"])
	}
}

// ---------------------------------------------------------------------------
// IdentityGroupMappingsHandler — Phase 2 enterprise identity
// ---------------------------------------------------------------------------

func TestIdentityGroupMappingsHandler_NoProviders(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	r := gin.New()
	r.GET("/admin/identity/group-mappings", h.IdentityGroupMappingsHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/identity/group-mappings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	// Neither SAML nor LDAP enabled → empty object
	if resp["saml"] != nil {
		t.Errorf("expected no saml key, got %v", resp["saml"])
	}
	if resp["ldap"] != nil {
		t.Errorf("expected no ldap key, got %v", resp["ldap"])
	}
}

func TestIdentityGroupMappingsHandler_WithSAMLAndLDAP(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	cfg.Auth.SAML.Enabled = true
	cfg.Auth.SAML.GroupAttributeName = "memberOf"
	cfg.Auth.SAML.DefaultRole = "viewer"
	cfg.Auth.SAML.GroupMappings = []config.SAMLGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
		{Group: "devs", Organization: "acme", Role: "editor"},
	}
	cfg.Auth.LDAP.Enabled = true
	cfg.Auth.LDAP.DefaultRole = "reader"
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=ops,dc=example,dc=com", Organization: "ops-team", Role: "operator"},
	}
	// Manually construct handler to avoid SAML/LDAP provider initialization
	h := &AuthHandlers{
		cfg:        cfg,
		db:         db,
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}

	r := gin.New()
	r.GET("/admin/identity/group-mappings", h.IdentityGroupMappingsHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/identity/group-mappings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)

	// Verify SAML section
	samlSection, ok := resp["saml"].(map[string]interface{})
	if !ok {
		t.Fatalf("saml section missing or wrong type: %v", resp["saml"])
	}
	if samlSection["group_attribute_name"] != "memberOf" {
		t.Errorf("saml group_attribute_name = %v, want memberOf", samlSection["group_attribute_name"])
	}
	if samlSection["default_role"] != "viewer" {
		t.Errorf("saml default_role = %v, want viewer", samlSection["default_role"])
	}
	samlMappings := samlSection["group_mappings"].([]interface{})
	if len(samlMappings) != 2 {
		t.Errorf("expected 2 SAML mappings, got %d", len(samlMappings))
	}

	// Verify LDAP section
	ldapSection, ok := resp["ldap"].(map[string]interface{})
	if !ok {
		t.Fatalf("ldap section missing or wrong type: %v", resp["ldap"])
	}
	if ldapSection["default_role"] != "reader" {
		t.Errorf("ldap default_role = %v, want reader", ldapSection["default_role"])
	}
	ldapMappings := ldapSection["group_mappings"].([]interface{})
	if len(ldapMappings) != 1 {
		t.Errorf("expected 1 LDAP mapping, got %d", len(ldapMappings))
	}
	firstLDAP := ldapMappings[0].(map[string]interface{})
	if firstLDAP["group_dn"] != "cn=ops,dc=example,dc=com" {
		t.Errorf("ldap group_dn = %v", firstLDAP["group_dn"])
	}
}

// ---------------------------------------------------------------------------
// SAMLACSHandler — IdP-initiated guard (finding [1])
// ---------------------------------------------------------------------------

const samlTestIdPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// newSAMLACSHandler builds an AuthHandlers with a single SAML IdP configured.
func newSAMLACSHandler(t *testing.T, allowIDPInitiated bool) *AuthHandlers {
	t.Helper()
	samlCfg := &config.SAMLConfig{
		Enabled:           true,
		ACSURL:            "https://registry.example.com/api/v1/auth/saml/acs",
		EntityID:          "https://registry.example.com",
		AllowIDPInitiated: allowIDPInitiated,
	}
	prov, err := samlpkg.NewProvider(samlCfg, &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: samlTestIdPMetadata})
	if err != nil {
		t.Fatalf("samlpkg.NewProvider: %v", err)
	}
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Auth.SAML = *samlCfg
	return &AuthHandlers{
		cfg:           cfg,
		samlProviders: map[string]*samlpkg.Provider{"test-idp": prov},
		stateStore:    auth.NewMemoryStateStore(time.Hour),
	}
}

// postToACS posts a (bogus) SAMLResponse with no RelayState — the shape of an
// unsolicited IdP-initiated response.
func postToACS(h *AuthHandlers) *httptest.ResponseRecorder {
	r := gin.New()
	r.POST("/api/v1/auth/saml/acs", h.SAMLACSHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader("SAMLResponse=Zm9v"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSAMLACSHandler_RejectsUnsolicitedWhenIDPInitiatedDisabled(t *testing.T) {
	h := newSAMLACSHandler(t, false)
	defer h.stateStore.Close()

	w := postToACS(h)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=idp_initiated_disabled") {
		t.Errorf("Location = %q, want error=idp_initiated_disabled", loc)
	}
}

func TestSAMLACSHandler_AllowsIDPInitiatedWhenEnabled(t *testing.T) {
	h := newSAMLACSHandler(t, true)
	defer h.stateStore.Close()

	w := postToACS(h)

	// The unsolicited guard is bypassed; the bogus assertion then fails
	// signature/parse validation instead of being rejected up-front.
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=idp_initiated_disabled") {
		t.Errorf("guard should be bypassed when IdP-initiated is enabled; Location = %q", loc)
	}
	if !strings.Contains(loc, "error=assertion_invalid") {
		t.Errorf("Location = %q, want error=assertion_invalid", loc)
	}
}

// ---------------------------------------------------------------------------
// MTLSConfigHandler — Phase 2 enterprise identity
// ---------------------------------------------------------------------------

func TestMTLSConfigHandler_Disabled(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{} // MTLS not enabled (zero value)
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	r := gin.New()
	r.GET("/admin/mtls/config", h.MTLSConfigHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/mtls/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if resp["enabled"] != false {
		t.Errorf("enabled = %v, want false", resp["enabled"])
	}
	mappings := resp["mappings"].([]interface{})
	if len(mappings) != 0 {
		t.Errorf("expected 0 mappings, got %d", len(mappings))
	}
}

func TestMTLSConfigHandler_WithMappings(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	cfg.Security.MTLS.Enabled = true
	cfg.Security.MTLS.ClientCAFile = "/etc/ssl/client-ca.pem"
	cfg.Security.MTLS.Mappings = []config.MTLSSubjectMapping{
		{Subject: "CN=ci-bot", Scopes: []string{"modules:read", "providers:read"}},
		{Subject: "CN=admin", Scopes: []string{"admin"}},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	r := gin.New()
	r.GET("/admin/mtls/config", h.MTLSConfigHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/mtls/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if resp["enabled"] != true {
		t.Errorf("enabled = %v, want true", resp["enabled"])
	}
	if resp["client_ca_file"] != "/etc/ssl/client-ca.pem" {
		t.Errorf("client_ca_file = %v", resp["client_ca_file"])
	}
	mappings := resp["mappings"].([]interface{})
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	first := mappings[0].(map[string]interface{})
	if first["subject"] != "CN=ci-bot" {
		t.Errorf("first mapping subject = %v", first["subject"])
	}
}

// ---------------------------------------------------------------------------
// LDAPLoginHandler — Phase 2 enterprise identity
// ---------------------------------------------------------------------------

func TestLDAPLoginHandler_MissingCredentials(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	r := gin.New()
	r.POST("/auth/ldap/login", h.LDAPLoginHandler())

	// Empty body → binding error
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(`{}`)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["error"] != "username and password are required" {
		t.Errorf("error = %v", resp["error"])
	}
}

func TestLDAPLoginHandler_NotConfigured(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	cfg := &config.Config{}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	r := gin.New()
	r.POST("/auth/ldap/login", h.LDAPLoginHandler())

	body := `{"username":"alice","password":"secret"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["error"] != "LDAP authentication is not configured" {
		t.Errorf("error = %v", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// reconcileGroupMemberships — deprovisioning & first-login default-role
// (issue #467). Exercised through both the OIDC (applyGroupMappings) and SAML
// (applySAMLGroupMappings) entry points.
// ---------------------------------------------------------------------------

// expectOrgByName queues a GetByName lookup that returns a single org row.
func expectOrgByName(mock sqlmock.Sqlmock, name, orgID string) {
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs(name).
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow(orgID, name, name, nil, nil, time.Now(), time.Now()))
}

// expectIsMember queues a CheckMembership lookup that reports the user as a member.
func expectIsMember(mock sqlmock.Sqlmock, orgID, userID, roleID string) {
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols).
			AddRow(orgID, userID, roleID, time.Now()))
}

// expectNotMember queues a CheckMembership lookup that reports no membership.
func expectNotMember(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols))
}

// expectAddMember queues the role-template lookup + INSERT done by AddMemberWithParams.
func expectAddMember(mock sqlmock.Sqlmock, roleName, roleID string) {
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs(roleName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectUpdateMember queues the role-template lookup + UPDATE done by UpdateMemberRole.
func expectUpdateMember(mock sqlmock.Sqlmock, roleName, roleID string) {
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs(roleName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// expectRemoveMember queues the DELETE done by RemoveMember (deprovisioning).
func expectRemoveMember(mock sqlmock.Sqlmock) {
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// User loses their only mapped group → membership is REVOKED from that org.
func TestReconcile_LosesGroup_RevokesMembership(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// Managed org acme: user is currently a member but no longer has the group.
	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectRemoveMember(mock)

	// User now has an unrelated group that maps to nothing.
	err := h.applyGroupMappings(context.Background(), "user-1", []string{"some-other-group"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// User's group changes to one mapping a different role in the same org → role UPDATED.
func TestReconcile_GroupChanges_UpdatesRole(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
		{Group: "viewers", Organization: "acme", Role: "viewer"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// acme is managed; the user now has "viewers" (was "admins") → desired role viewer.
	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectUpdateMember(mock, "viewer", "rt-viewer")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"viewers"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// User keeps the group → membership preserved with the correct role (UPDATE to same role).
func TestReconcile_KeepsGroup_PreservesMembership(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectUpdateMember(mock, "admin", "rt-admin")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Manual membership in an UNMANAGED org (no mapping references it) → PRESERVED.
// The only mapping references "acme"; the user's manual membership in "other-org"
// must never be touched, so the reconcile only queries the managed org.
func TestReconcile_UnmanagedOrg_Preserved(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// Only the managed org "acme" is reconciled. The user is not a member and has
	// no matching group → no-op. No query is ever issued for the unmanaged org,
	// so a manual membership there cannot be revoked.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"unrelated"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// default_role does NOT overwrite an existing member's manually-set role
// (first-login-only) when the default org is unmanaged.
func TestReconcile_DefaultRole_FirstLoginOnly(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	// No mappings → default org is unmanaged.
	cfg.Auth.OIDC.DefaultRole = "viewer"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// GetDefaultOrganization → found; user is already a member → no write at all.
	expectOrgByName(mock, "default", "org-default")
	expectIsMember(mock, "org-default", "user-1", "rt-manual")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"whatever"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// default_role is applied on first login (user not yet a member of default org).
func TestReconcile_DefaultRole_FirstLoginAdds(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.DefaultRole = "viewer"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	expectOrgByName(mock, "default", "org-default")
	expectNotMember(mock)
	expectAddMember(mock, "viewer", "rt-viewer")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"whatever"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// default_role is SKIPPED when the default org is itself IdP-managed (referenced
// by a mapping). The managed reconcile is the single source of truth for it.
func TestReconcile_DefaultRole_SkippedWhenDefaultOrgManaged(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	// A mapping references the "default" org, making it IdP-managed.
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "default", Role: "admin"},
	}
	cfg.Auth.OIDC.DefaultRole = "viewer"
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// Managed reconcile of "default": user currently a member, no matching group
	// → REVOKE.
	expectOrgByName(mock, "default", "org-default")
	expectIsMember(mock, "org-default", "user-1", "rt-admin")
	expectRemoveMember(mock)

	// The default-role fallback resolves the default org, recognises it as
	// IdP-managed, and returns WITHOUT re-adding the user (no membership check,
	// no INSERT/UPDATE). The org row resolves to the same ID reconciled above.
	expectOrgByName(mock, "default", "org-default")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"not-admins"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Multiple groups mapping to the SAME org → deterministic single desired role.
// The first mapping in config order whose group the user has wins.
func TestReconcile_MultipleGroupsSameOrg_Deterministic(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
		{Group: "devs", Organization: "acme", Role: "editor"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// User has BOTH groups. First config mapping (admins → admin) must win.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "admin", "rt-admin")

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"devs", "admins"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Multiple managed orgs reconciled in a single login: one upserted, one revoked.
func TestReconcile_MultipleManagedOrgs_MixedActions(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
		{Group: "ops", Organization: "platform", Role: "operator"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// acme: has group → add member.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "admin", "rt-admin")
	// platform: no group, currently a member → revoke.
	expectOrgByName(mock, "platform", "org-platform")
	expectIsMember(mock, "org-platform", "user-1", "rt-operator")
	expectRemoveMember(mock)

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"})
	if err != nil {
		t.Fatalf("applyGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// RemoveMember DB error during deprovisioning is surfaced.
func TestReconcile_RevokeError_Surfaced(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	mock.ExpectExec("DELETE FROM organization_members").WillReturnError(errDB)

	err := h.applyGroupMappings(context.Background(), "user-1", []string{"not-admins"})
	if err == nil {
		t.Error("expected error from RemoveMember failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// SAML entry point — same reconcile semantics via applySAMLGroupMappings.
// ---------------------------------------------------------------------------

// SAML: user loses their only mapped group → membership REVOKED.
func TestApplySAMLGroupMappings_LosesGroup_Revokes(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.SAML.GroupMappings = []config.SAMLGroupMapping{
		{Group: "saml-admins", Organization: "acme", Role: "admin"},
	}
	h := &AuthHandlers{
		cfg:        cfg,
		db:         db,
		orgRepo:    repositories.NewOrganizationRepository(db),
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}

	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectRemoveMember(mock)

	err := h.applySAMLGroupMappings(context.Background(), "user-1", []string{"unrelated"})
	if err != nil {
		t.Fatalf("applySAMLGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// SAML: user keeps the group → membership upserted with the mapped role.
func TestApplySAMLGroupMappings_KeepsGroup_Upserts(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.SAML.GroupMappings = []config.SAMLGroupMapping{
		{Group: "saml-admins", Organization: "acme", Role: "admin"},
	}
	h := &AuthHandlers{
		cfg:        cfg,
		db:         db,
		orgRepo:    repositories.NewOrganizationRepository(db),
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}

	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "admin", "rt-admin")

	err := h.applySAMLGroupMappings(context.Background(), "user-1", []string{"saml-admins"})
	if err != nil {
		t.Fatalf("applySAMLGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// SAML: default_role first-login-only — existing member not overwritten.
func TestApplySAMLGroupMappings_DefaultRole_FirstLoginOnly(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.SAML.DefaultRole = "viewer"
	h := &AuthHandlers{
		cfg:        cfg,
		db:         db,
		orgRepo:    repositories.NewOrganizationRepository(db),
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}

	expectOrgByName(mock, "default", "org-default")
	expectIsMember(mock, "org-default", "user-1", "rt-manual")

	err := h.applySAMLGroupMappings(context.Background(), "user-1", []string{"anything"})
	if err != nil {
		t.Fatalf("applySAMLGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// SAML: nothing configured → no-op (no DB calls).
func TestApplySAMLGroupMappings_NothingConfigured(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h := &AuthHandlers{
		cfg:        cfg,
		db:         db,
		orgRepo:    repositories.NewOrganizationRepository(db),
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}

	if err := h.applySAMLGroupMappings(context.Background(), "user-1", []string{"x"}); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// LDAP entry point — same reconcile semantics via applyLDAPGroupMappings.
// LDAP group DNs are matched case-insensitively (matching
// ldappkg.MatchGroupMappings); the adapter lowercases both the configured
// GroupDNs and the user's DNs before delegating to reconcileGroupMemberships.
// ---------------------------------------------------------------------------

// newLDAPHandler builds an AuthHandlers wired only with what the LDAP group
// reconcile needs, avoiding NewProvider (no live LDAP server in tests).
func newLDAPHandler(db *sql.DB, cfg *config.Config) *AuthHandlers {
	return &AuthHandlers{
		cfg:        cfg,
		db:         db,
		orgRepo:    repositories.NewOrganizationRepository(db),
		stateStore: auth.NewMemoryStateStore(time.Hour),
	}
}

// LDAP: user loses their only mapped group DN → membership REVOKED.
func TestApplyLDAPGroupMappings_LosesGroup_Revokes(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "acme", Role: "admin"},
	}
	h := newLDAPHandler(db, cfg)

	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectRemoveMember(mock)

	// User now has an unrelated DN that maps to nothing.
	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=unrelated,ou=groups,dc=example,dc=com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: user's DN changes to one mapping a different role in the same org → role UPDATED.
func TestApplyLDAPGroupMappings_GroupChanges_UpdatesRole(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "acme", Role: "admin"},
		{GroupDN: "cn=viewers,ou=groups,dc=example,dc=com", Organization: "acme", Role: "viewer"},
	}
	h := newLDAPHandler(db, cfg)

	// User now has the viewers DN (was admins) → desired role viewer.
	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-admin")
	expectUpdateMember(mock, "viewer", "rt-viewer")

	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=viewers,ou=groups,dc=example,dc=com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: case-insensitive DN matching — a differently-cased DN still matches the
// configured mapping (reproducing ldappkg.MatchGroupMappings) and upserts.
func TestApplyLDAPGroupMappings_CaseInsensitiveDN_Matches(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	// Configured DN uses lowercase; the user presents a mixed/upper-case DN.
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "acme", Role: "admin"},
	}
	h := newLDAPHandler(db, cfg)

	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "admin", "rt-admin")

	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"CN=Admins,OU=Groups,DC=Example,DC=Com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: manual membership in an UNMANAGED org → PRESERVED. Only the managed org
// is ever queried, so a manual membership elsewhere cannot be revoked.
func TestApplyLDAPGroupMappings_UnmanagedOrg_Preserved(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "acme", Role: "admin"},
	}
	h := newLDAPHandler(db, cfg)

	// Only managed org "acme" reconciled; user not a member, no matching DN → no-op.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)

	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=unrelated,ou=groups,dc=example,dc=com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: default_role first-login-only — existing member not overwritten.
func TestApplyLDAPGroupMappings_DefaultRole_FirstLoginOnly(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.LDAP.DefaultRole = "viewer"
	h := newLDAPHandler(db, cfg)

	// GetDefaultOrganization → found; user is already a member → no write at all.
	expectOrgByName(mock, "default", "org-default")
	expectIsMember(mock, "org-default", "user-1", "rt-manual")

	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=anything,ou=groups,dc=example,dc=com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: default_role SKIPPED when the default org is itself IdP-managed.
func TestApplyLDAPGroupMappings_DefaultRole_SkippedWhenDefaultOrgManaged(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	// A mapping references the "default" org, making it IdP-managed.
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "default", Role: "admin"},
	}
	cfg.Auth.LDAP.DefaultRole = "viewer"
	h := newLDAPHandler(db, cfg)

	// Managed reconcile of "default": user currently a member, no matching DN → REVOKE.
	expectOrgByName(mock, "default", "org-default")
	expectIsMember(mock, "org-default", "user-1", "rt-admin")
	expectRemoveMember(mock)

	// default-role fallback resolves the default org, recognises it as IdP-managed,
	// and returns WITHOUT re-adding the user (no membership check, no INSERT/UPDATE).
	expectOrgByName(mock, "default", "org-default")

	err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=not-admins,ou=groups,dc=example,dc=com"})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: multiple DNs mapping to the SAME org → deterministic single desired role.
// The first mapping in config order whose DN the user has wins.
func TestApplyLDAPGroupMappings_MultipleDNsSameOrg_Deterministic(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.LDAP.GroupMappings = []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "acme", Role: "admin"},
		{GroupDN: "cn=devs,ou=groups,dc=example,dc=com", Organization: "acme", Role: "editor"},
	}
	h := newLDAPHandler(db, cfg)

	// User has BOTH DNs. First config mapping (admins → admin) must win.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "admin", "rt-admin")

	err := h.applyLDAPGroupMappings(context.Background(), "user-1", []string{
		"cn=devs,ou=groups,dc=example,dc=com",
		"cn=admins,ou=groups,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("applyLDAPGroupMappings: unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// LDAP: nothing configured → no-op (no DB calls).
func TestApplyLDAPGroupMappings_NothingConfigured(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	cfg := &config.Config{}
	h := newLDAPHandler(db, cfg)

	if err := h.applyLDAPGroupMappings(context.Background(), "user-1",
		[]string{"cn=x,ou=groups,dc=example,dc=com"}); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

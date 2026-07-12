// auth.go implements HTTP handlers for OIDC login, OAuth callbacks, token refresh, and logout.
package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/azuread"
	ldappkg "github.com/terraform-registry/terraform-registry/internal/auth/ldap"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	samlpkg "github.com/terraform-registry/terraform-registry/internal/auth/saml"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// AuthHandlers handles authentication-related endpoints
type AuthHandlers struct {
	cfg             *config.Config
	db              *sql.DB
	userRepo        *repositories.UserRepository
	orgRepo         *repositories.OrganizationRepository
	oidcConfigRepo  *repositories.OIDCConfigRepository
	tokenRepo       *repositories.TokenRepository
	oidcProvider    atomic.Pointer[oidc.OIDCProvider]
	azureADProvider *azuread.AzureADProvider
	samlProviders   map[string]*samlpkg.Provider // keyed by IdP name
	ldapProvider    *ldappkg.Provider
	// stateStore persists auth CSRF state tokens. When Redis is configured the
	// store is shared across instances; otherwise an in-memory store is used.
	stateStore auth.StateStore
	// samlEgressGuard widens the SSRF deny-list applied when fetching a SAML
	// IdP's metadata_url (nil = strict). Set via WithSAMLEgressGuard.
	samlEgressGuard *httpsafe.Guard
}

// AuthHandlersOption configures optional AuthHandlers construction behavior.
type AuthHandlersOption func(*AuthHandlers)

// WithSAMLEgressGuard widens the SSRF deny-list applied when fetching a SAML
// IdP's metadata_url (nil = strict default), for deployments whose IdP is
// only reachable at an internal address.
func WithSAMLEgressGuard(g *httpsafe.Guard) AuthHandlersOption {
	return func(h *AuthHandlers) { h.samlEgressGuard = g }
}

// NewAuthHandlers creates a new AuthHandlers instance.
// stateStore must be non-nil; the caller selects the implementation
// (MemoryStateStore for single-instance, RedisStateStore for HA).
func NewAuthHandlers(cfg *config.Config, db *sql.DB, oidcConfigRepo *repositories.OIDCConfigRepository, tokenRepo *repositories.TokenRepository, stateStore auth.StateStore, opts ...AuthHandlersOption) (*AuthHandlers, error) {
	h := &AuthHandlers{
		cfg:            cfg,
		db:             db,
		userRepo:       repositories.NewUserRepository(db),
		orgRepo:        repositories.NewOrganizationRepository(db),
		oidcConfigRepo: oidcConfigRepo,
		tokenRepo:      tokenRepo,
		stateStore:     stateStore,
	}
	for _, opt := range opts {
		opt(h)
	}

	// Initialize OIDC provider if enabled
	if cfg.Auth.OIDC.Enabled {
		oidcProv, err := oidc.NewOIDCProvider(&cfg.Auth.OIDC)
		if err != nil {
			return nil, err
		}
		h.oidcProvider.Store(oidcProv)
	}

	// Initialize Azure AD provider if enabled
	if cfg.Auth.AzureAD.Enabled {
		azProv, err := azuread.NewAzureADProvider(&cfg.Auth.AzureAD)
		if err != nil {
			return nil, err
		}
		h.azureADProvider = azProv
	}

	// Initialize SAML providers if enabled
	if cfg.Auth.SAML.Enabled {
		h.samlProviders = make(map[string]*samlpkg.Provider, len(cfg.Auth.SAML.IdPs))
		for i := range cfg.Auth.SAML.IdPs {
			idpCfg := &cfg.Auth.SAML.IdPs[i]
			sp, err := samlpkg.NewProviderWithGuard(&cfg.Auth.SAML, idpCfg, h.samlEgressGuard)
			if err != nil {
				return nil, fmt.Errorf("saml idp %q: %w", idpCfg.Name, err)
			}
			h.samlProviders[idpCfg.Name] = sp
			slog.Info("SAML IdP configured", "name", idpCfg.Name)
		}
	}

	// Initialize LDAP provider if enabled
	if cfg.Auth.LDAP.Enabled {
		ldapProv, err := ldappkg.NewProvider(&cfg.Auth.LDAP)
		if err != nil {
			return nil, fmt.Errorf("ldap: %w", err)
		}
		h.ldapProvider = ldapProv
		slog.Info("LDAP authentication configured", "host", cfg.Auth.LDAP.Host)
	}

	return h, nil
}

// SetOIDCProvider atomically swaps the active OIDC provider. This is used by
// the setup wizard to activate a newly configured OIDC provider at runtime
// without requiring a server restart.
func (h *AuthHandlers) SetOIDCProvider(provider *oidc.OIDCProvider) {
	h.oidcProvider.Store(provider)
	slog.Info("OIDC provider swapped at runtime")
}

// SetLDAPProvider swaps the active LDAP provider at runtime. This is used by
// the setup wizard to activate a newly configured LDAP provider without a restart.
func (h *AuthHandlers) SetLDAPProvider(provider *ldappkg.Provider) {
	h.ldapProvider = provider
	slog.Info("LDAP provider swapped at runtime")
}

// generateState generates a random state string for OAuth
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// @Summary      Initiate OAuth login
// @Description  Redirect user to an identity provider to begin authentication. Supports OIDC, Azure AD, SAML, and LDAP (LDAP uses a separate POST endpoint). For SAML, set provider=saml:<idp-name>.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        provider  query  string  false  "Auth provider: oidc, azuread, saml, or saml:<idp-name> (default: oidc)"
// @Success      302  {object}  string  "Redirects to IdP authorization URL"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider or provider not configured"
// @Failure      500  {object}  map[string]interface{}  "Failed to generate state or internal error"
// @Router       /api/v1/auth/login [get]
// LoginHandler initiates the OAuth login flow
// GET /api/v1/auth/login?provider=oidc|azuread
func (h *AuthHandlers) LoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		provider := c.Query("provider")
		if provider == "" {
			provider = "oidc" // Default to OIDC
		}

		// Generate state for CSRF protection
		state, err := generateState()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate state",
			})
			return
		}

		// Store state in session store with 10-minute TTL
		sessionState := &auth.SessionState{
			State:        state,
			CreatedAt:    time.Now(),
			ProviderType: provider,
		}
		if err := h.stateStore.Save(c.Request.Context(), state, sessionState, 10*time.Minute); err != nil {
			slog.Error("failed to save OIDC state", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to save session state",
			})
			return
		}

		// Get authorization URL based on provider
		var authURL string
		switch provider {
		case "oidc":
			oidcProv := h.oidcProvider.Load()
			if oidcProv == nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "OIDC provider not configured",
				})
				return
			}
			authURL = oidcProv.GetAuthURL(state) //nolint:staticcheck // SA1019: migrating to BeginAuth (nonce+PKCE) is tracked in the other v0.17.0-adoption PR
		case "azuread":
			if h.azureADProvider == nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Azure AD provider not configured",
				})
				return
			}
			authURL = h.azureADProvider.GetAuthURL(state)
		default:
			// Check for SAML provider: "saml" uses first IdP, "saml:<name>" picks by name.
			if provider == "saml" || strings.HasPrefix(provider, "saml:") {
				idpName := ""
				if provider == "saml" {
					// Use first configured IdP
					for name := range h.samlProviders {
						idpName = name
						break
					}
				} else {
					idpName = strings.TrimPrefix(provider, "saml:")
				}
				sp, ok := h.samlProviders[idpName]
				if !ok || sp == nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("SAML IdP %q not configured", idpName),
					})
					return
				}
				redirectURL, reqID, err := sp.MakeAuthenticationRequest(state)
				if err != nil {
					slog.Error("saml: failed to create AuthnRequest", "idp", idpName, "error", err)
					c.JSON(http.StatusInternalServerError, gin.H{
						"error": "Failed to initiate SAML login",
					})
					return
				}
				// Update session state with the specific IdP name for callback routing
				// and bind the AuthnRequest ID so the ACS can enforce InResponseTo.
				sessionState.ProviderType = "saml:" + idpName
				sessionState.SAMLRequestID = reqID
				_ = h.stateStore.Save(c.Request.Context(), state, sessionState, 10*time.Minute)
				authURL = redirectURL.String()
			} else {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid provider. Must be 'oidc', 'azuread', or 'saml'",
				})
				return
			}
		}

		// Redirect to authorization URL
		c.Redirect(http.StatusFound, authURL)
	}
}

// @Summary      OAuth callback handler
// @Description  Handles the callback from OAuth provider after user authorizes. Exchanges the authorization code for a JWT, sets a `tfr_auth_token` HttpOnly cookie, and redirects to `/auth/callback`.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        code   query  string  true   "Authorization code from OAuth provider"
// @Param        state  query  string  true   "State parameter for CSRF validation"
// @Success      302  {object}  string  "Sets tfr_auth_token HttpOnly cookie and redirects to frontend /auth/callback"
// @Failure      400  {object}  map[string]interface{}  "Invalid state or authorization code"
// @Failure      401  {object}  map[string]interface{}  "Failed to exchange code for token"
// @Failure      500  {object}  map[string]interface{}  "Database or internal error"
// @Router       /api/v1/auth/callback [get]
// CallbackHandler handles OAuth callback
// GET /api/v1/auth/callback?code=...&state=...
func (h *AuthHandlers) CallbackHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Derive the frontend base URL once; used for both the success redirect and all
		// error redirects so the user always lands on the frontend CallbackPage.
		frontendBase := deriveFrontendURL(h.cfg)

		// callbackError redirects the browser to the frontend /auth/callback page with
		// error details as query parameters. The frontend CallbackPage displays a
		// user-friendly message and navigates to /login after a short delay.
		// Falls back to a plain JSON response only when no frontend URL can be derived.
		callbackError := func(errCode, description string) {
			if frontendBase == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": description})
				return
			}
			target := fmt.Sprintf(
				"%s/auth/callback?error=%s&error_description=%s",
				frontendBase,
				url.QueryEscape(errCode),
				url.QueryEscape(description),
			)
			c.Redirect(http.StatusFound, target)
		}

		code := c.Query("code")
		state := c.Query("state")

		// Validate state
		sessionState, loadErr := h.stateStore.Load(c.Request.Context(), state)
		if loadErr != nil {
			slog.Error("failed to load OIDC state from store", "error", loadErr)
			callbackError("state_error", "Failed to validate session state. Please try logging in again.")
			return
		}
		if sessionState == nil {
			callbackError("invalid_state", "Invalid state parameter. Please try logging in again.")
			return
		}

		// Check state expiration (5 minutes)
		if time.Since(sessionState.CreatedAt) > 5*time.Minute {
			// State was already consumed by Load (single-use in Redis) but check TTL anyway
			callbackError("state_expired", "Login session expired. Please try logging in again.")
			return
		}

		// State was already atomically consumed by Load (Redis) or needs explicit delete (memory).
		// Explicit delete is a no-op for Redis since Load already removed it.
		_ = h.stateStore.Delete(c.Request.Context(), state)

		ctx := context.Background()

		var sub, email, name string
		var err error
		var oidcGroups []string // populated for OIDC logins when group_claim_name is configured
		var emailVerified *bool

		// Exchange code for tokens based on provider
		switch sessionState.ProviderType {
		case "oidc":
			oidcProv := h.oidcProvider.Load()
			if oidcProv == nil {
				callbackError("provider_not_configured", "OIDC provider is not configured.")
				return
			}

			// Exchange code for token
			token, err := oidcProv.ExchangeCode(ctx, code)
			if err != nil {
				callbackError("token_exchange_failed", "Failed to exchange authorization code for token.")
				return
			}

			// Extract ID token
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				callbackError("no_id_token", "The identity provider did not return an ID token.")
				return
			}

			// Verify ID token
			idToken, err := oidcProv.VerifyIDToken(ctx, rawIDToken)
			if err != nil {
				callbackError("id_token_invalid", "The ID token could not be verified.")
				return
			}

			// Extract user info. The library's own emailVerified return is
			// discarded here in favor of the existing emailVerifiedClaim(idToken)
			// helper below, which this repo's enforceEmailVerified/RequireVerifiedEmail
			// gate already relies on -- reconciling the two is left to the other
			// v0.17.0-adoption PR in this batch.
			sub, email, name, _, err = oidcProv.ExtractUserInfo(idToken)
			if err != nil {
				slog.Error("oidc: failed to extract user info from ID token", "error", err)
				callbackError("user_info_failed", "Failed to extract user information from the ID token.")
				return
			}

			emailVerified = emailVerifiedClaim(idToken)

			// Extract group claims for role mapping.
			// DB config group mapping settings take precedence over env/file config.
			effectiveClaimName := h.resolveGroupClaimName(ctx)
			oidcGroups = oidcProv.ExtractGroups(idToken, effectiveClaimName)

		case "azuread":
			if h.azureADProvider == nil {
				callbackError("provider_not_configured", "Azure AD provider is not configured.")
				return
			}

			// Exchange code for token
			token, err := h.azureADProvider.ExchangeCode(ctx, code)
			if err != nil {
				callbackError("token_exchange_failed", "Failed to exchange authorization code for token.")
				return
			}

			// Extract ID token
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				callbackError("no_id_token", "The identity provider did not return an ID token.")
				return
			}

			// Verify ID token
			idToken, err := h.azureADProvider.VerifyIDToken(ctx, rawIDToken)
			if err != nil {
				callbackError("id_token_invalid", "The ID token could not be verified.")
				return
			}

			// Extract user info (see the OIDC branch above re: the discarded
			// library emailVerified return).
			sub, email, name, _, err = h.azureADProvider.ExtractUserInfo(idToken)
			if err != nil {
				slog.Error("azuread: failed to extract user info from ID token", "error", err)
				callbackError("user_info_failed", "Failed to extract user information from the ID token.")
				return
			}

			emailVerified = emailVerifiedClaim(idToken)

		default:
			// Check for SAML provider type ("saml" or "saml:<idp_name>")
			if sessionState.ProviderType == "saml" || strings.HasPrefix(sessionState.ProviderType, "saml:") {
				// SAML responses arrive via the ACS endpoint (POST), not here.
				// If we get here it means something went wrong in routing.
				callbackError("invalid_flow", "SAML responses should be sent to the ACS endpoint.")
				return
			}
			callbackError("unknown_provider", "Unknown authentication provider.")
			return
		}

		// Get or create user
		if err := enforceEmailVerified(emailVerified, h.cfg.Auth.OIDC.RequireVerifiedEmail); err != nil {
			callbackError("email_not_verified", err.Error())
			return
		}
		if err := h.guardEmailRebind(ctx, sub, email); err != nil {
			callbackError("email_bound", err.Error())
			return
		}
		user, err := h.userRepo.GetOrCreateUserByOIDC(ctx, sub, email, name, emailVerified != nil && *emailVerified)
		if err != nil {
			callbackError("user_creation_failed", "Failed to look up or create your account.")
			return
		}

		// Apply OIDC group-to-role mappings. applyGroupMappings is a no-op when
		// nothing is configured — the guard lives inside the function so it accounts
		// for both DB-stored and env-var config.
		if mapErr := h.applyGroupMappings(ctx, user.ID, oidcGroups); mapErr != nil {
			slog.Warn("failed to apply OIDC group mappings", "user_id", user.ID, "error", mapErr)
		}

		// Fetch user scopes to embed in JWT (avoids per-request DB lookup)
		scopes, err := h.orgRepo.GetUserCombinedScopes(ctx, user.ID)
		if err != nil {
			scopes = []string{}
		}

		// Generate JWT token for user
		jwtToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			callbackError("jwt_failed", "Failed to generate an authentication token.")
			return
		}

		// Set HttpOnly cookie — prevents JS access, logging, and Referer leakage.
		// SameSite=Lax allows the cookie to survive the top-level redirect from
		// the identity provider back to the frontend; Strict would block it.
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "tfr_auth_token",
			Value:    jwtToken,
			Path:     "/",
			MaxAge:   86400, // 24 hours
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Set CSRF double-submit cookie (non-HttpOnly so the frontend can read it
		// and echo it back in the X-CSRF-Token header on mutating requests).
		if _, csrfErr := middleware.SetCSRFCookie(c.Writer, true); csrfErr != nil {
			slog.Error("failed to set CSRF cookie on callback", "error", csrfErr)
		}

		redirectTarget := fmt.Sprintf("%s/auth/callback", frontendBase)
		c.Redirect(http.StatusFound, redirectTarget)
	}
}

// @Summary      OIDC logout
// @Description  Revokes the current JWT, clears the auth cookie, and when OIDC is active, redirects the browser to the provider's end_session_endpoint to terminate the SSO session. Falls back to a plain redirect to the frontend login page for non-OIDC setups.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        post_logout_redirect_uri  query  string  false  "URL to redirect to after the provider logs out (defaults to frontend /login)"
// @Success      302  {object}  string  "Redirects to OIDC end_session_endpoint or frontend /login"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized — no valid session"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/auth/logout [get]
// LogoutHandler revokes the current JWT, clears the auth cookie, and terminates
// the OIDC SSO session by redirecting to the provider's end_session_endpoint.
// GET /api/v1/auth/logout
func (h *AuthHandlers) LogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Revoke the current JWT if present
		if claims, exists := c.Get("jwt_claims"); exists {
			if jwtClaims, ok := claims.(*auth.Claims); ok && jwtClaims.JTI != "" {
				if jwtClaims.ExpiresAt != nil {
					_ = h.tokenRepo.RevokeToken(c.Request.Context(),
						jwtClaims.JTI, jwtClaims.UserID, jwtClaims.ExpiresAt.Time)
				}
			}
		}

		// Clear the auth cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "tfr_auth_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		// Clear the CSRF cookie
		middleware.ClearCSRFCookie(c.Writer)

		frontendBase := deriveFrontendURL(h.cfg)
		// After the IdP terminates the session, redirect to the frontend home page.
		// The user can then choose to log in again from there.
		postLogoutRedirect := frontendBase + "/"

		// If the OIDC provider has an end_session_endpoint, redirect there so that
		// the Keycloak (or other IdP) SSO session is also terminated.  Without this,
		// clicking "Login with OIDC" after logout silently re-authenticates the user
		// via the still-active IdP session cookie.
		oidcProv := h.oidcProvider.Load()
		if oidcProv != nil {
			if endSessionURL := oidcProv.GetEndSessionEndpoint(); endSessionURL != "" {
				logoutURL, err := url.Parse(endSessionURL)
				if err == nil {
					q := logoutURL.Query()
					q.Set("post_logout_redirect_uri", postLogoutRedirect)
					// Keycloak requires either id_token_hint or client_id when
					// post_logout_redirect_uri is set (returns 400 without one of them).
					// We use client_id (supported since Keycloak 19) — it is public
					// config, requires nothing stored client-side, and avoids the
					// security concern of storing raw ID tokens in localStorage.
					q.Set("client_id", h.cfg.Auth.OIDC.ClientID)
					logoutURL.RawQuery = q.Encode()
					c.Redirect(http.StatusFound, logoutURL.String())
					return
				}
			}
		}

		// No OIDC end_session_endpoint available — redirect to the frontend home page.
		c.Redirect(http.StatusFound, postLogoutRedirect)
	}
}

// setSessionCookies sets the HttpOnly auth cookie and the CSRF double-submit
// cookie for a freshly issued session JWT. The attributes must stay identical
// to the OIDC callback's — the frontend never sees the raw token, so the
// cookie is the only session carrier.
func setSessionCookies(c *gin.Context, jwtToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "tfr_auth_token",
		Value:    jwtToken,
		Path:     "/",
		MaxAge:   86400, // 24 hours — matches the JWT lifetime
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	if _, csrfErr := middleware.SetCSRFCookie(c.Writer, true); csrfErr != nil {
		slog.Error("failed to set CSRF cookie", "error", csrfErr)
	}
}

// deriveFrontendURL returns the browser-facing base URL of the frontend SPA.
// It tries (in order):
//  1. cfg.Server.PublicURL — set explicitly to the frontend's public address
//  2. The origin (scheme + host) of cfg.Auth.OIDC.RedirectURL — the registered callback URL
//     already points to the frontend's public address so stripping its path gives the base.
//  3. cfg.Server.BaseURL — internal backend address, last resort.
func deriveFrontendURL(cfg *config.Config) string {
	if cfg.Server.PublicURL != "" {
		return strings.TrimRight(cfg.Server.PublicURL, "/")
	}
	if cfg.Auth.OIDC.RedirectURL != "" {
		if u, err := url.Parse(cfg.Auth.OIDC.RedirectURL); err == nil {
			return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	if cfg.Auth.AzureAD.RedirectURL != "" {
		if u, err := url.Parse(cfg.Auth.AzureAD.RedirectURL); err == nil {
			return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	return strings.TrimRight(cfg.Server.BaseURL, "/")
}

// @Summary      Refresh JWT token
// @Description  Revokes the current JWT and sets a fresh one as an httpOnly auth cookie with extended expiration. The token itself is never returned in the response body.
// @Tags         Authentication
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Success      200  {object}  admin.RefreshResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - invalid or missing token"
// @Failure      500  {object}  map[string]interface{}  "Internal error during token generation"
// @Router       /api/v1/auth/refresh [post]
// RefreshHandler refreshes an existing JWT token
// POST /api/v1/auth/refresh
// Authorization: Bearer <existing_jwt>
func (h *AuthHandlers) RefreshHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get current user from context (set by auth middleware)
		userVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, ok := userVal.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get user details
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
			})
			return
		}

		// Fetch fresh scopes to embed in the new JWT
		scopes, err := h.orgRepo.GetUserCombinedScopes(c.Request.Context(), user.ID)
		if err != nil {
			scopes = []string{}
		}

		// Revoke the old JWT so it cannot be replayed after refresh.
		if claims, exists := c.Get("jwt_claims"); exists {
			if jwtClaims, ok := claims.(*auth.Claims); ok && jwtClaims.JTI != "" {
				if jwtClaims.ExpiresAt != nil {
					_ = h.tokenRepo.RevokeToken(c.Request.Context(),
						jwtClaims.JTI, jwtClaims.UserID, jwtClaims.ExpiresAt.Time)
				}
			}
		}

		// Generate new JWT token
		newToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate new token",
			})
			return
		}

		// Set the refreshed JWT as an HttpOnly cookie.
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "tfr_auth_token",
			Value:    newToken,
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Refresh the CSRF double-submit cookie.
		if _, csrfErr := middleware.SetCSRFCookie(c.Writer, true); csrfErr != nil {
			slog.Error("failed to set CSRF cookie on refresh", "error", csrfErr)
		}

		c.JSON(http.StatusOK, gin.H{
			"expires_in": 86400, // 24 hours in seconds
		})
	}
}

// @Summary      Get current user
// @Description  Retrieve information about the currently authenticated user, including organization memberships and role templates
// @Tags         Authentication
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Success      200  {object}  admin.MeResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/auth/me [get]
// MeHandler returns the current authenticated user's information including per-org role templates
// GET /api/v1/auth/me
func (h *AuthHandlers) MeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, ok := userIDVal.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get user with per-organization role template information
		userWithRoles, err := h.userRepo.GetUserWithOrgRoles(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get user information",
			})
			return
		}

		if userWithRoles == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Build response with user info and per-org role templates
		response := gin.H{
			"user": gin.H{
				"id":         userWithRoles.ID,
				"email":      userWithRoles.Email,
				"name":       userWithRoles.Name,
				"created_at": userWithRoles.CreatedAt,
				"updated_at": userWithRoles.UpdatedAt,
			},
		}

		// Build per-org memberships with role templates
		memberships := make([]gin.H, 0, len(userWithRoles.Memberships))
		for _, m := range userWithRoles.Memberships {
			membership := gin.H{
				"organization_id":   m.OrganizationID,
				"organization_name": m.OrganizationName,
				"created_at":        m.CreatedAt,
			}
			if m.RoleTemplateID != nil {
				membership["role_template"] = gin.H{
					"id":           m.RoleTemplateID,
					"name":         m.RoleTemplateName,
					"display_name": m.RoleTemplateDisplayName,
					"scopes":       m.RoleTemplateScopes,
				}
			} else {
				membership["role_template"] = nil
			}
			memberships = append(memberships, membership)
		}
		response["memberships"] = memberships

		// Calculate combined allowed scopes across all organizations
		// and provide a "primary" role template (highest privilege) for backward compatibility
		response["allowed_scopes"] = userWithRoles.GetAllowedScopes()

		// Include session expiry from JWT claims so the frontend can schedule the
		// pre-expiry warning dialog for cookie-based sessions. Absent for API-key auth.
		if claimsVal, ok := c.Get("jwt_claims"); ok {
			if claims, ok := claimsVal.(*auth.Claims); ok && claims.ExpiresAt != nil {
				t := claims.ExpiresAt.Time
				response["session_expires_at"] = t
			}
		}

		// For backward compatibility, provide the first membership's role template as primary
		// In a multi-org setup, the frontend should use per-org memberships
		if len(userWithRoles.Memberships) > 0 && userWithRoles.Memberships[0].RoleTemplateID != nil {
			m := userWithRoles.Memberships[0]
			response["role_template"] = gin.H{
				"name":         m.RoleTemplateName,
				"display_name": m.RoleTemplateDisplayName,
			}
		} else {
			response["role_template"] = nil
		}

		c.JSON(http.StatusOK, response)
	}
}

// resolveGroupClaimName returns the effective group claim name to use when
// extracting IdP group memberships from the OIDC ID token.
// Priority: DB-stored OIDC config > env/file config.
func (h *AuthHandlers) resolveGroupClaimName(ctx context.Context) string {
	if h.oidcConfigRepo != nil {
		if dbCfg, err := h.oidcConfigRepo.GetActiveOIDCConfig(ctx); err == nil && dbCfg != nil {
			claimName, _, _ := dbCfg.GetGroupMappingConfig()
			if claimName != "" {
				return claimName
			}
		}
	}
	return h.cfg.Auth.OIDC.GroupClaimName
}

// resolveGroupMappingConfig returns the effective group mapping configuration.
// DB-stored settings take precedence over env/file config so that changes made
// via the admin UI take effect without restarting the server.
func (h *AuthHandlers) resolveGroupMappingConfig(ctx context.Context) (claimName string, mappings []config.OIDCGroupMapping, defaultRole string) {
	if h.oidcConfigRepo != nil {
		if dbCfg, err := h.oidcConfigRepo.GetActiveOIDCConfig(ctx); err == nil && dbCfg != nil {
			cn, dbMappings, dr := dbCfg.GetGroupMappingConfig()
			if cn != "" || len(dbMappings) > 0 || dr != "" {
				// Convert DB model mappings to config type
				cfgMappings := make([]config.OIDCGroupMapping, len(dbMappings))
				for i, m := range dbMappings {
					cfgMappings[i] = config.OIDCGroupMapping{
						Group:        m.Group,
						Organization: m.Organization,
						Role:         m.Role,
					}
				}
				return cn, cfgMappings, dr
			}
		}
	}
	return h.cfg.Auth.OIDC.GroupClaimName, h.cfg.Auth.OIDC.GroupMappings, h.cfg.Auth.OIDC.DefaultRole
}

// groupMapping is the provider-agnostic shape of a single group-to-role mapping.
// OIDC (config.OIDCGroupMapping) and SAML (config.SAMLGroupMapping) both carry
// the identical {Group, Organization, Role} triple, so the reconcile logic is
// shared and adapts each provider's slice into this type.
type groupMapping struct {
	Group        string
	Organization string
	Role         string
}

// applyGroupMappings resolves the user's OIDC IdP groups against the configured
// group_mappings and reconciles their org memberships. See
// reconcileGroupMemberships for the full reconciliation semantics.
func (h *AuthHandlers) applyGroupMappings(ctx context.Context, userID string, groups []string) error {
	_, mappings, defaultRole := h.resolveGroupMappingConfig(ctx)
	gm := make([]groupMapping, len(mappings))
	for i, m := range mappings {
		gm[i] = groupMapping{Group: m.Group, Organization: m.Organization, Role: m.Role}
	}
	return h.reconcileGroupMemberships(ctx, userID, groups, gm, defaultRole, "OIDC")
}

// applySAMLGroupMappings applies SAML group-to-role mappings for a user.
// It mirrors applyGroupMappings but reads from SAMLConfig.
func (h *AuthHandlers) applySAMLGroupMappings(ctx context.Context, userID string, groups []string) error {
	mappings := h.cfg.Auth.SAML.GroupMappings
	defaultRole := h.cfg.Auth.SAML.DefaultRole
	gm := make([]groupMapping, len(mappings))
	for i, m := range mappings {
		gm[i] = groupMapping{Group: m.Group, Organization: m.Organization, Role: m.Role}
	}
	return h.reconcileGroupMemberships(ctx, userID, groups, gm, defaultRole, "SAML")
}

// reconcileGroupMemberships reconciles a user's organization memberships against
// the IdP groups carried by their signature-verified login token. It is shared
// by the OIDC and SAML callback paths; provider names the log source ("OIDC" or
// "SAML").
//
// Every organization referenced by a configured mapping is treated as
// IdP-authoritative and is reconciled on every login:
//
//  1. The desired role per managed org is computed from the user's *current*
//     groups. When several current groups map to the same org, the first
//     matching mapping in configuration order wins (deterministic).
//  2. For each managed org: if a current group maps to it the membership is
//     upserted (added if absent, role updated if changed); if no current group
//     maps to it the membership is REVOKED (removed) when the user is currently
//     a member — this is the deprovisioning step.
//  3. Organizations not referenced by any mapping are left untouched, so
//     manually granted memberships in unmanaged orgs persist across logins.
//  4. The default_role fallback is first-login-only: the user is added to the
//     default org with default_role only when they are not already a member
//     (existing roles are never overwritten). It is skipped entirely when the
//     default org is itself IdP-managed (already reconciled in step 2).
//
// Groups originate solely from the verified token and mappings are
// admin-configured, preserving the existing trust model.
func (h *AuthHandlers) reconcileGroupMemberships(ctx context.Context, userID string, groups []string, mappings []groupMapping, defaultRole, provider string) error {
	if len(mappings) == 0 && defaultRole == "" {
		return nil
	}

	// Set of the user's current groups for O(1) lookup.
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	// Compute the desired role per managed org from current groups, and the full
	// set of managed orgs. A "managed org" is any org named in a mapping; it is
	// reconciled (and possibly revoked) below even when no current group maps to
	// it. Iterating mappings in configuration order makes the desired-role choice
	// deterministic: the first mapping for an org whose group the user currently
	// has wins.
	managedOrgs := make([]string, 0, len(mappings)) // preserves config order, deduped
	seenManaged := make(map[string]struct{}, len(mappings))
	desiredRole := make(map[string]string, len(mappings)) // org name -> role

	for _, m := range mappings {
		if _, ok := seenManaged[m.Organization]; !ok {
			seenManaged[m.Organization] = struct{}{}
			managedOrgs = append(managedOrgs, m.Organization)
		}
		if _, hasGroup := groupSet[m.Group]; !hasGroup {
			continue
		}
		// First matching mapping (config order) sets the desired role for the org.
		if _, already := desiredRole[m.Organization]; !already {
			desiredRole[m.Organization] = m.Role
		}
	}

	// Reconcile each managed org. Track resolved org IDs so the default-role
	// fallback can detect when the default org is itself IdP-managed.
	managedOrgIDs := make(map[string]struct{}, len(managedOrgs))

	for _, orgName := range managedOrgs {
		org, err := h.orgRepo.GetByName(ctx, orgName)
		if err != nil || org == nil {
			slog.Warn(provider+" group mapping: organization not found", "org", orgName)
			continue
		}
		managedOrgIDs[org.ID] = struct{}{}

		isMember, _, err := h.orgRepo.CheckMembership(ctx, org.ID, userID)
		if err != nil {
			return fmt.Errorf("check membership org=%s user=%s: %w", org.ID, userID, err)
		}

		role, wanted := desiredRole[orgName]
		switch {
		case wanted && isMember:
			if err := h.orgRepo.UpdateMemberRole(ctx, org.ID, userID, role); err != nil {
				return fmt.Errorf("update member role org=%s user=%s role=%s: %w", org.ID, userID, role, err)
			}
			slog.Info(provider+" group mapping applied", "user_id", userID, "org", orgName, "role", role)
		case wanted && !isMember:
			if err := h.orgRepo.AddMemberWithParams(ctx, org.ID, userID, role); err != nil {
				return fmt.Errorf("add member org=%s user=%s role=%s: %w", org.ID, userID, role, err)
			}
			slog.Info(provider+" group mapping applied", "user_id", userID, "org", orgName, "role", role)
		case !wanted && isMember:
			// No current group maps to this managed org → deprovision.
			if err := h.orgRepo.RemoveMember(ctx, org.ID, userID); err != nil {
				return fmt.Errorf("revoke member org=%s user=%s: %w", org.ID, userID, err)
			}
			slog.Info(provider+" group mapping revoked", "user_id", userID, "org", orgName)
		default:
			// Not wanted and not a member → nothing to do.
		}
	}

	// default_role fallback — first-login-only. Add the user to the default org
	// with default_role only if they are not already a member. Skip entirely when
	// the default org is itself IdP-managed (already reconciled above).
	if defaultRole != "" {
		org, err := h.orgRepo.GetDefaultOrganization(ctx)
		if err != nil || org == nil {
			return fmt.Errorf("default organization not found for default_role fallback: %w", err)
		}
		if _, isManaged := managedOrgIDs[org.ID]; isManaged {
			return nil
		}

		isMember, _, err := h.orgRepo.CheckMembership(ctx, org.ID, userID)
		if err != nil {
			return fmt.Errorf("check membership default org user=%s: %w", userID, err)
		}
		if !isMember {
			if err := h.orgRepo.AddMemberWithParams(ctx, org.ID, userID, defaultRole); err != nil {
				return fmt.Errorf("add default member user=%s role=%s: %w", userID, defaultRole, err)
			}
			slog.Info(provider+" default role applied", "user_id", userID, "role", defaultRole)
		}
	}

	return nil
}

// @Summary      SAML SP metadata
// @Description  Returns the SAML Service Provider metadata XML for the specified (or first configured) IdP. Used by SAML identity providers during federation setup.
// @Tags         Authentication
// @Produce      xml
// @Param        idp  query  string  false  "SAML IdP name (defaults to first configured)"
// @Success      200  {string}  string  "SAML SP metadata XML"
// @Failure      404  {object}  map[string]interface{}  "No SAML provider configured"
// @Failure      500  {object}  map[string]interface{}  "Failed to marshal metadata"
// @Router       /api/v1/auth/saml/metadata [get]
// SAMLMetadataHandler returns the SP metadata XML for the first configured IdP.
// GET /api/v1/auth/saml/metadata
func (h *AuthHandlers) SAMLMetadataHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		idpName := c.Query("idp")
		var provider *samlpkg.Provider
		if idpName != "" {
			provider = h.samlProviders[idpName]
		} else {
			// Return metadata from first configured provider
			for _, p := range h.samlProviders {
				provider = p
				break
			}
		}
		if provider == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "No SAML provider configured"})
			return
		}

		metadata := provider.GetMetadata()
		data, err := xml.MarshalIndent(metadata, "", "  ")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal SP metadata"})
			return
		}
		c.Data(http.StatusOK, "application/samlmetadata+xml", data)
	}
}

// @Summary      SAML Assertion Consumer Service
// @Description  Receives SAML responses from the IdP (SP-initiated or IdP-initiated), validates the assertion, creates or updates the user, issues a JWT, and redirects to the frontend callback.
// @Tags         Authentication
// @Accept       x-www-form-urlencoded
// @Produce      html
// @Param        SAMLResponse  formData  string  true  "Base64-encoded SAML response"
// @Param        RelayState    formData  string  false "Relay state (contains session key)"
// @Success      302  {string}  string  "Redirects to frontend /auth/callback with token"
// @Failure      400  {object}  map[string]interface{}  "Invalid SAML response or assertion"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/auth/saml/acs [post]
// SAMLACSHandler handles the SAML Assertion Consumer Service (ACS) endpoint.
// It receives SAML responses from the IdP (via POST), validates the assertion,
// creates/updates the user, issues a JWT, and redirects to the frontend.
// POST /api/v1/auth/saml/acs
func (h *AuthHandlers) SAMLACSHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		frontendBase := deriveFrontendURL(h.cfg)

		callbackError := func(errCode, description string) {
			if frontendBase == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": description})
				return
			}
			target := fmt.Sprintf(
				"%s/auth/callback?error=%s&error_description=%s",
				frontendBase,
				url.QueryEscape(errCode),
				url.QueryEscape(description),
			)
			c.Redirect(http.StatusFound, target)
		}

		relayState := c.PostForm("RelayState")

		// Determine which IdP to validate against.
		// The RelayState may contain our session state key which includes the IdP name.
		var provider *samlpkg.Provider
		var idpName string
		// possibleRequestIDs binds the assertion to an AuthnRequest this SP issued
		// (SP-initiated). It stays empty only for genuine IdP-initiated responses.
		var possibleRequestIDs []string

		if relayState != "" {
			// Try to load session state from relay state (which is our CSRF state token)
			sessionState, _ := h.stateStore.Load(c.Request.Context(), relayState)
			if sessionState != nil {
				_ = h.stateStore.Delete(c.Request.Context(), relayState)
				if strings.HasPrefix(sessionState.ProviderType, "saml:") {
					idpName = strings.TrimPrefix(sessionState.ProviderType, "saml:")
					provider = h.samlProviders[idpName]
				}
				if sessionState.SAMLRequestID != "" {
					possibleRequestIDs = []string{sessionState.SAMLRequestID}
				}
			}
		}

		// Fallback: try all providers (IdP-initiated flow has no RelayState)
		if provider == nil {
			for name, p := range h.samlProviders {
				provider = p
				idpName = name
				break
			}
		}

		if provider == nil {
			callbackError("provider_not_configured", "No SAML IdP configured.")
			return
		}

		// Reject unsolicited (IdP-initiated) responses unless the operator has
		// explicitly enabled them. Without a bound request ID such a response is
		// not tied to a login this SP initiated, enabling replay and login CSRF.
		if len(possibleRequestIDs) == 0 && !provider.AllowIDPInitiated() {
			slog.Warn("saml: rejected unsolicited response; IdP-initiated SSO is disabled", "idp", idpName)
			callbackError("idp_initiated_disabled", "Unsolicited IdP-initiated SAML login is not enabled.")
			return
		}

		// Validate the SAML response. When possibleRequestIDs is populated the
		// crewjam SP enforces InResponseTo; for enabled IdP-initiated flows the
		// binding is skipped and replay is mitigated by the cache below.
		userInfo, assertionMeta, err := provider.ValidateResponse(c.Request, possibleRequestIDs, h.cfg.Auth.SAML.GroupAttributeName)
		if err != nil {
			slog.Error("saml: assertion validation failed", "idp", idpName, "error", err)
			callbackError("assertion_invalid", "SAML assertion validation failed.")
			return
		}

		// Assertion replay protection for IdP-initiated flows (no InResponseTo
		// binding). Dedupe on the assertion ID until it expires (NotOnOrAfter).
		if provider.AllowIDPInitiated() && assertionMeta != nil && assertionMeta.ID != "" {
			ttl := time.Until(assertionMeta.NotOnOrAfter)
			if ttl <= 0 || ttl > 15*time.Minute {
				ttl = 15 * time.Minute
			}
			reserved, resErr := h.stateStore.Reserve(c.Request.Context(), "saml_assertion:"+assertionMeta.ID, ttl)
			if resErr != nil {
				slog.Error("saml: assertion replay check failed", "idp", idpName, "error", resErr)
				callbackError("assertion_invalid", "SAML assertion validation failed.")
				return
			}
			if !reserved {
				slog.Warn("saml: rejected replayed assertion", "idp", idpName, "assertion_id", assertionMeta.ID)
				callbackError("assertion_replayed", "This SAML assertion has already been used.")
				return
			}
		}

		if userInfo.Email == "" && userInfo.NameID == "" {
			callbackError("user_info_failed", "SAML assertion did not contain an email or NameID.")
			return
		}

		// Use NameID as the unique subject identifier
		sub := fmt.Sprintf("saml:%s:%s", idpName, userInfo.NameID)

		ctx := context.Background()

		if err := h.guardEmailRebind(ctx, sub, userInfo.Email); err != nil {
			callbackError("email_bound", err.Error())
			return
		}

		// Get or create user (reuse the OIDC path — sub is unique per IdP).
		// SAML assertions are IdP-signed, so the asserted email is treated as
		// verified here, matching this flow's pre-v0.17.0 behavior (no
		// verification gate existed before this parameter was added). A
		// dedicated SAML email-verified signal, if ever needed, belongs to the
		// other v0.17.0-adoption PR in this batch.
		user, err := h.userRepo.GetOrCreateUserByOIDC(ctx, sub, userInfo.Email, userInfo.Name, true)
		if err != nil {
			callbackError("user_creation_failed", "Failed to look up or create your account.")
			return
		}

		// Apply SAML group mappings
		if mapErr := h.applySAMLGroupMappings(ctx, user.ID, userInfo.Groups); mapErr != nil {
			slog.Warn("failed to apply SAML group mappings", "user_id", user.ID, "error", mapErr)
		}

		// Fetch user scopes to embed in JWT
		scopes, scopeErr := h.orgRepo.GetUserCombinedScopes(ctx, user.ID)
		if scopeErr != nil {
			scopes = []string{}
		}

		// Generate JWT token
		jwtToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			callbackError("jwt_failed", "Failed to generate an authentication token.")
			return
		}

		// Set HttpOnly cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "tfr_auth_token",
			Value:    jwtToken,
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Set CSRF double-submit cookie
		if _, csrfErr := middleware.SetCSRFCookie(c.Writer, true); csrfErr != nil {
			slog.Error("failed to set CSRF cookie on SAML ACS", "error", csrfErr)
		}

		redirectTarget := fmt.Sprintf("%s/auth/callback", frontendBase)
		c.Redirect(http.StatusFound, redirectTarget)
	}
}

// @Summary      List authentication providers
// @Description  Returns the list of available authentication providers (OIDC, Azure AD, SAML IdPs, LDAP) for the login page provider picker.
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "List of available providers"
// @Router       /api/v1/auth/providers [get]
// ProvidersHandler returns the list of available authentication providers.
// This is consumed by the frontend to show the login provider picker.
// GET /api/v1/auth/providers
func (h *AuthHandlers) ProvidersHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		providers := make([]gin.H, 0)

		if h.oidcProvider.Load() != nil {
			providers = append(providers, gin.H{
				"type": "oidc",
				"name": "OpenID Connect",
			})
		}

		if h.azureADProvider != nil {
			providers = append(providers, gin.H{
				"type": "azuread",
				"name": "Azure AD",
			})
		}

		for name := range h.samlProviders {
			providers = append(providers, gin.H{
				"type": "saml",
				"name": name,
				"id":   name,
			})
		}

		if h.ldapProvider != nil {
			providers = append(providers, gin.H{
				"type": "ldap",
				"name": "LDAP",
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"providers": providers,
		})
	}
}

// @Summary      LDAP login
// @Description  Authenticates a user via LDAP with username and password. On success, sets an httpOnly auth cookie; the token is never returned in the response body.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        body  body  object{username=string,password=string}  true  "LDAP credentials"
// @Success      200  {object}  map[string]interface{}  "Session established via cookie"
// @Failure      400  {object}  map[string]interface{}  "Missing credentials or LDAP not configured"
// @Failure      401  {object}  map[string]interface{}  "Invalid username or password"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/auth/ldap/login [post]
// LDAPLoginHandler authenticates a user via LDAP with username/password.
// POST /api/v1/auth/ldap/login
// Body: {"username": "...", "password": "..."}
func (h *AuthHandlers) LDAPLoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
			return
		}

		if h.ldapProvider == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "LDAP authentication is not configured"})
			return
		}

		userInfo, err := h.ldapProvider.Authenticate(req.Username, req.Password)
		if err != nil {
			slog.Warn("LDAP authentication failed", "username", req.Username, "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		ctx := c.Request.Context()

		// Use the LDAP DN as the unique subject identifier
		sub := fmt.Sprintf("ldap:%s", userInfo.DN)

		if err := h.guardEmailRebind(ctx, sub, userInfo.Email); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		// A successful LDAP bind against the directory is treated as verifying
		// the returned email, matching this flow's pre-v0.17.0 behavior (no
		// verification gate existed before this parameter was added).
		user, err := h.userRepo.GetOrCreateUserByOIDC(ctx, sub, userInfo.Email, userInfo.Name, true)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up or create your account"})
			return
		}

		// Apply LDAP group mappings
		if mapErr := h.applyLDAPGroupMappings(ctx, user.ID, userInfo.Groups); mapErr != nil {
			slog.Warn("failed to apply LDAP group mappings", "user_id", user.ID, "error", mapErr)
		}

		// Fetch user scopes
		scopes, err := h.orgRepo.GetUserCombinedScopes(ctx, user.ID)
		if err != nil {
			scopes = []string{}
		}

		// Generate JWT
		jwtToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication token"})
			return
		}

		// Set HttpOnly cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "tfr_auth_token",
			Value:    jwtToken,
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Set CSRF cookie
		if _, csrfErr := middleware.SetCSRFCookie(c.Writer, true); csrfErr != nil {
			slog.Error("failed to set CSRF cookie on LDAP login", "error", csrfErr)
		}

		c.JSON(http.StatusOK, gin.H{
			"expires_in": 86400,
		})
	}
}

// applyLDAPGroupMappings reconciles LDAP group DN-to-role mappings for a user,
// delegating to the shared reconcileGroupMemberships. LDAP DNs are matched
// case-insensitively (matching ldappkg.MatchGroupMappings), so DNs are
// lowercased into the provider-agnostic groupMapping before reconciliation.
func (h *AuthHandlers) applyLDAPGroupMappings(ctx context.Context, userID string, groupDNs []string) error {
	mappings := h.cfg.Auth.LDAP.GroupMappings
	gm := make([]groupMapping, len(mappings))
	for i, m := range mappings {
		gm[i] = groupMapping{Group: strings.ToLower(m.GroupDN), Organization: m.Organization, Role: m.Role}
	}
	groups := make([]string, len(groupDNs))
	for i, dn := range groupDNs {
		groups[i] = strings.ToLower(dn)
	}
	return h.reconcileGroupMemberships(ctx, userID, groups, gm, h.cfg.Auth.LDAP.DefaultRole, "LDAP")
}

// @Summary      Identity group mappings
// @Description  Returns read-only SAML and LDAP group-to-role mapping configuration. OIDC mappings are managed separately via the OIDC admin endpoints.
// @Tags         Authentication
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "SAML and LDAP group mapping config"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — requires admin scope"
// @Router       /api/v1/admin/identity/group-mappings [get]
// IdentityGroupMappingsHandler returns read-only group mapping config for all
// identity providers (SAML + LDAP). OIDC mappings are handled separately via
// the OIDCConfigAdminHandlers.
// GET /api/v1/admin/identity/group-mappings
func (h *AuthHandlers) IdentityGroupMappingsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		result := gin.H{}

		// SAML group mappings (from config)
		if h.cfg.Auth.SAML.Enabled {
			samlMappings := make([]gin.H, 0, len(h.cfg.Auth.SAML.GroupMappings))
			for _, m := range h.cfg.Auth.SAML.GroupMappings {
				samlMappings = append(samlMappings, gin.H{
					"group":        m.Group,
					"organization": m.Organization,
					"role":         m.Role,
				})
			}
			result["saml"] = gin.H{
				"group_attribute_name": h.cfg.Auth.SAML.GroupAttributeName,
				"default_role":         h.cfg.Auth.SAML.DefaultRole,
				"group_mappings":       samlMappings,
			}
		}

		// LDAP group mappings (from config)
		if h.cfg.Auth.LDAP.Enabled {
			ldapMappings := make([]gin.H, 0, len(h.cfg.Auth.LDAP.GroupMappings))
			for _, m := range h.cfg.Auth.LDAP.GroupMappings {
				ldapMappings = append(ldapMappings, gin.H{
					"group_dn":     m.GroupDN,
					"organization": m.Organization,
					"role":         m.Role,
				})
			}
			result["ldap"] = gin.H{
				"default_role":   h.cfg.Auth.LDAP.DefaultRole,
				"group_mappings": ldapMappings,
			}
		}

		c.JSON(http.StatusOK, result)
	}
}

// @Summary      mTLS configuration
// @Description  Returns the mTLS certificate-subject to scope mappings from the server configuration (read-only). Shows whether mTLS is enabled and lists all configured subject-to-scope bindings.
// @Tags         Authentication
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "mTLS config with enabled flag, CA file path, and mappings"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — requires admin scope"
// @Router       /api/v1/admin/mtls/config [get]
// MTLSConfigHandler returns the mTLS certificate-subject → scope mappings
// from the server configuration (read-only).
// GET /api/v1/admin/mtls/config
func (h *AuthHandlers) MTLSConfigHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		mappings := make([]gin.H, 0, len(h.cfg.Security.MTLS.Mappings))
		for _, m := range h.cfg.Security.MTLS.Mappings {
			mappings = append(mappings, gin.H{
				"subject": m.Subject,
				"scopes":  m.Scopes,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"enabled":        h.cfg.Security.MTLS.Enabled,
			"client_ca_file": h.cfg.Security.MTLS.ClientCAFile,
			"mappings":       mappings,
		})
	}
}

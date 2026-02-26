// auth.go implements HTTP handlers for OIDC login, OAuth callbacks, token refresh, and logout.
package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// AuthHandlers handles authentication-related endpoints
type AuthHandlers struct {
	cfg             *config.Config
	db              *sql.DB
	userRepo        *repositories.UserRepository
	orgRepo         *repositories.OrganizationRepository
	oidcProvider    atomic.Pointer[oidc.OIDCProvider]
	azureADProvider *azuread.AzureADProvider
	sessionStore    map[string]*SessionState // In-memory for MVP; use Redis in production
}

// SessionState represents OAuth state during authentication flow
type SessionState struct {
	State        string
	CreatedAt    time.Time
	RedirectURL  string
	ProviderType string // "oidc" or "azuread"
}

// NewAuthHandlers creates a new AuthHandlers instance
func NewAuthHandlers(cfg *config.Config, db *sql.DB) (*AuthHandlers, error) {
	h := &AuthHandlers{
		cfg:          cfg,
		db:           db,
		userRepo:     repositories.NewUserRepository(db),
		orgRepo:      repositories.NewOrganizationRepository(db),
		sessionStore: make(map[string]*SessionState),
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

	return h, nil
}

// SetOIDCProvider atomically swaps the active OIDC provider. This is used by
// the setup wizard to activate a newly configured OIDC provider at runtime
// without requiring a server restart.
func (h *AuthHandlers) SetOIDCProvider(provider *oidc.OIDCProvider) {
	h.oidcProvider.Store(provider)
	slog.Info("OIDC provider swapped at runtime")
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
// @Description  Redirect user to OAuth provider (OIDC or Azure AD) to begin authentication flow
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        provider  query  string  false  "OAuth provider: oidc or azuread (default: oidc)"
// @Success      302  {object}  string  "Redirects to OAuth provider authorization URL"
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

		// Store state in session (in-memory for MVP)
		h.sessionStore[state] = &SessionState{
			State:        state,
			CreatedAt:    time.Now(),
			ProviderType: provider,
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
			authURL = oidcProv.GetAuthURL(state)
		case "azuread":
			if h.azureADProvider == nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Azure AD provider not configured",
				})
				return
			}
			authURL = h.azureADProvider.GetAuthURL(state)
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid provider. Must be 'oidc' or 'azuread'",
			})
			return
		}

		// Redirect to authorization URL
		c.Redirect(http.StatusFound, authURL)
	}
}

// @Summary      OAuth callback handler
// @Description  Handles the callback from OAuth provider after user authorizes. Exchanges the authorization code for a JWT and redirects the browser to the frontend /auth/callback page with the token as a query parameter.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        code   query  string  true   "Authorization code from OAuth provider"
// @Param        state  query  string  true   "State parameter for CSRF validation"
// @Success      302  {object}  string  "Redirects to frontend /auth/callback?token=<jwt>"
// @Failure      400  {object}  map[string]interface{}  "Invalid state or authorization code"
// @Failure      401  {object}  map[string]interface{}  "Failed to exchange code for token"
// @Failure      500  {object}  map[string]interface{}  "Database or internal error"
// @Router       /api/v1/auth/callback [get]
// CallbackHandler handles OAuth callback
// GET /api/v1/auth/callback?code=...&state=...
func (h *AuthHandlers) CallbackHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")

		// Validate state
		sessionState, exists := h.sessionStore[state]
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid state parameter",
			})
			return
		}

		// Check state expiration (5 minutes)
		if time.Since(sessionState.CreatedAt) > 5*time.Minute {
			delete(h.sessionStore, state)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "State expired",
			})
			return
		}

		// Delete state to prevent reuse
		delete(h.sessionStore, state)

		ctx := context.Background()

		var sub, email, name string
		var err error
		var oidcGroups []string // populated for OIDC logins when group_claim_name is configured

		// Exchange code for tokens based on provider
		switch sessionState.ProviderType {
		case "oidc":
			oidcProv := h.oidcProvider.Load()
			if oidcProv == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "OIDC provider not configured",
				})
				return
			}

			// Exchange code for token
			token, err := oidcProv.ExchangeCode(ctx, code)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to exchange code for token",
				})
				return
			}

			// Extract ID token
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "No id_token in response",
				})
				return
			}

			// Verify ID token
			idToken, err := oidcProv.VerifyIDToken(ctx, rawIDToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to verify ID token",
				})
				return
			}

			// Extract user info
			sub, email, name, err = oidcProv.ExtractUserInfo(idToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to extract user info",
				})
				return
			}

			// Extract group claims for role mapping (no-op when group_claim_name is not configured)
			oidcGroups = oidcProv.ExtractGroups(idToken, h.cfg.Auth.OIDC.GroupClaimName)

		case "azuread":
			if h.azureADProvider == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Azure AD provider not configured",
				})
				return
			}

			// Exchange code for token
			token, err := h.azureADProvider.ExchangeCode(ctx, code)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to exchange code for token",
				})
				return
			}

			// Extract ID token
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "No id_token in response",
				})
				return
			}

			// Verify ID token
			idToken, err := h.azureADProvider.VerifyIDToken(ctx, rawIDToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to verify ID token",
				})
				return
			}

			// Extract user info
			sub, email, name, err = h.azureADProvider.ExtractUserInfo(idToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to extract user info",
				})
				return
			}

		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid provider type",
			})
			return
		}

		// Get or create user
		user, err := h.userRepo.GetOrCreateUserByOIDC(ctx, sub, email, name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get or create user",
			})
			return
		}

		// Apply OIDC group-to-role mappings (no-op when not configured or no groups extracted)
		if len(oidcGroups) > 0 || h.cfg.Auth.OIDC.DefaultRole != "" {
			if mapErr := h.applyGroupMappings(ctx, user.ID, oidcGroups); mapErr != nil {
				slog.Warn("failed to apply OIDC group mappings", "user_id", user.ID, "error", mapErr)
			}
		}

		// Fetch user scopes to embed in JWT (avoids per-request DB lookup)
		scopes, err := h.orgRepo.GetUserCombinedScopes(ctx, user.ID)
		if err != nil {
			scopes = []string{}
		}

		// Generate JWT token for user
		jwtToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate JWT",
			})
			return
		}

		// Derive the frontend base URL from the OIDC redirect URL (strip the /api/... path)
		// and redirect the browser to the frontend callback page with the JWT in the query string.
		// This completes the authorization code flow in the browser so the SPA can store the token.
		frontendBase := deriveFrontendURL(h.cfg)
		redirectTarget := fmt.Sprintf("%s/auth/callback?token=%s", frontendBase, url.QueryEscape(jwtToken))
		c.Redirect(http.StatusFound, redirectTarget)
	}
}

// @Summary      OIDC logout
// @Description  Clears the local session and, when OIDC is active, redirects the browser to the provider's end_session_endpoint to terminate the SSO session. Falls back to a plain redirect to the frontend login page for non-OIDC setups.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        post_logout_redirect_uri  query  string  false  "URL to redirect to after the provider logs out (defaults to frontend /login)"
// @Success      302  {object}  string  "Redirects to OIDC end_session_endpoint or frontend /login"
// @Router       /api/v1/auth/logout [get]
// LogoutHandler terminates the OIDC SSO session by redirecting to the provider's end_session_endpoint.
// GET /api/v1/auth/logout
func (h *AuthHandlers) LogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
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
// @Description  Exchange existing JWT token for a fresh one with extended expiration
// @Tags         Authentication
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "New JWT token with extended expiration"
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

		// Generate new JWT token
		newToken, err := auth.GenerateJWT(user.ID, user.Email, scopes, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate new token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      newToken,
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
// @Success      200  {object}  map[string]interface{}  "Current user information with memberships and role templates"
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

// applyGroupMappings resolves the user's IdP groups against the configured
// group_mappings and upserts their org memberships accordingly.
//
// Logic per configured mapping:
//   - If the user belongs to the mapped group → ensure they are a member of the
//     mapped organization with the mapped role (insert or update).
//   - Memberships created by a previous login are updated if the role changed.
//
// If no mapping matches any of the user's groups but default_role is set, the
// user is added to (or kept in) the default organization with that role.
//
// Groups/orgs not mentioned in any mapping are left untouched so that manually
// assigned memberships are not wiped by an unrelated login.
func (h *AuthHandlers) applyGroupMappings(ctx context.Context, userID string, groups []string) error {
	cfg := h.cfg.Auth.OIDC
	if len(cfg.GroupMappings) == 0 && cfg.DefaultRole == "" {
		return nil
	}

	// Build a set of the user's groups for O(1) lookup.
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	matched := false

	for _, mapping := range cfg.GroupMappings {
		if _, ok := groupSet[mapping.Group]; !ok {
			continue
		}
		matched = true

		org, err := h.orgRepo.GetByName(ctx, mapping.Organization)
		if err != nil || org == nil {
			slog.Warn("OIDC group mapping: organization not found", "org", mapping.Organization, "group", mapping.Group)
			continue
		}

		isMember, _, err := h.orgRepo.CheckMembership(ctx, org.ID, userID)
		if err != nil {
			return fmt.Errorf("check membership org=%s user=%s: %w", org.ID, userID, err)
		}

		if isMember {
			if err := h.orgRepo.UpdateMemberRole(ctx, org.ID, userID, mapping.Role); err != nil {
				return fmt.Errorf("update member role org=%s user=%s role=%s: %w", org.ID, userID, mapping.Role, err)
			}
		} else {
			if err := h.orgRepo.AddMemberWithParams(ctx, org.ID, userID, mapping.Role); err != nil {
				return fmt.Errorf("add member org=%s user=%s role=%s: %w", org.ID, userID, mapping.Role, err)
			}
		}

		slog.Info("OIDC group mapping applied", "user_id", userID, "group", mapping.Group, "org", mapping.Organization, "role", mapping.Role)
	}

	// Fall back to default_role in the default organization when nothing matched.
	if !matched && cfg.DefaultRole != "" {
		org, err := h.orgRepo.GetDefaultOrganization(ctx)
		if err != nil || org == nil {
			return fmt.Errorf("default organization not found for default_role fallback: %w", err)
		}

		isMember, _, err := h.orgRepo.CheckMembership(ctx, org.ID, userID)
		if err != nil {
			return fmt.Errorf("check membership default org user=%s: %w", userID, err)
		}

		if isMember {
			if err := h.orgRepo.UpdateMemberRole(ctx, org.ID, userID, cfg.DefaultRole); err != nil {
				return fmt.Errorf("update default role user=%s role=%s: %w", userID, cfg.DefaultRole, err)
			}
		} else {
			if err := h.orgRepo.AddMemberWithParams(ctx, org.ID, userID, cfg.DefaultRole); err != nil {
				return fmt.Errorf("add default member user=%s role=%s: %w", userID, cfg.DefaultRole, err)
			}
		}

		slog.Info("OIDC default role applied", "user_id", userID, "role", cfg.DefaultRole)
	}

	return nil
}

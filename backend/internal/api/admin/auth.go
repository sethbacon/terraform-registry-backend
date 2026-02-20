// auth.go implements HTTP handlers for OIDC login, OAuth callbacks, token refresh, and logout.
package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
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
	oidcProvider    *oidc.OIDCProvider
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
		h.oidcProvider = oidcProv
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
			if h.oidcProvider == nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "OIDC provider not configured",
				})
				return
			}
			authURL = h.oidcProvider.GetAuthURL(state)
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
// @Description  Handles the callback from OAuth provider after user authorizes. Internal endpoint - automatically redirected to by OAuth provider.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        code   query  string  true   "Authorization code from OAuth provider"
// @Param        state  query  string  true   "State parameter for CSRF validation"
// @Success      301  {object}  string  "Redirects to frontend with auth token in URL"
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

		// Exchange code for tokens based on provider
		switch sessionState.ProviderType {
		case "oidc":
			if h.oidcProvider == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "OIDC provider not configured",
				})
				return
			}

			// Exchange code for token
			token, err := h.oidcProvider.ExchangeCode(ctx, code)
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
			idToken, err := h.oidcProvider.VerifyIDToken(ctx, rawIDToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to verify ID token",
				})
				return
			}

			// Extract user info
			sub, email, name, err = h.oidcProvider.ExtractUserInfo(idToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to extract user info",
				})
				return
			}

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

		// Generate JWT token for user
		jwtToken, err := auth.GenerateJWT(user.ID, user.Email, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate JWT",
			})
			return
		}

		// Return JWT token
		c.JSON(http.StatusOK, gin.H{
			"token":      jwtToken,
			"user":       user,
			"expires_in": 86400, // 24 hours in seconds
		})
	}
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

		// Generate new JWT token
		newToken, err := auth.GenerateJWT(user.ID, user.Email, 24*time.Hour)
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

// scm_oauth.go implements handlers for initiating SCM OAuth authorization flows, processing callbacks, and storing encrypted tokens.
package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// SCMOAuthHandlers handles SCM OAuth flows
type SCMOAuthHandlers struct {
	cfg         *config.Config
	scmRepo     *repositories.SCMRepository
	userRepo    *repositories.UserRepository
	tokenCipher *crypto.TokenCipher
}

// NewSCMOAuthHandlers creates a new SCM OAuth handlers instance
func NewSCMOAuthHandlers(cfg *config.Config, scmRepo *repositories.SCMRepository, userRepo *repositories.UserRepository, tokenCipher *crypto.TokenCipher) *SCMOAuthHandlers {
	return &SCMOAuthHandlers{
		cfg:         cfg,
		scmRepo:     scmRepo,
		userRepo:    userRepo,
		tokenCipher: tokenCipher,
	}
}

// @Summary      Initiate SCM OAuth
// @Description  Start the OAuth authorization flow for an SCM provider. Returns the authorization URL to redirect the user to. For PAT-based providers, returns guidance on using POST /token instead.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "authorization_url: string, state: string"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/oauth/authorize [get]
// InitiateOAuth starts the OAuth flow for an SCM provider
// GET /api/v1/scm-providers/:id/oauth/authorize
func (h *SCMOAuthHandlers) InitiateOAuth(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	// Get user ID from context (set by auth middleware)
	// Note: user.ID is stored as string, so we parse it to uuid.UUID
	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// PAT-based providers don't use OAuth
	if provider.ProviderType.IsPATBased() {
		c.JSON(http.StatusOK, gin.H{
			"auth_method": "pat",
			"message":     "This provider requires a Personal Access Token. Use POST /api/v1/scm-providers/:id/token to save your PAT.",
		})
		return
	}

	// Build connector
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}

	// Decrypt client secret
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt client secret"})
		return
	}

	tenantID := ""
	if provider.TenantID != nil {
		tenantID = *provider.TenantID
	}

	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    clientSecret,
		CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.cfg.Server.BaseURL, providerID),
		TenantID:        tenantID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Generate authorization URL
	state := fmt.Sprintf("%s:%s", userID, providerID)
	authURL := connector.AuthorizationEndpoint(state, []string{})

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": authURL,
		"state":             state,
	})
}

// @Summary      SCM OAuth callback
// @Description  Processes the OAuth callback from the SCM provider, exchanges the code for tokens, stores them, and redirects to the frontend success page.
// @Tags         SCM OAuth
// @Produce      json
// @Param        id     path   string  true  "SCM provider ID (UUID)"
// @Param        code   query  string  true  "Authorization code from SCM provider"
// @Param        state  query  string  true  "State parameter (userID:providerID)"
// @Success      302    "Redirect to frontend success page"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID, code, or state"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/oauth/callback [get]
// HandleOAuthCallback processes the OAuth callback
// GET /api/v1/scm-providers/:id/oauth/callback
func (h *SCMOAuthHandlers) HandleOAuthCallback(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return
	}

	// Parse state to get user ID (format: "userID:providerID")
	stateParts := strings.SplitN(state, ":", 2)
	if len(stateParts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return
	}
	userID, err := uuid.Parse(stateParts[0])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID in state"})
		return
	}

	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// Decrypt client secret for token exchange
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt client secret"})
		return
	}

	// Build connector
	callbackTenantID := ""
	if provider.TenantID != nil {
		callbackTenantID = *provider.TenantID
	}

	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:         provider.ProviderType,
		ClientID:     provider.ClientID,
		ClientSecret: clientSecret,
		CallbackURL:  fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.cfg.Server.BaseURL, providerID),
		TenantID:     callbackTenantID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Complete OAuth flow
	oauthToken, err := connector.CompleteAuthorization(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("OAuth flow failed: %v", err)})
		return
	}

	// Encrypt access token
	encryptedAccessToken, err := h.tokenCipher.Seal(oauthToken.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt access token"})
		return
	}

	// Encrypt refresh token if present
	var encryptedRefreshToken *string
	if oauthToken.RefreshToken != "" {
		encrypted, err := h.tokenCipher.Seal(oauthToken.RefreshToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt refresh token"})
			return
		}
		encryptedRefreshToken = &encrypted
	}

	// Format scopes as comma-separated string
	scopesStr := ""
	if len(oauthToken.Scopes) > 0 {
		for i, scope := range oauthToken.Scopes {
			if i > 0 {
				scopesStr += ","
			}
			scopesStr += scope
		}
	}

	// Store or update token
	tokenRecord := &scm.SCMUserTokenRecord{
		ID:                    uuid.New(),
		UserID:                userID,
		SCMProviderID:         providerID,
		AccessTokenEncrypted:  encryptedAccessToken,
		RefreshTokenEncrypted: encryptedRefreshToken,
		TokenType:             oauthToken.TokenType,
		ExpiresAt:             oauthToken.ExpiresAt,
		Scopes:                &scopesStr,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	// Check if token already exists
	existingToken, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing token"})
		return
	}

	if existingToken != nil {
		// Update existing token
		tokenRecord.ID = existingToken.ID
		tokenRecord.CreatedAt = existingToken.CreatedAt
		if err := h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update token"})
			return
		}
	} else {
		// Create new token
		if err := h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store token"})
			return
		}
	}

	// Redirect to frontend success page
	redirectURL := fmt.Sprintf("%s/admin/scm-providers/%s/connected", h.cfg.Server.BaseURL, providerID)
	c.Redirect(http.StatusFound, redirectURL)
}

// @Summary      Revoke SCM OAuth token
// @Description  Revoke and delete the current user's OAuth or PAT token for an SCM provider.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: OAuth token revoked"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/oauth/token [delete]
// RevokeOAuth revokes a user's OAuth token for a provider
// DELETE /api/v1/scm-providers/:id/oauth/token
func (h *SCMOAuthHandlers) RevokeOAuth(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	// Get user ID from context
	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	if err := h.scmRepo.DeleteUserToken(c.Request.Context(), userID, providerID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OAuth token revoked"})
}

// @Summary      Refresh SCM OAuth token
// @Description  Manually trigger a refresh of the current user's OAuth token for an SCM provider using the stored refresh token.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: token refreshed, expires_at: time"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Token or provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/oauth/refresh [post]
// RefreshToken manually refreshes an OAuth token
// POST /api/v1/scm-providers/:id/oauth/refresh
func (h *SCMOAuthHandlers) RefreshToken(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	// Get user ID from context
	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get existing token
	tokenRecord, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, providerID)
	if err != nil || tokenRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAuth token not found"})
		return
	}

	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// Decrypt refresh token
	var refreshToken string
	if tokenRecord.RefreshTokenEncrypted != nil {
		refreshToken, err = h.tokenCipher.Open(*tokenRecord.RefreshTokenEncrypted)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt refresh token"})
			return
		}
	}

	// Decrypt client secret
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt client secret"})
		return
	}

	// Build connector
	refreshTenantID := ""
	if provider.TenantID != nil {
		refreshTenantID = *provider.TenantID
	}

	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:         provider.ProviderType,
		ClientID:     provider.ClientID,
		ClientSecret: clientSecret,
		CallbackURL:  fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.cfg.Server.BaseURL, providerID),
		TenantID:     refreshTenantID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Convert scopes string back to array
	var scopes []string
	if tokenRecord.Scopes != nil && *tokenRecord.Scopes != "" {
		for _, scope := range splitString(*tokenRecord.Scopes, ",") {
			scopes = append(scopes, scope)
		}
	}

	// Refresh token using the refresh token string
	newToken, err := connector.RenewToken(context.Background(), refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("token refresh failed: %v", err)})
		return
	}

	// Encrypt new tokens
	encryptedAccessToken, err := h.tokenCipher.Seal(newToken.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt new access token"})
		return
	}

	var encryptedRefreshToken *string
	if newToken.RefreshToken != "" {
		encrypted, err := h.tokenCipher.Seal(newToken.RefreshToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt new refresh token"})
			return
		}
		encryptedRefreshToken = &encrypted
	}

	// Update token record
	tokenRecord.AccessTokenEncrypted = encryptedAccessToken
	tokenRecord.RefreshTokenEncrypted = encryptedRefreshToken
	tokenRecord.ExpiresAt = newToken.ExpiresAt
	tokenRecord.UpdatedAt = time.Now()

	if err := h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "token refreshed",
		"expires_at": newToken.ExpiresAt,
	})
}

// @Summary      Save SCM Personal Access Token
// @Description  Store a Personal Access Token for a PAT-based SCM provider (e.g. Bitbucket Data Center).
// @Tags         SCM OAuth
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "SCM provider ID (UUID)"
// @Param        body  body  object  true  "access_token: string"
// @Success      200  {object}  map[string]interface{}  "message: Personal Access Token saved successfully"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID, request, or not a PAT provider"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/token [post]
// SavePATToken stores a Personal Access Token for a PAT-based SCM provider
// POST /api/v1/scm-providers/:id/token
func (h *SCMOAuthHandlers) SavePATToken(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	// Get user ID from context
	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Parse request
	var req struct {
		AccessToken string `json:"access_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token is required"})
		return
	}

	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// Verify this is a PAT-based provider
	if !provider.ProviderType.IsPATBased() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this provider uses OAuth, not Personal Access Tokens"})
		return
	}

	// Encrypt the PAT
	encryptedToken, err := h.tokenCipher.Seal(req.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt token"})
		return
	}

	patScopes := "repo"
	tokenRecord := &scm.SCMUserTokenRecord{
		ID:                   uuid.New(),
		UserID:               userID,
		SCMProviderID:        providerID,
		AccessTokenEncrypted: encryptedToken,
		TokenType:            "pat",
		Scopes:               &patScopes,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Upsert: check if token already exists
	existingToken, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing token"})
		return
	}

	if existingToken != nil {
		tokenRecord.ID = existingToken.ID
		tokenRecord.CreatedAt = existingToken.CreatedAt
	}

	if err := h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Personal Access Token saved successfully"})
}

// @Summary      Get SCM token status
// @Description  Returns whether the current user is connected to an SCM provider and token metadata (without exposing the token itself).
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "connected: bool, connected_at: time, expires_at: time, token_type: string"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/oauth/token [get]
// GetTokenStatus returns the OAuth connection status for the current user and a provider
// GET /api/v1/scm-providers/:id/oauth/token
func (h *SCMOAuthHandlers) GetTokenStatus(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	token, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get token status"})
		return
	}

	if token == nil {
		c.JSON(http.StatusOK, gin.H{
			"connected":    false,
			"connected_at": nil,
			"expires_at":   nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"connected":    true,
		"connected_at": token.UpdatedAt,
		"expires_at":   token.ExpiresAt,
		"token_type":   token.TokenType,
	})
}

// @Summary      List SCM repositories
// @Description  List repositories available to the current user from an SCM provider. Optionally search by name.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id      path   string  true   "SCM provider ID (UUID)"
// @Param        search  query  string  false  "Search query to filter repositories by name"
// @Success      200  {object}  map[string]interface{}  "repositories: [{id, name, full_name, owner, ...}]"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized or not connected to provider"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/repositories [get]
// ListRepositories lists repositories from the SCM provider
// GET /api/v1/scm-providers/:id/repositories
func (h *SCMOAuthHandlers) ListRepositories(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// Get user's token for this provider
	tokenRecord, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, providerID)
	if err != nil || tokenRecord == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not connected to this provider"})
		return
	}

	// Decrypt the access token
	accessToken, err := h.tokenCipher.Open(tokenRecord.AccessTokenEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt access token"})
		return
	}

	// Decrypt client secret
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt client secret"})
		return
	}

	// Build connector
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}

	tenantID := ""
	if provider.TenantID != nil {
		tenantID = *provider.TenantID
	}

	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    clientSecret,
		CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.cfg.Server.BaseURL, providerID),
		TenantID:        tenantID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Create AccessToken from the decrypted token
	token := &scm.AccessToken{
		AccessToken: accessToken,
		TokenType:   tokenRecord.TokenType,
		ExpiresAt:   tokenRecord.ExpiresAt,
	}

	// Parse refresh token if present
	if tokenRecord.RefreshTokenEncrypted != nil {
		refreshToken, err := h.tokenCipher.Open(*tokenRecord.RefreshTokenEncrypted)
		if err == nil {
			token.RefreshToken = refreshToken
		}
	}

	// Parse scopes if present
	if tokenRecord.Scopes != nil && *tokenRecord.Scopes != "" {
		token.Scopes = splitString(*tokenRecord.Scopes, ",")
	}

	// Get search query parameter
	search := c.Query("search")

	// doFetch calls the appropriate connector method based on whether a search term is present.
	doFetch := func(tok *scm.AccessToken) (*scm.RepoListResult, error) {
		if search != "" {
			return connector.SearchRepositories(c.Request.Context(), tok, search, scm.DefaultPagination())
		}
		return connector.FetchRepositories(c.Request.Context(), tok, scm.DefaultPagination())
	}

	// tryRefresh attempts to exchange the stored refresh token for a new access token and
	// persists the result. It updates token in-place and returns true on success.
	tryRefresh := func() bool {
		if token.RefreshToken == "" {
			return false
		}
		newToken, renewErr := connector.RenewToken(c.Request.Context(), token.RefreshToken)
		if renewErr != nil {
			return false
		}
		if encAccess, encErr := h.tokenCipher.Seal(newToken.AccessToken); encErr == nil {
			tokenRecord.AccessTokenEncrypted = encAccess
			tokenRecord.ExpiresAt = newToken.ExpiresAt
			tokenRecord.UpdatedAt = time.Now()
			if newToken.RefreshToken != "" {
				if encRefresh, rErr := h.tokenCipher.Seal(newToken.RefreshToken); rErr == nil {
					tokenRecord.RefreshTokenEncrypted = &encRefresh
				}
			}
			_ = h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord)
			token.AccessToken = newToken.AccessToken
			token.RefreshToken = newToken.RefreshToken
			token.ExpiresAt = newToken.ExpiresAt
			return true
		}
		return false
	}

	// Proactively refresh if the token is expired or within 60 seconds of expiry.
	// This avoids making a doomed API call and then having to retry after a 401.
	if token.RefreshToken != "" && token.ExpiresAt != nil && time.Now().After(token.ExpiresAt.Add(-60*time.Second)) {
		tryRefresh()
	}

	// List repositories, with a silent token refresh on auth failure.
	// GitLab and Azure DevOps issue refresh tokens; GitHub tokens do not expire so
	// RenewToken returns ErrTokenRefreshFailed immediately for GitHub providers.
	var repos *scm.RepoListResult
	repos, err = doFetch(token)
	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) &&
			(apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden) &&
			token.RefreshToken != "" {
			// Try to exchange the stored refresh token for a new access token and retry.
			if tryRefresh() {
				repos, err = doFetch(token)
			}
		}
	}

	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNonAuthoritativeInfo) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth token is invalid or has been revoked; please reconnect to this SCM provider"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list repositories: %v", err)})
		return
	}

	// Convert to frontend-friendly format
	repositories := make([]gin.H, len(repos.Repos))
	for i, repo := range repos.Repos {
		repositories[i] = gin.H{
			"id":             repo.ID,
			"name":           repo.Name,
			"full_name":      repo.FullName,
			"owner":          repo.Owner,
			"description":    repo.Description,
			"default_branch": repo.DefaultBranch,
			"clone_url":      repo.CloneURL,
			"html_url":       repo.HTMLURL,
			"private":        repo.Private,
		}
	}

	c.JSON(http.StatusOK, gin.H{"repositories": repositories})
}

// getUserIDFromContext extracts the user ID from the Gin context.
// The auth middleware stores user.ID as a string, so we parse it to uuid.UUID.
func getUserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	userIDValue, exists := c.Get("user_id")
	if !exists {
		return uuid.UUID{}, false
	}
	switch v := userIDValue.(type) {
	case uuid.UUID:
		return v, true
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			return uuid.UUID{}, false
		}
		return parsed, true
	default:
		return uuid.UUID{}, false
	}
}

// @Summary      List repository tags
// @Description  List tags (version tags) for a specific repository from an SCM provider. Used during module linking to select which tags to publish.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id     path   string  true  "SCM provider ID (UUID)"
// @Param        owner  path   string  true  "Repository owner/organization"
// @Param        repo   path   string  true  "Repository name"
// @Success      200  {object}  map[string]interface{}  "tags: [{name, commit_sha, commit_message, created_at, tagger}]"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID or missing parameters"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized or not connected to provider"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/repositories/{owner}/{repo}/tags [get]
// ListRepositoryTags lists tags for a specific repository
// GET /api/v1/scm-providers/:id/repositories/:owner/:repo/tags
func (h *SCMOAuthHandlers) ListRepositoryTags(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")
	if owner == "" || repo == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "owner and repo are required"})
		return
	}

	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get provider and token
	connector, token, tokenRecord, err := h.buildConnectorWithToken(c.Request.Context(), providerID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// List tags, with a silent token refresh on auth failure.
	tags, err := connector.FetchTags(c.Request.Context(), token, owner, repo, scm.DefaultPagination())
	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) &&
			(apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNonAuthoritativeInfo) &&
			token.RefreshToken != "" {
			if newToken, renewErr := h.refreshAndPersistToken(c.Request.Context(), connector, tokenRecord); renewErr == nil {
				token.AccessToken = newToken.AccessToken
				token.RefreshToken = newToken.RefreshToken
				token.ExpiresAt = newToken.ExpiresAt
				tags, err = connector.FetchTags(c.Request.Context(), token, owner, repo, scm.DefaultPagination())
			}
		}
	}
	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNonAuthoritativeInfo) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth token is invalid or has been revoked; please reconnect to this SCM provider"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list tags: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// @Summary      List repository branches
// @Description  List branches for a specific repository from an SCM provider. Used during module linking to select the default branch.
// @Tags         SCM OAuth
// @Security     Bearer
// @Produce      json
// @Param        id     path   string  true  "SCM provider ID (UUID)"
// @Param        owner  path   string  true  "Repository owner/organization"
// @Param        repo   path   string  true  "Repository name"
// @Success      200  {object}  map[string]interface{}  "branches: [{name, commit_sha, protected}]"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID or missing parameters"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized or not connected to provider"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id}/repositories/{owner}/{repo}/branches [get]
// ListRepositoryBranches lists branches for a specific repository
// GET /api/v1/scm-providers/:id/repositories/:owner/:repo/branches
func (h *SCMOAuthHandlers) ListRepositoryBranches(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	owner := c.Param("owner")
	repo := c.Param("repo")
	if owner == "" || repo == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "owner and repo are required"})
		return
	}

	userID, ok := getUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get provider and token
	connector, token, tokenRecord, err := h.buildConnectorWithToken(c.Request.Context(), providerID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// List branches, with a silent token refresh on auth failure.
	branches, err := connector.FetchBranches(c.Request.Context(), token, owner, repo, scm.DefaultPagination())
	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) &&
			(apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNonAuthoritativeInfo) &&
			token.RefreshToken != "" {
			if newToken, renewErr := h.refreshAndPersistToken(c.Request.Context(), connector, tokenRecord); renewErr == nil {
				token.AccessToken = newToken.AccessToken
				token.RefreshToken = newToken.RefreshToken
				token.ExpiresAt = newToken.ExpiresAt
				branches, err = connector.FetchBranches(c.Request.Context(), token, owner, repo, scm.DefaultPagination())
			}
		}
	}
	if err != nil {
		var apiErr *scm.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusNonAuthoritativeInfo) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth token is invalid or has been revoked; please reconnect to this SCM provider"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list branches: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"branches": branches})
}

// refreshAndPersistToken uses the refresh token to obtain a new access token and
// persists the updated record to the database. It returns the new OAuthToken.
func (h *SCMOAuthHandlers) refreshAndPersistToken(ctx context.Context, connector scm.Connector, tokenRecord *scm.SCMUserTokenRecord) (*scm.OAuthToken, error) {
	if tokenRecord.RefreshTokenEncrypted == nil {
		return nil, fmt.Errorf("no refresh token available")
	}
	refreshToken, err := h.tokenCipher.Open(*tokenRecord.RefreshTokenEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}
	newToken, err := connector.RenewToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	// Encrypt and persist the new credentials.
	encAccess, err := h.tokenCipher.Seal(newToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt new access token: %w", err)
	}
	tokenRecord.AccessTokenEncrypted = encAccess
	tokenRecord.ExpiresAt = newToken.ExpiresAt
	tokenRecord.UpdatedAt = time.Now()
	if newToken.RefreshToken != "" {
		if encRefresh, rErr := h.tokenCipher.Seal(newToken.RefreshToken); rErr == nil {
			tokenRecord.RefreshTokenEncrypted = &encRefresh
		}
	}
	_ = h.scmRepo.SaveUserToken(ctx, tokenRecord)
	return newToken, nil
}

// buildConnectorWithToken is a helper to build an SCM connector with a user's OAuth token.
// If the stored token is already expired it will attempt a proactive refresh before returning.
func (h *SCMOAuthHandlers) buildConnectorWithToken(ctx context.Context, providerID, userID uuid.UUID) (scm.Connector, *scm.OAuthToken, *scm.SCMUserTokenRecord, error) {
	// Get provider configuration
	provider, err := h.scmRepo.GetProvider(ctx, providerID)
	if err != nil || provider == nil {
		return nil, nil, nil, fmt.Errorf("provider not found")
	}

	// Get user's token for this provider
	tokenRecord, err := h.scmRepo.GetUserToken(ctx, userID, providerID)
	if err != nil || tokenRecord == nil {
		return nil, nil, nil, fmt.Errorf("not connected to this provider")
	}

	// Decrypt the access token
	accessToken, err := h.tokenCipher.Open(tokenRecord.AccessTokenEncrypted)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt access token")
	}

	// Decrypt client secret
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt client secret")
	}

	// Build connector
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}

	tenantID := ""
	if provider.TenantID != nil {
		tenantID = *provider.TenantID
	}

	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    clientSecret,
		CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.cfg.Server.BaseURL, providerID),
		TenantID:        tenantID,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create connector")
	}

	// Create AccessToken from the decrypted token
	token := &scm.OAuthToken{
		AccessToken: accessToken,
		TokenType:   tokenRecord.TokenType,
		ExpiresAt:   tokenRecord.ExpiresAt,
	}

	// Parse refresh token if present
	if tokenRecord.RefreshTokenEncrypted != nil {
		refreshToken, err := h.tokenCipher.Open(*tokenRecord.RefreshTokenEncrypted)
		if err == nil {
			token.RefreshToken = refreshToken
		}
	}

	// Parse scopes if present
	if tokenRecord.Scopes != nil && *tokenRecord.Scopes != "" {
		token.Scopes = splitString(*tokenRecord.Scopes, ",")
	}

	// Proactively refresh if the token is already expired or expires within 5 minutes.
	if token.RefreshToken != "" && (token.IsExpired() || (token.ExpiresAt != nil && time.Until(*token.ExpiresAt) < 5*time.Minute)) {
		if newToken, err := h.refreshAndPersistToken(ctx, connector, tokenRecord); err == nil {
			token.AccessToken = newToken.AccessToken
			token.RefreshToken = newToken.RefreshToken
			token.ExpiresAt = newToken.ExpiresAt
		}
		// If refresh fails, continue with the existing token — the caller will surface the auth error.
	}

	return connector, token, tokenRecord, nil
}
func splitString(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	result := []string{}
	current := ""
	for _, char := range s {
		if string(char) == sep {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

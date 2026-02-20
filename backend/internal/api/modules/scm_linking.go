// scm_linking.go handles linking modules to their SCM source repositories and managing OAuth-based repository connections.
package modules

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// SCMLinkingHandler handles module-SCM repository linking
type SCMLinkingHandler struct {
	scmRepo     *repositories.SCMRepository
	moduleRepo  *repositories.ModuleRepository
	tokenCipher *crypto.TokenCipher
	publicURL   string
	publisher   *services.SCMPublisher
}

// NewSCMLinkingHandler creates a new SCM linking handler
func NewSCMLinkingHandler(scmRepo *repositories.SCMRepository, moduleRepo *repositories.ModuleRepository, tokenCipher *crypto.TokenCipher, publicURL string, publisher *services.SCMPublisher) *SCMLinkingHandler {
	return &SCMLinkingHandler{
		scmRepo:     scmRepo,
		moduleRepo:  moduleRepo,
		tokenCipher: tokenCipher,
		publicURL:   publicURL,
		publisher:   publisher,
	}
}

type LinkSCMRequest struct {
	SCMProviderID   string `json:"provider_id" binding:"required"`
	RepositoryOwner string `json:"repository_owner" binding:"required"`
	RepositoryName  string `json:"repository_name" binding:"required"`
	DefaultBranch   string `json:"default_branch"`
	ModulePath      string `json:"repository_path"`
	TagPattern      string `json:"tag_pattern"`
	AutoPublish     bool   `json:"auto_publish_enabled"`
}

// @Summary      Link module to SCM repository
// @Description  Link a module to a source repository in an SCM provider. Generates a unique webhook callback URL
// @Description  (containing an embedded URL secret) that must be registered in the repository's webhook settings.
// @Description  The module must not already be linked. Validates that both the module and the SCM provider exist.
// @Tags         SCM Linking
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string          true  "Module ID (UUID)"
// @Param        body  body  LinkSCMRequest  true  "Repository link configuration"
// @Success      201  {object}  map[string]interface{}  "link_id (UUID), webhook_callback_url, note, message"
// @Failure      400  {object}  map[string]interface{}  "Invalid module or provider ID, or malformed request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found or SCM provider not found"
// @Failure      409  {object}  map[string]interface{}  "Module is already linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id}/scm [post]
// LinkModuleToSCM links a module to an SCM repository
// POST /api/v1/admin/modules/:id/scm
func (h *SCMLinkingHandler) LinkModuleToSCM(c *gin.Context) {
	moduleIDStr := c.Param("id")
	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	var req LinkSCMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	providerID, err := uuid.Parse(req.SCMProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid SCM provider ID"})
		return
	}

	existingModule, err := h.moduleRepo.GetModuleByID(c.Request.Context(), moduleID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get module"})
		return
	}
	if existingModule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module not found"})
		return
	}

	// Check if SCM provider exists
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get SCM provider"})
		return
	}
	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SCM provider not found"})
		return
	}

	// Check if module is already linked
	existing, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing link"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "module is already linked to a repository"})
		return
	}

	// Set defaults
	if req.DefaultBranch == "" {
		req.DefaultBranch = "main"
	}
	if req.ModulePath == "" {
		req.ModulePath = "/"
	}
	if req.TagPattern == "" {
		req.TagPattern = "v*"
	}

	// Create the webhook secret
	webhookSecret := generateWebhookSecret()

	// Create module source repo link
	linkID := uuid.New()
	repoFullURL := fmt.Sprintf("%s/%s/%s", *provider.BaseURL, req.RepositoryOwner, req.RepositoryName)
	webhookCallbackURL := fmt.Sprintf("%s/webhooks/scm/%s/%s", h.publicURL, linkID, webhookSecret)

	link := &scm.ModuleSourceRepoRecord{
		ID:              linkID,
		ModuleID:        moduleID,
		SCMProviderID:   providerID,
		RepositoryOwner: req.RepositoryOwner,
		RepositoryName:  req.RepositoryName,
		RepositoryURL:   &repoFullURL,
		DefaultBranch:   req.DefaultBranch,
		ModulePath:      req.ModulePath,
		TagPattern:      req.TagPattern,
		AutoPublish:     req.AutoPublish,
		WebhookURL:      &webhookCallbackURL,
		WebhookEnabled:  false, // Will be activated after webhook registration
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := h.scmRepo.CreateModuleSourceRepo(c.Request.Context(), link); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create repository link"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":              "module linked to repository",
		"link_id":              linkID,
		"webhook_callback_url": webhookCallbackURL,
		"note":                 "Register this webhook URL in your repository settings",
	})
}

// @Summary      Update SCM repository link
// @Description  Update the configuration of an existing SCM repository link for a module.
// @Tags         SCM Linking
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string          true  "Module ID (UUID)"
// @Param        body  body  LinkSCMRequest  true  "Updated repository link configuration"
// @Success      200  {object}  map[string]interface{}  "message: repository link updated"
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID or request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id}/scm [put]
// UpdateSCMLink updates the SCM link configuration
// PUT /api/v1/admin/modules/:id/scm
func (h *SCMLinkingHandler) UpdateSCMLink(c *gin.Context) {
	moduleIDStr := c.Param("id")
	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	var req LinkSCMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing link
	link, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module is not linked to a repository"})
		return
	}

	// Update fields
	link.RepositoryOwner = req.RepositoryOwner
	link.RepositoryName = req.RepositoryName
	link.DefaultBranch = req.DefaultBranch
	link.ModulePath = req.ModulePath
	link.TagPattern = req.TagPattern
	link.AutoPublish = req.AutoPublish

	if err := h.scmRepo.UpdateModuleSourceRepo(c.Request.Context(), link); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update repository link"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "repository link updated"})
}

// @Summary      Unlink module from SCM repository
// @Description  Remove the SCM repository link from a module, disabling all webhook-based and manual syncing.
// @Description  If the link has a registered webhook ID, a best-effort request is made to delete the webhook from
// @Description  the SCM provider using the calling user's OAuth token. Webhook removal failure is non-fatal — the
// @Description  database link record is always deleted regardless of whether the remote call succeeds.
// @Tags         SCM Linking
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: module unlinked from repository"
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id}/scm [delete]
// UnlinkModuleFromSCM removes the SCM repository link
// DELETE /api/v1/admin/modules/:id/scm
func (h *SCMLinkingHandler) UnlinkModuleFromSCM(c *gin.Context) {
	moduleIDStr := c.Param("id")
	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	// Get existing link
	link, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module is not linked to a repository"})
		return
	}

	// Attempt best-effort webhook removal from the SCM provider.
	// Failure here is non-fatal: we still proceed to delete the DB record.
	if link.WebhookID != nil {
		provider, provErr := h.scmRepo.GetProvider(c.Request.Context(), link.SCMProviderID)
		userID, uidErr := getUserIDFromContext(c)
		if provErr == nil && provider != nil && uidErr == nil {
			tokenRecord, tokErr := h.scmRepo.GetUserToken(c.Request.Context(), userID, link.SCMProviderID)
			if tokErr == nil && tokenRecord != nil {
				if accessToken, decErr := h.tokenCipher.Open(tokenRecord.AccessTokenEncrypted); decErr == nil {
					clientSecret, csErr := h.tokenCipher.Open(provider.ClientSecretEncrypted)
					if csErr == nil {
						baseURL := ""
						if provider.BaseURL != nil {
							baseURL = *provider.BaseURL
						}
						tenantID := ""
						if provider.TenantID != nil {
							tenantID = *provider.TenantID
						}
						connector, connErr := scm.BuildConnector(&scm.ConnectorSettings{
							Kind:            provider.ProviderType,
							InstanceBaseURL: baseURL,
							ClientID:        provider.ClientID,
							ClientSecret:    clientSecret,
							CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.publicURL, link.SCMProviderID),
							TenantID:        tenantID,
						})
						if connErr == nil {
							token := &scm.OAuthToken{
								AccessToken: accessToken,
								TokenType:   tokenRecord.TokenType,
								ExpiresAt:   tokenRecord.ExpiresAt,
							}
							if rmErr := connector.RemoveWebhook(c.Request.Context(), token, link.RepositoryOwner, link.RepositoryName, *link.WebhookID); rmErr != nil {
								fmt.Printf("[UnlinkModuleFromSCM] Warning: failed to remove webhook %s from %s/%s: %v\n",
									*link.WebhookID, link.RepositoryOwner, link.RepositoryName, rmErr)
							}
						}
					}
				}
			}
		}
	}

	// Delete the link
	if err := h.scmRepo.DeleteModuleSourceRepo(c.Request.Context(), moduleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete repository link"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "module unlinked from repository"})
}

// @Summary      Get module SCM link info
// @Description  Retrieve the SCM repository link configuration and webhook details for a module.
// @Tags         SCM Linking
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module ID (UUID)"
// @Success      200  {object}  scm.ModuleSourceRepoRecord  "Repository link details including webhook URL and status"
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id}/scm [get]
// GetModuleSCMInfo retrieves the SCM link information for a module
// GET /api/v1/admin/modules/:id/scm
func (h *SCMLinkingHandler) GetModuleSCMInfo(c *gin.Context) {
	moduleIDStr := c.Param("id")
	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	link, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module is not linked to a repository"})
		return
	}

	c.JSON(http.StatusOK, link)
}

// @Summary      Trigger manual SCM sync
// @Description  Manually trigger an asynchronous repository scan that imports matching tag-based versions from the
// @Description  linked SCM repository. The endpoint returns 202 immediately; the sync runs in the background.
// @Description  Tags are matched against the configured pattern (default: v*) and the semantic version is extracted.
// @Description  Versions that already exist in the registry are silently skipped. The caller's OAuth token is used
// @Description  for SCM API access and is proactively refreshed if it is expired or within 5 minutes of expiry.
// @Tags         SCM Linking
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module ID (UUID)"
// @Success      202  {object}  map[string]interface{}  "message: sync triggered"
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized or no OAuth token for this SCM provider"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error (connector build, token decryption, etc.)"
// @Router       /api/v1/admin/modules/{id}/scm/sync [post]
// TriggerManualSync manually triggers a repository sync
// POST /api/v1/admin/modules/:id/scm/sync
func (h *SCMLinkingHandler) TriggerManualSync(c *gin.Context) {
	moduleIDStr := c.Param("id")
	fmt.Printf("TriggerManualSync called for module ID: %s\n", moduleIDStr)

	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		fmt.Printf("Invalid module ID: %s\n", moduleIDStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	link, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module is not linked to a repository"})
		return
	}

	// Get the SCM provider
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), link.SCMProviderID)
	if err != nil || provider == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "provider not found"})
		return
	}

	// Get user ID from context
	userID, err := getUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Get user's OAuth token for this provider
	tokenRecord, err := h.scmRepo.GetUserToken(c.Request.Context(), userID, link.SCMProviderID)
	if err != nil || tokenRecord == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not connected to this SCM provider"})
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
		CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.publicURL, link.SCMProviderID),
		TenantID:        tenantID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Create OAuth token
	token := &scm.OAuthToken{
		AccessToken: accessToken,
		TokenType:   tokenRecord.TokenType,
		ExpiresAt:   tokenRecord.ExpiresAt,
	}

	// Parse refresh token if present
	var decryptedRefreshToken string
	if tokenRecord.RefreshTokenEncrypted != nil {
		if rt, err := h.tokenCipher.Open(*tokenRecord.RefreshTokenEncrypted); err == nil {
			token.RefreshToken = rt
			decryptedRefreshToken = rt
		}
	}

	// Proactively refresh if the token is expired or expires within 5 minutes.
	if decryptedRefreshToken != "" && (token.IsExpired() || (token.ExpiresAt != nil && time.Until(*token.ExpiresAt) < 5*time.Minute)) {
		fmt.Printf("[TriggerManualSync] Token expired/expiring soon, refreshing...\n")
		if newToken, err := connector.RenewToken(c.Request.Context(), decryptedRefreshToken); err == nil {
			token.AccessToken = newToken.AccessToken
			token.RefreshToken = newToken.RefreshToken
			token.ExpiresAt = newToken.ExpiresAt
			// Persist the refreshed token so future requests don't need to refresh again.
			if encAccess, err := h.tokenCipher.Seal(newToken.AccessToken); err == nil {
				tokenRecord.AccessTokenEncrypted = encAccess
				tokenRecord.ExpiresAt = newToken.ExpiresAt
				tokenRecord.UpdatedAt = time.Now()
				if newToken.RefreshToken != "" {
					if encRefresh, err := h.tokenCipher.Seal(newToken.RefreshToken); err == nil {
						tokenRecord.RefreshTokenEncrypted = &encRefresh
					}
				}
				_ = h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord)
				fmt.Printf("[TriggerManualSync] Token refreshed successfully\n")
			}
		} else {
			fmt.Printf("[TriggerManualSync] Token refresh failed: %v\n", err)
		}
	}

	// Trigger async sync in background using a new context
	// (c.Request.Context() would be canceled when the HTTP response is sent)
	fmt.Printf("Starting async sync for module %s (repo: %s/%s)\n", moduleID, link.RepositoryOwner, link.RepositoryName)
	go func() {
		fmt.Printf("Running sync in goroutine for module %s\n", moduleID)
		if err := h.publisher.TriggerManualSync(context.Background(), link, connector, token); err != nil {
			// Log error but don't fail the request
			fmt.Printf("Manual sync failed for module %s: %v\n", moduleID, err)
		} else {
			fmt.Printf("Manual sync completed successfully for module %s\n", moduleID)
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": "sync triggered"})
}

// @Summary      Get webhook event history
// @Description  Retrieve the recent webhook event log for a module's SCM repository link (last 50 events).
// @Tags         SCM Linking
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "events: []WebhookLog"
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id}/scm/events [get]
// GetWebhookEvents retrieves webhook event history for a module
// GET /api/v1/admin/modules/:id/scm/events
func (h *SCMLinkingHandler) GetWebhookEvents(c *gin.Context) {
	moduleIDStr := c.Param("id")
	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid module ID"})
		return
	}

	link, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), moduleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module is not linked to a repository"})
		return
	}

	limit := 50 // Default limit
	events, err := h.scmRepo.ListWebhookLogs(c.Request.Context(), link.ID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get webhook events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

func generateWebhookSecret() string {
	return uuid.New().String()
}

// getUserIDFromContext extracts the user ID from the Gin context
func getUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	userIDValue, exists := c.Get("user_id")
	if !exists {
		return uuid.UUID{}, fmt.Errorf("user not authenticated")
	}
	switch v := userIDValue.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("invalid user ID format")
		}
		return parsed, nil
	default:
		return uuid.UUID{}, fmt.Errorf("unexpected user ID type")
	}
}

// scm_linking.go handles linking modules to their SCM source repositories and managing OAuth-based repository connections.
package modules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// SCMLinkingHandler handles module-SCM repository linking
type SCMLinkingHandler struct {
	scmRepo     *repositories.SCMRepository
	moduleRepo  *repositories.ModuleRepository
	tokenCipher *crypto.TokenCipher
	publicURL   string
	publisher   *services.SCMPublisher
	minter      appcreds.SharedMinter
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

// WithMinter wires in the shared app-credential minter used by providers in an
// app auth mode (entra_app/github_app). Returns the handler for chaining.
func (h *SCMLinkingHandler) WithMinter(minter appcreds.SharedMinter) *SCMLinkingHandler {
	h.minter = minter
	return h
}

// connectorAndToken builds an SCM connector for a provider and resolves an access
// token for it. Providers in an app auth mode (entra_app/github_app) mint the
// shared, admin-managed credential; legacy oauth_user providers use the requesting
// user's stored personal token. For an oauth_user provider with no stored token
// for the user, the returned token is nil (with a nil error) so best-effort
// callers can treat the operation as a no-op.
func (h *SCMLinkingHandler) connectorAndToken(ctx context.Context, provider *scm.SCMProviderRecord, userID uuid.UUID) (scm.Connector, *scm.OAuthToken, error) {
	clientSecret, _, err := h.tokenCipher.OpenWithContextOrLegacy(
		provider.ClientSecretEncrypted, scm.ProviderClientSecretContext(provider.ID.String()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt client secret")
	}
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
		CallbackURL:     fmt.Sprintf("%s/api/v1/scm-providers/%s/oauth/callback", h.publicURL, provider.ID),
		TenantID:        tenantID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connector")
	}

	// App-mode: shared credential, no per-user token needed.
	if provider.AuthMode == scm.AuthModeEntraApp || provider.AuthMode == scm.AuthModeGitHubApp {
		if h.minter == nil {
			return nil, nil, fmt.Errorf("shared app credentials not available")
		}
		token, mErr := h.minter.MintProviderToken(ctx, provider)
		if mErr != nil {
			return nil, nil, fmt.Errorf("failed to mint shared token: %w", mErr)
		}
		return connector, token, nil
	}

	// Legacy oauth_user: requesting user's stored token (may be absent).
	tokenRecord, err := h.scmRepo.GetUserToken(ctx, userID, provider.ID)
	if err != nil || tokenRecord == nil {
		return connector, nil, nil
	}
	accessToken, _, err := h.tokenCipher.OpenWithContextOrLegacy(
		tokenRecord.AccessTokenEncrypted, scm.UserTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID))
	if err != nil {
		return connector, nil, nil
	}
	token := &scm.OAuthToken{
		AccessToken: accessToken,
		TokenType:   tokenRecord.TokenType,
		ExpiresAt:   tokenRecord.ExpiresAt,
	}
	if tokenRecord.RefreshTokenEncrypted != nil {
		if rt, _, rErr := h.tokenCipher.OpenWithContextOrLegacy(
			*tokenRecord.RefreshTokenEncrypted, scm.UserRefreshTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID)); rErr == nil {
			token.RefreshToken = rt
		}
	}
	return connector, token, nil
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
// @Success      201  {object}  modules.LinkModuleSCMResponse
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

	// The route's RequireModuleAccessByID guard authorized the caller against
	// the MODULE's owning organization and published it as owner_org_id; the
	// provider side was previously unchecked, so a caller authorized for their
	// own module could bind it to another organization's SCM provider (issue
	// #719). That link is durable and credential-bearing: syncs would then run
	// against the other organization's provider credentials.
	//
	// Rejected for every caller including platform admins, deliberately
	// departing from this codebase's usual admin-bypass convention: this is not
	// "act on one organization's resource" (which admin may do) but "create a
	// persistent cross-tenant credential path", which nothing in the product
	// needs and which would be invisible after the fact.
	if ownerOrgVal, exists := c.Get("owner_org_id"); exists {
		ownerOrgID, _ := ownerOrgVal.(string)
		providerOrgID := ""
		if provider.OrganizationID != uuid.Nil {
			providerOrgID = provider.OrganizationID.String()
		}
		if ownerOrgID != "" && providerOrgID != "" && ownerOrgID != providerOrgID {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "SCM provider belongs to a different organization than the module",
			})
			return
		}
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
		req.DefaultBranch = h.detectDefaultBranch(c.Request.Context(), c, provider, req.RepositoryOwner, req.RepositoryName)
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

	// Resolve the display URL for the repository. When the provider record has no
	// base_url set, fall back to the well-known default for providers that have one
	// (GitHub.com, GitLab.com, Azure DevOps). This avoids a nil-pointer panic while
	// also producing a sensible display URL for the common case where the provider
	// was registered without an explicit base_url (i.e. cloud instances).
	// RepositoryURL is display-only and is never used for API calls.
	repoBaseURL := ""
	if provider.BaseURL != nil && *provider.BaseURL != "" {
		repoBaseURL = *provider.BaseURL
	} else {
		switch provider.ProviderType {
		case scm.ProviderGitHub:
			repoBaseURL = "https://github.com"
		case scm.ProviderGitLab:
			repoBaseURL = "https://gitlab.com"
		case scm.ProviderAzureDevOps:
			repoBaseURL = "https://dev.azure.com"
		}
	}
	var repoFullURL *string
	if repoBaseURL != "" {
		u := fmt.Sprintf("%s/%s/%s", repoBaseURL, req.RepositoryOwner, req.RepositoryName)
		repoFullURL = &u
	}
	webhookCallbackURL := fmt.Sprintf("%s/webhooks/scm/%s/%s", h.publicURL, linkID, webhookSecret)

	link := &scm.ModuleSourceRepoRecord{
		ID:              linkID,
		ModuleID:        moduleID,
		SCMProviderID:   providerID,
		RepositoryOwner: req.RepositoryOwner,
		RepositoryName:  req.RepositoryName,
		RepositoryURL:   repoFullURL,
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

	// Attempt to auto-register the webhook with the SCM provider (non-fatal on failure).
	webhookRegistered := false
	userID, uidErr := getUserIDFromContext(c)
	if uidErr == nil {
		if connector, token, connErr := h.connectorAndToken(c.Request.Context(), provider, userID); connErr == nil && token != nil {
			hookInfo, regErr := connector.RegisterWebhook(c.Request.Context(), token, req.RepositoryOwner, req.RepositoryName, scm.WebhookSetup{
				CallbackURL:   webhookCallbackURL,
				SharedSecret:  provider.WebhookSecret,
				EventTypes:    []string{"push"},
				ActiveOnSetup: true,
			})
			if regErr == nil && hookInfo != nil {
				webhookRegistered = true
				link.WebhookID = &hookInfo.ExternalID
				link.WebhookEnabled = true
				if updErr := h.scmRepo.UpdateModuleSourceRepo(c.Request.Context(), link); updErr != nil {
					slog.Warn("webhook registered but failed to persist state", "link_id", linkID, "webhook_id", hookInfo.ExternalID, "error", updErr)
				}
			} else if regErr != nil {
				slog.Warn("auto-register webhook failed", "provider_type", provider.ProviderType, "owner", req.RepositoryOwner, "repo", req.RepositoryName, "error", regErr)
			}
		}
	}

	webhookNote := "Webhook registered automatically"
	if !webhookRegistered {
		webhookNote = "Auto-registration unavailable; register the webhook URL manually in your repository settings"
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":              "module linked to repository",
		"link_id":              linkID,
		"webhook_callback_url": webhookCallbackURL,
		"webhook_registered":   webhookRegistered,
		"note":                 webhookNote,
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
// @Success      200  {object}  admin.MessageResponse
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

	// Update fields — only overwrite string fields when the request provides a non-empty value
	// so partial updates (e.g. only changing default_branch) don't clobber the rest.
	if req.RepositoryOwner != "" {
		link.RepositoryOwner = req.RepositoryOwner
	}
	if req.RepositoryName != "" {
		link.RepositoryName = req.RepositoryName
	}
	if req.DefaultBranch != "" {
		link.DefaultBranch = req.DefaultBranch
	}
	if req.ModulePath != "" {
		link.ModulePath = req.ModulePath
	}
	if req.TagPattern != "" {
		link.TagPattern = req.TagPattern
	}
	// AutoPublish is boolean: always update because false is a valid intentional value.
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
// @Success      200  {object}  admin.MessageResponse
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
			if connector, token, connErr := h.connectorAndToken(c.Request.Context(), provider, userID); connErr == nil && token != nil {
				if rmErr := connector.RemoveWebhook(c.Request.Context(), token, link.RepositoryOwner, link.RepositoryName, *link.WebhookID); rmErr != nil {
					slog.Warn("failed to remove webhook", "webhook_id", *link.WebhookID, "owner", link.RepositoryOwner, "repo", link.RepositoryName, "error", rmErr)
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
// @Description
// @Description  Optionally pinned to one ref. `tag` narrows the sync to that tag alone; `commit_sha`
// @Description  additionally asserts the tag still points at that commit, and the request is refused
// @Description  with 409 if it has moved. Both are validated before the sync is dispatched, so a bad
// @Description  ref is reported to the caller rather than discovered inside the background job.
// @Param        id          path   string  true   "Module ID (UUID)"
// @Param        tag         query  string  false  "Sync only this tag (default: every tag matching the configured pattern)"
// @Param        commit_sha  query  string  false  "Assert the tag points at this commit; requires tag. Abbreviations of 7+ characters are accepted"
// @Success      202  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid module ID, or commit_sha given without tag"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized or no OAuth token for this SCM provider"
// @Failure      404  {object}  map[string]interface{}  "Module is not linked to a repository, or the named tag does not exist"
// @Failure      409  {object}  map[string]interface{}  "The named tag no longer points at the asserted commit"
// @Failure      500  {object}  map[string]interface{}  "Internal server error (connector build, token decryption, etc.)"
// @Failure      502  {object}  map[string]interface{}  "Could not reach the SCM provider to resolve the ref"
// @Router       /api/v1/admin/modules/{id}/scm/sync [post]
// TriggerManualSync manually triggers a repository sync
// POST /api/v1/admin/modules/:id/scm/sync
func (h *SCMLinkingHandler) TriggerManualSync(c *gin.Context) {
	moduleIDStr := c.Param("id")
	slog.Debug("TriggerManualSync called", "module_id", moduleIDStr)

	moduleID, err := uuid.Parse(moduleIDStr)
	if err != nil {
		slog.Debug("invalid module ID", "module_id", moduleIDStr)
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

	// App-mode providers use the shared, admin-managed credential — no per-user
	// connection is required to trigger a sync.
	ref, ok := parseSyncRef(c)
	if !ok {
		return
	}

	if provider.AuthMode == scm.AuthModeEntraApp || provider.AuthMode == scm.AuthModeGitHubApp {
		connector, token, connErr := h.connectorAndToken(c.Request.Context(), provider, uuid.Nil)
		if connErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": connErr.Error()})
			return
		}
		if !h.resolveSyncRef(c, link, connector, token, ref) {
			return
		}
		h.dispatchSync(c, moduleID, link, connector, token, ref)
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
	accessToken, _, err := h.tokenCipher.OpenWithContextOrLegacy(
		tokenRecord.AccessTokenEncrypted, scm.UserTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt access token"})
		return
	}

	// Decrypt client secret
	clientSecret, _, err := h.tokenCipher.OpenWithContextOrLegacy(
		provider.ClientSecretEncrypted, scm.ProviderClientSecretContext(provider.ID.String()))
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
		if rt, _, err := h.tokenCipher.OpenWithContextOrLegacy(
			*tokenRecord.RefreshTokenEncrypted, scm.UserRefreshTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID)); err == nil {
			token.RefreshToken = rt
			decryptedRefreshToken = rt
		}
	}

	// Proactively refresh if the token is expired or expires within 5 minutes.
	if decryptedRefreshToken != "" && (token.IsExpired() || (token.ExpiresAt != nil && time.Until(*token.ExpiresAt) < 5*time.Minute)) {
		slog.Debug("token expired or expiring soon, refreshing")
		if newToken, err := connector.RenewToken(c.Request.Context(), decryptedRefreshToken); err == nil {
			token.AccessToken = newToken.AccessToken
			token.RefreshToken = newToken.RefreshToken
			token.ExpiresAt = newToken.ExpiresAt
			// Persist the refreshed token so future requests don't need to refresh again.
			if encAccess, err := h.tokenCipher.SealWithContext(newToken.AccessToken, scm.UserTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID)); err == nil {
				tokenRecord.AccessTokenEncrypted = encAccess
				tokenRecord.ExpiresAt = newToken.ExpiresAt
				tokenRecord.UpdatedAt = time.Now()
				if newToken.RefreshToken != "" {
					if encRefresh, err := h.tokenCipher.SealWithContext(newToken.RefreshToken, scm.UserRefreshTokenContext(tokenRecord.UserID, tokenRecord.SCMProviderID)); err == nil {
						tokenRecord.RefreshTokenEncrypted = &encRefresh
					}
				}
				_ = h.scmRepo.SaveUserToken(c.Request.Context(), tokenRecord)
				slog.Debug("token refreshed successfully")
			}
		} else {
			slog.Warn("token refresh failed", "error", err)
		}
	}

	if !h.resolveSyncRef(c, link, connector, token, ref) {
		return
	}
	h.dispatchSync(c, moduleID, link, connector, token, ref)
}

// parseSyncRef reads the optional ref from the request (#879).
//
// Query parameters, not a body: this is a POST with no body today and every
// existing caller sends none, so a required body would break them and an
// optional one is two ways to say the same thing. Callers are CI workflows
// building a URL.
//
// Returns false when it has already answered the request.
func parseSyncRef(c *gin.Context) (services.SyncRef, bool) {
	ref := services.SyncRef{
		TagName:   strings.TrimSpace(c.Query("tag")),
		CommitSHA: strings.TrimSpace(c.Query("commit_sha")),
	}
	// A commit without a tag cannot be resolved: the sync walks tags, and a
	// bare SHA names no tag to import. Refusing is better than ignoring it,
	// which would let a caller believe it had pinned something.
	if ref.CommitSHA != "" && ref.TagName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "commit_sha requires tag: a sync imports tags, so a commit alone names nothing to publish",
		})
		return services.SyncRef{}, false
	}
	return ref, true
}

// resolveSyncRef checks the named ref BEFORE dispatching, and answers the
// request itself when it does not hold.
//
// SYNCHRONOUS ON PURPOSE. The sync runs detached and the handler answers 202,
// so a failure discovered inside it reaches nobody -- which would make "fail if
// the ref no longer resolves" a promise this API could not keep. Resolving
// first turns a moved or missing tag into a status code the caller sees.
//
// Returns false when it has already answered.
func (h *SCMLinkingHandler) resolveSyncRef(c *gin.Context, link *scm.ModuleSourceRepoRecord, connector scm.Connector, token *scm.OAuthToken, ref services.SyncRef) bool {
	if ref.TagName == "" {
		return true
	}
	tag, err := h.publisher.ResolveRef(c.Request.Context(), link, connector, token, ref)
	if err != nil {
		status, msg := statusForRefError(err)
		c.JSON(status, gin.H{"error": msg})
		return false
	}
	if tag != nil {
		slog.Debug("resolved sync ref", "tag", tag.TagName, "commit", tag.TargetCommit)
	}
	return true
}

// statusForRefError maps a ref-resolution failure to a status.
//
// A pure function so the mapping is testable without a live SCM connector --
// and it is the part a publisher actually depends on. The distinctions matter:
//
//   - 404: the tag does not exist. The caller named something wrong, or the
//     push has not landed yet.
//   - 409: the tag exists and points somewhere else. THE REQUEST WAS FINE and
//     the repository changed underneath it -- which is the force-moved-tag case
//     this whole feature exists to refuse. Reporting it as 400 would tell a
//     publisher it had sent nonsense.
//   - 502: the registry could not reach the SCM provider. Nothing about the
//     caller's request is wrong, and it is worth retrying; the other two are
//     not.
//
// The upstream message is passed through for the first two because it names the
// tag and both commits, which is what a human debugging a failed publish needs.
// The 502 message is generic: an SCM client error can carry an instance URL or
// a token fragment.
func statusForRefError(err error) (int, string) {
	switch {
	case errors.Is(err, services.ErrRefNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, services.ErrRefMoved):
		return http.StatusConflict, err.Error()
	default:
		return http.StatusBadGateway, "failed to resolve ref against the repository"
	}
}

// dispatchSync starts the sync in the background and answers 202.
func (h *SCMLinkingHandler) dispatchSync(c *gin.Context, moduleID uuid.UUID, link *scm.ModuleSourceRepoRecord, connector scm.Connector, token *scm.OAuthToken, ref services.SyncRef) {
	// A new context: c.Request.Context() is canceled when the response is sent.
	slog.Debug("starting async sync", "module_id", moduleID, "owner", link.RepositoryOwner, "repo", link.RepositoryName, "tag", ref.TagName)
	safego.Go(func() {
		if err := h.publisher.TriggerManualSyncRef(context.Background(), link, connector, token, ref); err != nil {
			slog.Warn("manual sync failed", "module_id", moduleID, "tag", ref.TagName, "error", err)
		} else {
			slog.Debug("manual sync completed successfully", "module_id", moduleID)
		}
	})

	body := gin.H{"message": "sync triggered"}
	if ref.TagName != "" {
		// Echo what was pinned, so a caller can confirm the server understood
		// the ref rather than having silently ignored an unknown parameter.
		body["tag"] = ref.TagName
		if ref.CommitSHA != "" {
			body["commit_sha"] = ref.CommitSHA
		}
	}
	c.JSON(http.StatusAccepted, body)
}

// @Summary      Get webhook event history
// @Description  Retrieve the recent webhook event log for a module's SCM repository link (last 50 events).
// @Tags         SCM Linking
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module ID (UUID)"
// @Success      200  {object}  admin.WebhookEventsResponse
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

// detectDefaultBranch attempts to auto-detect the default branch of a repository
// using the calling user's OAuth token. Returns "main" on any failure (non-fatal).
func (h *SCMLinkingHandler) detectDefaultBranch(ctx context.Context, c *gin.Context, provider *scm.SCMProvider, owner, repoName string) string {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		return "main"
	}
	connector, token, err := h.connectorAndToken(ctx, provider, userID)
	if err != nil || token == nil {
		return "main"
	}
	sourceRepo, err := connector.FetchRepository(ctx, token, owner, repoName)
	if err != nil || sourceRepo == nil || sourceRepo.DefaultBranch == "" {
		return "main"
	}
	return sourceRepo.DefaultBranch
}

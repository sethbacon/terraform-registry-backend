// scm_providers.go implements CRUD handlers for managing SCM provider configurations.
package admin

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
)

// SCMProviderHandlers handles SCM provider CRUD operations
type SCMProviderHandlers struct {
	cfg         *config.Config
	scmRepo     *repositories.SCMRepository
	orgRepo     *repositories.OrganizationRepository
	tokenCipher *crypto.TokenCipher
	minter      appcreds.SharedMinter
}

// NewSCMProviderHandlers creates a new SCM provider handlers instance
func NewSCMProviderHandlers(cfg *config.Config, scmRepo *repositories.SCMRepository, orgRepo *repositories.OrganizationRepository, tokenCipher *crypto.TokenCipher) *SCMProviderHandlers {
	return &SCMProviderHandlers{
		cfg:         cfg,
		scmRepo:     scmRepo,
		orgRepo:     orgRepo,
		tokenCipher: tokenCipher,
	}
}

// WithMinter wires in the shared app-credential minter used by providers in an
// app auth mode (entra_app/github_app). Returns the handler for chaining.
func (h *SCMProviderHandlers) WithMinter(minter appcreds.SharedMinter) *SCMProviderHandlers {
	h.minter = minter
	return h
}

// CreateSCMProviderRequest represents the request to create a new SCM provider configuration.
// OAuth providers require ClientID and ClientSecret; PAT-based providers (e.g. Bitbucket Data Center)
// use a personal access token supplied as ClientSecret with BaseURL required.
type CreateSCMProviderRequest struct {
	OrganizationID *uuid.UUID       `json:"organization_id,omitempty"`
	ProviderType   scm.ProviderType `json:"provider_type" binding:"required"`
	Name           string           `json:"name" binding:"required"`
	BaseURL        *string          `json:"base_url,omitempty"`
	TenantID       *string          `json:"tenant_id,omitempty"`
	ClientID       string           `json:"client_id"`
	ClientSecret   string           `json:"client_secret"`
	WebhookSecret  string           `json:"webhook_secret,omitempty"`
	// AuthMode selects the authentication model: "oauth_user" (default, legacy
	// per-user OAuth), "entra_app" (Microsoft Entra app registration for Azure
	// DevOps) or "github_app" (GitHub App). The app modes use a single shared,
	// admin-managed credential.
	AuthMode             string `json:"auth_mode,omitempty"`
	GitHubAppID          string `json:"github_app_id,omitempty"`
	GitHubInstallationID string `json:"github_installation_id,omitempty"`
	AppPrivateKey        string `json:"app_private_key,omitempty"`
}

// UpdateSCMProviderRequest represents the request to update an existing SCM provider configuration.
// All fields are optional; only provided (non-nil) fields will be updated.
type UpdateSCMProviderRequest struct {
	Name          *string `json:"name,omitempty"`
	BaseURL       *string `json:"base_url,omitempty"`
	TenantID      *string `json:"tenant_id,omitempty"`
	ClientID      *string `json:"client_id,omitempty"`
	ClientSecret  *string `json:"client_secret,omitempty"`
	WebhookSecret *string `json:"webhook_secret,omitempty"`
	IsActive      *bool   `json:"is_active,omitempty"`
	// App-credential fields. Setting AppPrivateKey to "" clears the stored key.
	AuthMode             *string `json:"auth_mode,omitempty"`
	GitHubAppID          *string `json:"github_app_id,omitempty"`
	GitHubInstallationID *string `json:"github_installation_id,omitempty"`
	AppPrivateKey        *string `json:"app_private_key,omitempty"`
}

// @Summary      Create SCM provider
// @Description  Create a new SCM provider configuration (GitHub, GitLab, Bitbucket, etc.). Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateSCMProviderRequest  true  "SCM provider configuration"
// @Success      201  {object}  scm.SCMProviderRecord
// @Failure      400  {object}  map[string]interface{}  "Invalid request or provider type"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "SCM provider with this name and type already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers [post]
// CreateProvider creates a new SCM provider configuration
// POST /api/v1/scm-providers
func (h *SCMProviderHandlers) CreateProvider(c *gin.Context) {
	var req CreateSCMProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate provider type
	if !req.ProviderType.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider type"})
		return
	}

	// Resolve the auth mode (defaults to legacy per-user OAuth).
	authMode := req.AuthMode
	if authMode == "" {
		authMode = scm.AuthModeOAuthUser
	}

	// app_private_key, when supplied for github_app, is encrypted separately.
	var encryptedAppPrivateKey *string

	switch authMode {
	case scm.AuthModeOAuthUser:
		// PAT-based providers don't require OAuth credentials
		if req.ProviderType.IsPATBased() {
			if req.BaseURL == nil || *req.BaseURL == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "base_url is required for Bitbucket Data Center"})
				return
			}
			if req.ClientID == "" {
				req.ClientID = "pat-auth"
			}
			if req.ClientSecret == "" {
				req.ClientSecret = "not-applicable"
			}
		} else {
			if req.ClientID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required for OAuth providers"})
				return
			}
			if req.ClientSecret == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "client_secret is required for OAuth providers"})
				return
			}
		}
	case scm.AuthModeEntraApp:
		// Microsoft Entra app registration (Azure DevOps): client-credentials grant.
		if req.ProviderType != scm.ProviderAzureDevOps {
			c.JSON(http.StatusBadRequest, gin.H{"error": "entra_app auth is only supported for azuredevops providers"})
			return
		}
		if req.TenantID == nil || *req.TenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required for entra_app auth"})
			return
		}
		if req.ClientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required for entra_app auth"})
			return
		}
		if req.ClientSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "client_secret is required for entra_app auth"})
			return
		}
	case scm.AuthModeGitHubApp:
		// GitHub App: app JWT exchanged for an installation token.
		if req.ProviderType != scm.ProviderGitHub {
			c.JSON(http.StatusBadRequest, gin.H{"error": "github_app auth is only supported for github providers"})
			return
		}
		if req.GitHubAppID == "" || req.GitHubInstallationID == "" || req.AppPrivateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "github_app_id, github_installation_id and app_private_key are required for github_app auth"})
			return
		}
		if !appcreds.ValidRSAPrivateKey(req.AppPrivateKey) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "app_private_key is not a valid RSA private key (PKCS#1 or PKCS#8 PEM)"})
			return
		}
		// The client_id/client_secret columns are NOT NULL but unused for GitHub
		// App auth; store stable placeholders.
		if req.ClientID == "" {
			req.ClientID = "github-app"
		}
		req.ClientSecret = "not-applicable"
		enc, encErr := h.tokenCipher.Seal(req.AppPrivateKey)
		if encErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt app private key"})
			return
		}
		encryptedAppPrivateKey = &enc
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth_mode"})
		return
	}

	// Encrypt client secret
	clientSecretEncrypted, err := h.tokenCipher.Seal(req.ClientSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt secret"})
		return
	}

	// Resolve organization ID: use the provided value, or fall back to the default organization.
	orgID := uuid.Nil
	if req.OrganizationID != nil && *req.OrganizationID != uuid.Nil {
		orgID = *req.OrganizationID
	}
	if orgID == uuid.Nil {
		defaultOrg, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil || defaultOrg == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no organization found — create an organization before adding an SCM provider"})
			return
		}
		parsed, parseErr := uuid.Parse(defaultOrg.ID)
		if parseErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve organization"})
			return
		}
		orgID = parsed
	}

	// Check for a duplicate before inserting to return 409 instead of letting
	// the unique constraint produce a 500.
	existing, err := h.scmRepo.GetProviderByOrgAndName(c.Request.Context(), orgID, req.ProviderType, req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing provider"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "An SCM provider with this name and type already exists in this organization"})
		return
	}

	provider := &scm.SCMProviderRecord{
		ID:                     uuid.New(),
		OrganizationID:         orgID,
		ProviderType:           req.ProviderType,
		Name:                   req.Name,
		BaseURL:                req.BaseURL,
		TenantID:               req.TenantID,
		ClientID:               req.ClientID,
		ClientSecretEncrypted:  clientSecretEncrypted,
		WebhookSecret:          req.WebhookSecret,
		AuthMode:               authMode,
		EncryptedAppPrivateKey: encryptedAppPrivateKey,
		IsActive:               true,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
	if req.GitHubAppID != "" {
		provider.GitHubAppID = &req.GitHubAppID
	}
	if req.GitHubInstallationID != "" {
		provider.GitHubInstallationID = &req.GitHubInstallationID
	}

	if err := h.scmRepo.CreateProvider(c.Request.Context(), provider); err != nil {
		slog.Error("failed to create SCM provider", "error", err, "org_id", provider.OrganizationID, "provider_type", provider.ProviderType, "name", provider.Name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create provider"})
		return
	}

	c.JSON(http.StatusCreated, provider)
}

// @Summary      List SCM providers
// @Description  List all SCM provider configurations, optionally filtered by organization. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Produce      json
// @Param        organization_id  query  string  false  "Filter by organization ID (UUID)"
// @Success      200  {array}   scm.SCMProviderRecord
// @Failure      400  {object}  map[string]interface{}  "Invalid organization ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers [get]
// ListProviders lists all SCM provider configurations
// GET /api/v1/scm-providers
func (h *SCMProviderHandlers) ListProviders(c *gin.Context) {
	orgIDStr := c.Query("organization_id")

	var providers []*scm.SCMProviderRecord
	var err error

	if orgIDStr != "" {
		orgID, parseErr := uuid.Parse(orgIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization_id"})
			return
		}
		providers, err = h.scmRepo.ListProviders(c.Request.Context(), orgID)
	} else {
		// Pass uuid.Nil to list all providers
		providers, err = h.scmRepo.ListProviders(c.Request.Context(), uuid.Nil)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list providers"})
		return
	}

	c.JSON(http.StatusOK, providers)
}

// @Summary      Get SCM provider
// @Description  Retrieve a specific SCM provider configuration by ID. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  scm.SCMProviderRecord
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id} [get]
// GetProvider retrieves a single SCM provider by ID
// GET /api/v1/scm-providers/:id
func (h *SCMProviderHandlers) GetProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// @Summary      Update SCM provider
// @Description  Update an existing SCM provider configuration. All fields are optional. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "SCM provider ID (UUID)"
// @Param        body  body  UpdateSCMProviderRequest  true  "Fields to update"
// @Success      200  {object}  scm.SCMProviderRecord
// @Failure      400  {object}  map[string]interface{}  "Invalid request or ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id} [put]
// UpdateProvider updates an SCM provider configuration
// PUT /api/v1/scm-providers/:id
func (h *SCMProviderHandlers) UpdateProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	var req UpdateSCMProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	// Update fields
	if req.Name != nil {
		provider.Name = *req.Name
	}
	if req.BaseURL != nil {
		provider.BaseURL = req.BaseURL
	}
	if req.TenantID != nil {
		provider.TenantID = req.TenantID
	}
	if req.ClientID != nil {
		provider.ClientID = *req.ClientID
	}
	if req.ClientSecret != nil {
		encryptedSecret, err := h.tokenCipher.Seal(*req.ClientSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt secret"})
			return
		}
		provider.ClientSecretEncrypted = encryptedSecret
	}
	if req.WebhookSecret != nil {
		provider.WebhookSecret = *req.WebhookSecret
	}
	if req.IsActive != nil {
		provider.IsActive = *req.IsActive
	}
	if req.AuthMode != nil {
		switch *req.AuthMode {
		case scm.AuthModeOAuthUser, scm.AuthModeEntraApp, scm.AuthModeGitHubApp:
			provider.AuthMode = *req.AuthMode
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth_mode"})
			return
		}
	}
	if req.GitHubAppID != nil {
		if *req.GitHubAppID == "" {
			provider.GitHubAppID = nil
		} else {
			provider.GitHubAppID = req.GitHubAppID
		}
	}
	if req.GitHubInstallationID != nil {
		if *req.GitHubInstallationID == "" {
			provider.GitHubInstallationID = nil
		} else {
			provider.GitHubInstallationID = req.GitHubInstallationID
		}
	}
	if req.AppPrivateKey != nil {
		if *req.AppPrivateKey == "" {
			provider.EncryptedAppPrivateKey = nil
		} else {
			if !appcreds.ValidRSAPrivateKey(*req.AppPrivateKey) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "app_private_key is not a valid RSA private key (PKCS#1 or PKCS#8 PEM)"})
				return
			}
			enc, encErr := h.tokenCipher.Seal(*req.AppPrivateKey)
			if encErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt app private key"})
				return
			}
			provider.EncryptedAppPrivateKey = &enc
		}
	}

	// Validate the resulting app-mode shape so we return 400 rather than letting a
	// DB CHECK constraint surface as a 500.
	switch provider.AuthMode {
	case scm.AuthModeGitHubApp:
		if provider.GitHubAppID == nil || *provider.GitHubAppID == "" ||
			provider.GitHubInstallationID == nil || *provider.GitHubInstallationID == "" ||
			provider.EncryptedAppPrivateKey == nil || *provider.EncryptedAppPrivateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "github_app auth requires github_app_id, github_installation_id and app_private_key"})
			return
		}
	case scm.AuthModeEntraApp:
		if provider.TenantID == nil || *provider.TenantID == "" || provider.ClientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "entra_app auth requires tenant_id and client_id"})
			return
		}
	}

	provider.UpdatedAt = time.Now()

	if err := h.scmRepo.UpdateProvider(c.Request.Context(), provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update provider"})
		return
	}

	// Credentials may have changed; drop any cached shared token so the next
	// request re-mints with the new configuration.
	_ = h.scmRepo.DeleteProviderToken(c.Request.Context(), providerID)

	c.JSON(http.StatusOK, provider)
}

// @Summary      Delete SCM provider
// @Description  Delete an SCM provider configuration. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/scm-providers/{id} [delete]
// DeleteProvider deletes an SCM provider configuration
// DELETE /api/v1/scm-providers/:id
func (h *SCMProviderHandlers) DeleteProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	if err := h.scmRepo.DeleteProvider(c.Request.Context(), providerID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete provider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "provider deleted"})
}

// @Summary      Verify SCM provider app credentials
// @Description  Mint a shared app token for a provider in an app auth mode (entra_app or github_app) to confirm the configured credentials are valid. Returns the token expiry on success. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "{ ok, expires_at }"
// @Failure      400  {object}  map[string]interface{}  "Invalid provider ID or provider not in an app auth mode"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      502  {object}  map[string]interface{}  "Failed to mint a token from the identity provider"
// @Router       /api/v1/scm-providers/{id}/verify [post]
// VerifyProvider mints a shared app token to confirm the provider's app
// credentials are valid.
// POST /api/v1/scm-providers/:id/verify
func (h *SCMProviderHandlers) VerifyProvider(c *gin.Context) {
	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider ID"})
		return
	}

	provider, err := h.scmRepo.GetProvider(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get provider"})
		return
	}
	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	if provider.AuthMode != scm.AuthModeEntraApp && provider.AuthMode != scm.AuthModeGitHubApp {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verification is only available for providers in an app auth mode"})
		return
	}
	if h.minter == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "shared app credentials not available"})
		return
	}

	// Force a fresh mint so verification reflects the current stored credentials.
	_ = h.scmRepo.DeleteProviderToken(c.Request.Context(), providerID)
	token, err := h.minter.MintProviderToken(c.Request.Context(), provider)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "expires_at": token.ExpiresAt})
}

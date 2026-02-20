// scm_providers.go implements CRUD handlers for managing SCM provider configurations.
package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// SCMProviderHandlers handles SCM provider CRUD operations
type SCMProviderHandlers struct {
	cfg         *config.Config
	scmRepo     *repositories.SCMRepository
	tokenCipher *crypto.TokenCipher
}

// NewSCMProviderHandlers creates a new SCM provider handlers instance
func NewSCMProviderHandlers(cfg *config.Config, scmRepo *repositories.SCMRepository, tokenCipher *crypto.TokenCipher) *SCMProviderHandlers {
	return &SCMProviderHandlers{
		cfg:         cfg,
		scmRepo:     scmRepo,
		tokenCipher: tokenCipher,
	}
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

	// Encrypt client secret
	clientSecretEncrypted, err := h.tokenCipher.Seal(req.ClientSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt secret"})
		return
	}

	// Get organization ID - use provided org or default to nil (will use default org)
	orgID := uuid.Nil
	if req.OrganizationID != nil && req.OrganizationID.String() != "00000000-0000-0000-0000-000000000000" {
		orgID = *req.OrganizationID
	}

	provider := &scm.SCMProviderRecord{
		ID:                    uuid.New(),
		OrganizationID:        orgID,
		ProviderType:          req.ProviderType,
		Name:                  req.Name,
		BaseURL:               req.BaseURL,
		TenantID:              req.TenantID,
		ClientID:              req.ClientID,
		ClientSecretEncrypted: clientSecretEncrypted,
		WebhookSecret:         req.WebhookSecret,
		IsActive:              true,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := h.scmRepo.CreateProvider(c.Request.Context(), provider); err != nil {
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

	provider.UpdatedAt = time.Now()

	if err := h.scmRepo.UpdateProvider(c.Request.Context(), provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update provider"})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// @Summary      Delete SCM provider
// @Description  Delete an SCM provider configuration. Requires admin scope.
// @Tags         SCM Providers
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "SCM provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: provider deleted"
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

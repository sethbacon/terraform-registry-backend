// providers.go implements admin handlers for listing, deprecating, and deleting provider versions.
package admin

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ProviderAdminHandlers handles administrative provider operations
type ProviderAdminHandlers struct {
	providerRepo   *repositories.ProviderRepository
	orgRepo        *repositories.OrganizationRepository
	storageBackend storage.Storage
	cfg            *config.Config
}

// NewProviderAdminHandlers creates a new provider admin handlers instance
func NewProviderAdminHandlers(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) *ProviderAdminHandlers {
	return &ProviderAdminHandlers{
		providerRepo:   repositories.NewProviderRepository(db),
		orgRepo:        repositories.NewOrganizationRepository(db),
		storageBackend: storageBackend,
		cfg:            cfg,
	}
}

// @Summary      Get provider
// @Description  Retrieve a provider with all its versions and platforms. No authentication required; authentication is optional and provides user context.
// @Tags         Providers
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Success      200  {object}  admin.ProviderDetailResponse
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type} [get]
// GetProvider retrieves a specific provider by namespace and type
// GET /api/v1/providers/:namespace/:type
func (h *ProviderAdminHandlers) GetProvider(c *gin.Context) {
	namespace := c.Param("namespace")
	providerType := c.Param("type")

	// Get organization context (default org for single-tenant mode)
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Get provider
	provider, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Get versions for the provider
	versions, err := h.providerRepo.ListVersions(c.Request.Context(), provider.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list provider versions"})
		return
	}

	// Format versions
	versionsList := make([]gin.H, 0, len(versions))
	for _, v := range versions {
		platforms, _ := h.providerRepo.ListPlatforms(c.Request.Context(), v.ID)
		platformsList := make([]gin.H, 0, len(platforms))
		for _, p := range platforms {
			platformsList = append(platformsList, gin.H{
				"os":             p.OS,
				"arch":           p.Arch,
				"filename":       p.Filename,
				"shasum":         p.Shasum,
				"download_count": p.DownloadCount,
			})
		}

		versionData := gin.H{
			"id":         v.ID,
			"version":    v.Version,
			"protocols":  v.Protocols,
			"platforms":  platformsList,
			"deprecated": v.Deprecated,
			"created_at": v.CreatedAt,
		}
		if v.DeprecatedAt != nil {
			versionData["deprecated_at"] = v.DeprecatedAt
		}
		if v.DeprecationMessage != nil {
			versionData["deprecation_message"] = v.DeprecationMessage
		}
		versionsList = append(versionsList, versionData)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          provider.ID,
		"namespace":   provider.Namespace,
		"type":        provider.Type,
		"description": provider.Description,
		"source":      provider.Source,
		"versions":    versionsList,
		"created_at":  provider.CreatedAt,
		"updated_at":  provider.UpdatedAt,
	})
}

// @Summary      Delete provider
// @Description  Delete a provider and all its versions and platform binaries from storage. Requires providers:delete scope.
// @Tags         Providers
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type} [delete]
// DeleteProvider deletes a provider and all its versions/platforms
// DELETE /api/v1/providers/:namespace/:type
func (h *ProviderAdminHandlers) DeleteProvider(c *gin.Context) {
	namespace := c.Param("namespace")
	providerType := c.Param("type")

	// Get organization context
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Get provider
	provider, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Get all versions to delete their files from storage
	versions, err := h.providerRepo.ListVersions(c.Request.Context(), provider.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list provider versions"})
		return
	}

	// Delete files from storage for each version
	for _, v := range versions {
		platforms, _ := h.providerRepo.ListPlatforms(c.Request.Context(), v.ID)
		for _, p := range platforms {
			if p.StoragePath != "" {
				// Try to delete from storage (ignore errors - file might not exist)
				_ = h.storageBackend.Delete(c.Request.Context(), p.StoragePath)
			}
		}
	}

	// Delete provider from database (cascades to versions and platforms)
	if err := h.providerRepo.DeleteProvider(c.Request.Context(), provider.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete provider: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Provider deleted successfully",
		"namespace": namespace,
		"type":      providerType,
	})
}

// @Summary      Delete provider version
// @Description  Delete a specific provider version and all its platform binaries from storage. Requires providers:delete scope.
// @Tags         Providers
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type}/versions/{version} [delete]
// DeleteVersion deletes a specific version of a provider
// DELETE /api/v1/providers/:namespace/:type/versions/:version
func (h *ProviderAdminHandlers) DeleteVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	providerType := c.Param("type")
	version := c.Param("version")

	// Get organization context
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Get provider
	provider, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}

	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	// Delete files from storage
	platforms, _ := h.providerRepo.ListPlatforms(c.Request.Context(), versionRecord.ID)
	for _, p := range platforms {
		if p.StoragePath != "" {
			_ = h.storageBackend.Delete(c.Request.Context(), p.StoragePath)
		}
	}

	// Delete version from database (cascades to platforms)
	if err := h.providerRepo.DeleteVersion(c.Request.Context(), versionRecord.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deleted successfully",
		"namespace": namespace,
		"type":      providerType,
		"version":   version,
	})
}

// DeprecateVersionRequest represents a request to deprecate a version
type DeprecateVersionRequest struct {
	Message string `json:"message,omitempty"`
}

// @Summary      Deprecate provider version
// @Description  Mark a specific provider version as deprecated with an optional message. Requires providers:publish scope.
// @Tags         Providers
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        namespace  path  string                 true   "Provider namespace"
// @Param        type       path  string                 true   "Provider type (e.g. aws, azurerm)"
// @Param        version    path  string                 true   "Semantic version (e.g. 1.2.3)"
// @Param        body       body  DeprecateVersionRequest  false  "Optional deprecation message"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type}/versions/{version}/deprecate [post]
// DeprecateVersion marks a specific version as deprecated
// POST /api/v1/providers/:namespace/:type/versions/:version/deprecate
func (h *ProviderAdminHandlers) DeprecateVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	providerType := c.Param("type")
	version := c.Param("version")

	var req DeprecateVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty body is OK - message is optional
		req = DeprecateVersionRequest{}
	}

	// Get organization context
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Get provider
	provider, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}

	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	// Deprecate the version
	var message *string
	if req.Message != "" {
		message = &req.Message
	}

	if err := h.providerRepo.DeprecateVersion(c.Request.Context(), versionRecord.ID, message); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deprecate version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deprecated successfully",
		"namespace": namespace,
		"type":      providerType,
		"version":   version,
	})
}

// @Summary      Undeprecate provider version
// @Description  Remove the deprecated status from a provider version. Requires providers:publish scope.
// @Tags         Providers
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type}/versions/{version}/deprecate [delete]
// UndeprecateVersion removes the deprecated status from a version
// DELETE /api/v1/providers/:namespace/:type/versions/:version/deprecate
func (h *ProviderAdminHandlers) UndeprecateVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	providerType := c.Param("type")
	version := c.Param("version")

	// Get organization context
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Get provider
	provider, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}

	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	// Undeprecate the version
	if err := h.providerRepo.UndeprecateVersion(c.Request.Context(), versionRecord.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to undeprecate version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deprecation removed successfully",
		"namespace": namespace,
		"type":      providerType,
		"version":   version,
	})
}

// CreateProviderRecordRequest is the payload for creating a new provider record
type CreateProviderRecordRequest struct {
	Namespace   string  `json:"namespace" binding:"required"`
	Type        string  `json:"type" binding:"required"`
	Description *string `json:"description,omitempty"`
	Source      *string `json:"source,omitempty"`
}

// @Summary      Create provider record
// @Description  Create a new provider record in the registry. Requires providers:write scope.
// @Tags         Providers
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateProviderRecordRequest  true  "Provider namespace, type, optional description and source"
// @Success      201  {object}  models.Provider
// @Failure      400  {object}  map[string]interface{}  "Invalid request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Provider already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/providers [post]
// CreateProviderRecord creates a new provider record
// POST /api/v1/admin/providers
func (h *ProviderAdminHandlers) CreateProviderRecord(c *gin.Context) {
	var req CreateProviderRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Get organization context (default org for single-tenant mode)
	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization context"})
		return
	}

	var orgID string
	if org != nil {
		orgID = org.ID
	}

	// Check for duplicate
	existing, err := h.providerRepo.GetProvider(c.Request.Context(), orgID, req.Namespace, req.Type)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing provider"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Provider already exists"})
		return
	}

	// Capture creating user
	var createdBy *string
	if rawUID, exists := c.Get("user_id"); exists {
		if uid, ok := rawUID.(uuid.UUID); ok {
			s := uid.String()
			createdBy = &s
		}
	}

	provider := &models.Provider{
		OrganizationID: orgID,
		Namespace:      req.Namespace,
		Type:           req.Type,
		Description:    req.Description,
		Source:         req.Source,
		CreatedBy:      createdBy,
	}

	if err := h.providerRepo.CreateProvider(c.Request.Context(), provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create provider: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, provider)
}

// @Summary      Get provider record by ID
// @Description  Retrieve a provider record by its UUID. Requires providers:read scope.
// @Tags         Providers
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Provider record UUID"
// @Success      200  {object}  models.Provider
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/providers/{id} [get]
// GetProviderByID retrieves a provider record by UUID
// GET /api/v1/admin/providers/:id
func (h *ProviderAdminHandlers) GetProviderByID(c *gin.Context) {
	id := c.Param("id")

	provider, err := h.providerRepo.GetProviderByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider"})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, provider)
}

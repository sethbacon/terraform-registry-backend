// modules.go implements admin handlers for listing, deprecating, and deleting module versions.
package admin

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/analyzer"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ModuleAdminHandlers handles administrative module operations
type ModuleAdminHandlers struct {
	moduleRepo     *repositories.ModuleRepository
	orgRepo        *repositories.OrganizationRepository
	storageBackend storage.Storage
	cfg            *config.Config
	moduleDocsRepo *repositories.ModuleDocsRepository
	scanRepo       *repositories.ModuleScanRepository
}

// NewModuleAdminHandlers creates a new module admin handlers instance
func NewModuleAdminHandlers(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) *ModuleAdminHandlers {
	return &ModuleAdminHandlers{
		moduleRepo:     repositories.NewModuleRepository(db),
		orgRepo:        repositories.NewOrganizationRepository(db),
		storageBackend: storageBackend,
		cfg:            cfg,
	}
}

// WithModuleDocs sets the module docs repository for re-analysis support.
func (h *ModuleAdminHandlers) WithModuleDocs(repo *repositories.ModuleDocsRepository) *ModuleAdminHandlers {
	h.moduleDocsRepo = repo
	return h
}

// WithScanQueue sets the scan repository for re-scan support.
func (h *ModuleAdminHandlers) WithScanQueue(repo *repositories.ModuleScanRepository) *ModuleAdminHandlers {
	h.scanRepo = repo
	return h
}

// @Summary      Create module record
// @Description  Create a module record without a version file. Used by the SCM publishing flow. Requires modules:publish scope.
// @Tags         Modules
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  object  true  "namespace, name, system, description (optional)"
// @Success      200  {object}  models.Module  "Module already exists (returned as-is)"
// @Success      201  {object}  models.Module  "Module created"
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/create [post]
// CreateModuleRecord creates a module record without a version file.
// This is used by the SCM publishing flow to register a module before linking it to a repository.
// POST /api/v1/admin/modules/create
func (h *ModuleAdminHandlers) CreateModuleRecord(c *gin.Context) {
	var req struct {
		Namespace   string `json:"namespace" binding:"required"`
		Name        string `json:"name" binding:"required"`
		System      string `json:"system" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil || org == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization context"})
		return
	}

	// Return existing module if it already exists
	existing, err := h.moduleRepo.GetModule(c.Request.Context(), org.ID, req.Namespace, req.Name, req.System)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query module"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusOK, existing)
		return
	}

	module := &models.Module{
		OrganizationID: org.ID,
		Namespace:      req.Namespace,
		Name:           req.Name,
		System:         req.System,
	}
	if req.Description != "" {
		module.Description = &req.Description
	}
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			module.CreatedBy = &uid
		}
	}

	if err := h.moduleRepo.CreateModule(c.Request.Context(), module); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create module"})
		return
	}

	c.JSON(http.StatusCreated, module)
}

// @Summary      Get module
// @Description  Retrieve a module with all its versions, download counts, and metadata. No authentication required; authentication is optional and provides user context.
// @Tags         Modules
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Success      200  {object}  admin.ModuleDetailResponse
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system} [get]
// GetModule retrieves a specific module by namespace, name, and system
// GET /api/v1/modules/:namespace/:name/:system
func (h *ModuleAdminHandlers) GetModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")

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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get versions for the module
	versions, err := h.moduleRepo.ListVersions(c.Request.Context(), module.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list module versions"})
		return
	}

	// Format versions and calculate total downloads
	versionsList := make([]gin.H, 0, len(versions))
	var totalDownloads int64
	for _, v := range versions {
		totalDownloads += v.DownloadCount
		versionData := gin.H{
			"id":                v.ID,
			"version":           v.Version,
			"size_bytes":        v.SizeBytes,
			"checksum":          v.Checksum,
			"download_count":    v.DownloadCount,
			"deprecated":        v.Deprecated,
			"published_by":      v.PublishedBy,
			"published_by_name": v.PublishedByName,
			"created_at":        v.CreatedAt,
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
		"id":                  module.ID,
		"organization_id":     module.OrganizationID,
		"namespace":           module.Namespace,
		"name":                module.Name,
		"system":              module.System,
		"description":         module.Description,
		"source":              module.Source,
		"created_by":          module.CreatedBy,
		"created_by_name":     module.CreatedByName,
		"download_count":      totalDownloads,
		"deprecated":          module.Deprecated,
		"deprecated_at":       module.DeprecatedAt,
		"deprecation_message": module.DeprecationMessage,
		"successor_module_id": module.SuccessorModuleID,
		"versions":            versionsList,
		"created_at":          module.CreatedAt,
		"updated_at":          module.UpdatedAt,
	})
}

// @Summary      Delete module
// @Description  Delete a module and all its versions, including files in storage. Requires modules:delete scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system} [delete]
// DeleteModule deletes a module and all its versions
// DELETE /api/v1/modules/:namespace/:name/:system
func (h *ModuleAdminHandlers) DeleteModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")

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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get all versions to delete their files from storage
	versions, err := h.moduleRepo.ListVersions(c.Request.Context(), module.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list module versions"})
		return
	}

	// Delete files from storage for each version
	for _, v := range versions {
		if v.StoragePath != "" {
			// Try to delete from storage (ignore errors - file might not exist)
			_ = h.storageBackend.Delete(c.Request.Context(), v.StoragePath)
		}
	}

	// Delete module from database (cascades to versions)
	if err := h.moduleRepo.DeleteModule(c.Request.Context(), module.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete module: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Module deleted successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
	})
}

// @Summary      Delete module version
// @Description  Delete a specific version of a module, including its file in storage. Requires modules:delete scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/versions/{version} [delete]
// DeleteVersion deletes a specific version of a module
// DELETE /api/v1/modules/:namespace/:name/:system/versions/:version
func (h *ModuleAdminHandlers) DeleteVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}

	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	// Delete file from storage
	if versionRecord.StoragePath != "" {
		_ = h.storageBackend.Delete(c.Request.Context(), versionRecord.StoragePath)
	}

	// Delete version from database
	if err := h.moduleRepo.DeleteVersion(c.Request.Context(), versionRecord.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deleted successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
		"version":   version,
	})
}

// DeprecateModuleVersionRequest represents a request to deprecate a module version.
// Message is optional; if omitted the version is marked deprecated without an explanatory note.
type DeprecateModuleVersionRequest struct {
	Message           string  `json:"message,omitempty"`
	ReplacementSource *string `json:"replacement_source,omitempty"` // Replacement module source address (e.g. "registry.example.com/acme/newmod/aws")
}

// @Summary      Deprecate module version
// @Description  Mark a specific module version as deprecated with an optional message and replacement source. Requires modules:publish scope.
// @Tags         Modules
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        namespace  path  string                       true   "Module namespace"
// @Param        name       path  string                       true   "Module name"
// @Param        system     path  string                       true   "Target system (e.g. aws, azurerm)"
// @Param        version    path  string                       true   "Semantic version (e.g. 1.2.3)"
// @Param        body       body  DeprecateModuleVersionRequest  false  "Optional deprecation message and replacement source"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/versions/{version}/deprecate [post]
// DeprecateVersion marks a specific version as deprecated
// POST /api/v1/modules/:namespace/:name/:system/versions/:version/deprecate
func (h *ModuleAdminHandlers) DeprecateVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
	version := c.Param("version")

	var req DeprecateModuleVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty body is OK - message is optional
		req = DeprecateModuleVersionRequest{}
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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
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

	if err := h.moduleRepo.DeprecateVersion(c.Request.Context(), versionRecord.ID, message, req.ReplacementSource); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deprecate version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deprecated successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
		"version":   version,
	})
}

// @Summary      Undeprecate module version
// @Description  Remove the deprecated status from a module version. Requires modules:publish scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/versions/{version}/deprecate [delete]
// UndeprecateVersion removes the deprecated status from a version
// DELETE /api/v1/modules/:namespace/:name/:system/versions/:version/deprecate
func (h *ModuleAdminHandlers) UndeprecateVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}

	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	// Undeprecate the version
	if err := h.moduleRepo.UndeprecateVersion(c.Request.Context(), versionRecord.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to undeprecate version: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Version deprecation removed successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
		"version":   version,
	})
}

// UpdateModuleRecord handler
// @Summary      Update module record
// @Description  Update a module record's description or source URL. Requires modules:write scope.
// @Tags         Modules
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Module UUID"
// @Param        body  body  object  true  "Fields to update"
// @Success      200  {object}  models.Module
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id} [put]
// UpdateModuleRecord updates a module record
// PUT /api/v1/admin/modules/:id
func (h *ModuleAdminHandlers) UpdateModuleRecord(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Description *string `json:"description"`
		Source      *string `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	module, err := h.moduleRepo.GetModuleByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get module"})
		return
	}
	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module not found"})
		return
	}

	if req.Description != nil {
		module.Description = req.Description
	}
	if req.Source != nil {
		module.Source = req.Source
	}

	if err := h.moduleRepo.UpdateModule(c.Request.Context(), module); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update module"})
		return
	}

	c.JSON(http.StatusOK, module)
}

// @Summary      Get module record by ID
// @Description  Retrieve a module record by its UUID. Requires modules:read scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Module record UUID"
// @Success      200  {object}  models.Module
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/modules/{id} [get]
// GetModuleByIDRecord retrieves a module record by UUID
// GET /api/v1/admin/modules/:id
func (h *ModuleAdminHandlers) GetModuleByIDRecord(c *gin.Context) {
	id := c.Param("id")

	module, err := h.moduleRepo.GetModuleByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get module"})
		return
	}
	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "module not found"})
		return
	}
	c.JSON(http.StatusOK, module)
}

// DeprecateModuleRequest represents a request to deprecate an entire module.
// Message is optional; SuccessorModuleID optionally points to a replacement module.
type DeprecateModuleRequest struct {
	Message           string  `json:"message,omitempty"`
	SuccessorModuleID *string `json:"successor_module_id,omitempty"`
}

// @Summary      Deprecate module
// @Description  Mark an entire module as deprecated with an optional message and successor module reference. Requires modules:write scope.
// @Tags         Modules
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        namespace  path  string                  true   "Module namespace"
// @Param        name       path  string                  true   "Module name"
// @Param        system     path  string                  true   "Target system (e.g. aws, azurerm)"
// @Param        body       body  DeprecateModuleRequest  false  "Optional deprecation message and successor module ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/deprecate [post]
// DeprecateModule marks an entire module as deprecated
// POST /api/v1/modules/:namespace/:name/:system/deprecate
func (h *ModuleAdminHandlers) DeprecateModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")

	var req DeprecateModuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty body is OK - message is optional
		req = DeprecateModuleRequest{}
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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Deprecate the module
	var message *string
	if req.Message != "" {
		message = &req.Message
	}

	if err := h.moduleRepo.DeprecateModule(c.Request.Context(), module.ID, message, req.SuccessorModuleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deprecate module: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Module deprecated successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
	})
}

// @Summary      Undeprecate module
// @Description  Remove the deprecated status from a module. Requires modules:write scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/deprecate [delete]
// UndeprecateModule removes the deprecated status from a module
// DELETE /api/v1/modules/:namespace/:name/:system/deprecate
func (h *ModuleAdminHandlers) UndeprecateModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")

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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}

	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Undeprecate the module
	if err := h.moduleRepo.UndeprecateModule(c.Request.Context(), module.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to undeprecate module: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Module deprecation removed successfully",
		"namespace": namespace,
		"name":      name,
		"system":    system,
	})
}

// @Summary      Re-analyze module version
// @Description  Re-download the module archive from storage and re-run the HCL analyzer to refresh terraform-docs metadata. Optionally re-queues a security scan. Requires modules:publish scope.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      200  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}  "Module or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/versions/{version}/reanalyze [post]
// ReanalyzeVersion re-runs the HCL analyzer on an existing module version's archive.
func (h *ModuleAdminHandlers) ReanalyzeVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
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

	// Get module
	module, err := h.moduleRepo.GetModule(c.Request.Context(), orgID, namespace, name, system)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get module"})
		return
	}
	if module == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Module not found"})
		return
	}

	// Get the specific version
	versionRecord, err := h.moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get version"})
		return
	}
	if versionRecord == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	if versionRecord.StoragePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Version has no stored archive"})
		return
	}

	result := gin.H{
		"namespace": namespace,
		"name":      name,
		"system":    system,
		"version":   version,
	}

	// Re-run HCL analyzer if docs repo is configured
	if h.moduleDocsRepo != nil {
		reader, err := h.storageBackend.Download(c.Request.Context(), versionRecord.StoragePath)
		if err != nil {
			slog.Error("reanalyze: failed to download archive from storage",
				"version_id", versionRecord.ID, "path", versionRecord.StoragePath, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download archive from storage"})
			return
		}
		defer reader.Close()

		var buf bytes.Buffer
		if _, err := buf.ReadFrom(reader); err != nil {
			slog.Error("reanalyze: failed to read archive",
				"version_id", versionRecord.ID, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read archive"})
			return
		}

		doc, err := analyzer.AnalyzeArchive(bytes.NewReader(buf.Bytes()))
		if err != nil {
			slog.Warn("reanalyze: HCL analysis failed",
				"version_id", versionRecord.ID, "error", err)
			result["docs"] = "analysis_failed"
		} else if doc != nil {
			if err := h.moduleDocsRepo.UpsertModuleDocs(c.Request.Context(), versionRecord.ID, doc); err != nil {
				slog.Warn("reanalyze: failed to store docs",
					"version_id", versionRecord.ID, "error", err)
				result["docs"] = "store_failed"
			} else {
				result["docs"] = "updated"
				result["inputs"] = len(doc.Inputs)
				result["outputs"] = len(doc.Outputs)
			}
		} else {
			result["docs"] = "no_terraform_files"
		}
	} else {
		result["docs"] = "skipped_no_docs_repo"
	}

	// Re-queue security scan if configured
	if h.scanRepo != nil && h.cfg.Scanning.Enabled && h.cfg.Scanning.BinaryPath != "" {
		if err := h.scanRepo.UpsertPendingScan(c.Request.Context(), versionRecord.ID); err != nil {
			slog.Warn("reanalyze: failed to queue security scan",
				"version_id", versionRecord.ID, "error", err)
			result["scan"] = "queue_failed"
		} else {
			result["scan"] = "queued"
		}
	} else {
		result["scan"] = "not_configured"
	}

	result["message"] = "Re-analysis complete"
	c.JSON(http.StatusOK, result)
}

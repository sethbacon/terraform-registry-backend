// mirror.go implements handlers for provider mirror CRUD operations, manual sync triggering, and sync history retrieval.
package admin

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MirrorSyncJobInterface defines the interface for triggering manual syncs
type MirrorSyncJobInterface interface {
	TriggerManualSync(ctx context.Context, mirrorID uuid.UUID) error
}

// MirrorHandler handles mirror configuration endpoints
type MirrorHandler struct {
	mirrorRepo *repositories.MirrorRepository
	orgRepo    *repositories.OrganizationRepository
	syncJob    MirrorSyncJobInterface
}

// NewMirrorHandler creates a new mirror handler
func NewMirrorHandler(mirrorRepo *repositories.MirrorRepository, orgRepo *repositories.OrganizationRepository) *MirrorHandler {
	return &MirrorHandler{
		mirrorRepo: mirrorRepo,
		orgRepo:    orgRepo,
	}
}

// SetSyncJob sets the sync job for triggering manual syncs
func (h *MirrorHandler) SetSyncJob(syncJob MirrorSyncJobInterface) {
	h.syncJob = syncJob
}

// @Summary      Create mirror configuration
// @Description  Create a new provider mirror configuration. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.CreateMirrorConfigRequest  true  "Mirror configuration"
// @Success      201  {object}  models.MirrorConfiguration
// @Failure      400  {object}  map[string]interface{}  "Invalid request or registry URL"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Mirror with this name already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors [post]
// CreateMirrorConfig creates a new mirror configuration
// POST /api/v1/admin/mirrors
func (h *MirrorHandler) CreateMirrorConfig(c *gin.Context) {
	var req models.CreateMirrorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate registry URL
	if err := mirror.ValidateRegistryURL(req.UpstreamRegistryURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid registry URL: " + err.Error()})
		return
	}

	// Check if name already exists
	existing, err := h.mirrorRepo.GetByName(c.Request.Context(), req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing mirror: " + err.Error()})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Mirror configuration with this name already exists"})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, _ := c.Get("user_id")
	var createdBy *uuid.UUID
	if userID != nil {
		if uid, ok := userID.(uuid.UUID); ok {
			createdBy = &uid
		}
	}

	// Set defaults
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	syncInterval := 24
	if req.SyncIntervalHours != nil {
		syncInterval = *req.SyncIntervalHours
	}

	// Parse organization ID if provided; fall back to the default organization
	var orgID *uuid.UUID
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		parsed, err := uuid.Parse(*req.OrganizationID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
		orgID = &parsed
	} else {
		// Default to the default organization so mirrored providers are discoverable
		defaultOrg, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
		if err == nil && defaultOrg != nil {
			parsed := uuid.MustParse(defaultOrg.ID)
			orgID = &parsed
		}
	}

	// Convert filter arrays to JSON strings
	var namespaceFilter, providerFilter, platformFilter *string
	if len(req.NamespaceFilter) > 0 {
		jsonData, err := json.Marshal(req.NamespaceFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize namespace filter: " + err.Error()})
			return
		}
		str := string(jsonData)
		namespaceFilter = &str
	}
	if len(req.ProviderFilter) > 0 {
		jsonData, err := json.Marshal(req.ProviderFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize provider filter: " + err.Error()})
			return
		}
		str := string(jsonData)
		providerFilter = &str
	}
	if len(req.PlatformFilter) > 0 {
		jsonData, err := json.Marshal(req.PlatformFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize platform filter: " + err.Error()})
			return
		}
		str := string(jsonData)
		platformFilter = &str
	}

	config := &models.MirrorConfiguration{
		ID:                  uuid.New(),
		Name:                req.Name,
		Description:         req.Description,
		UpstreamRegistryURL: req.UpstreamRegistryURL,
		OrganizationID:      orgID,
		NamespaceFilter:     namespaceFilter,
		ProviderFilter:      providerFilter,
		VersionFilter:       req.VersionFilter,
		PlatformFilter:      platformFilter,
		Enabled:             enabled,
		SyncIntervalHours:   syncInterval,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		CreatedBy:           createdBy,
	}

	if err := h.mirrorRepo.Create(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create mirror configuration: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, config)
}

// @Summary      List mirror configurations
// @Description  List all provider mirror configurations, optionally filtered to enabled only. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Produce      json
// @Param        enabled  query  bool  false  "Filter to enabled mirrors only"
// @Success      200  {object}  map[string]interface{}  "mirrors: []models.MirrorConfiguration"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors [get]
// ListMirrorConfigs lists all mirror configurations
// GET /api/v1/admin/mirrors
func (h *MirrorHandler) ListMirrorConfigs(c *gin.Context) {
	enabledOnly := c.Query("enabled") == "true"

	configs, err := h.mirrorRepo.List(c.Request.Context(), enabledOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list mirror configurations: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"mirrors": configs})
}

// @Summary      Get mirror configuration
// @Description  Retrieve a specific mirror configuration by ID. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror configuration ID (UUID)"
// @Success      200  {object}  models.MirrorConfiguration
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id} [get]
// GetMirrorConfig retrieves a specific mirror configuration
// GET /api/v1/admin/mirrors/:id
func (h *MirrorHandler) GetMirrorConfig(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	config, err := h.mirrorRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get mirror configuration: " + err.Error()})
		return
	}

	if config == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// @Summary      Update mirror configuration
// @Description  Update a provider mirror configuration. All fields are optional. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                          true  "Mirror configuration ID (UUID)"
// @Param        body  body  models.UpdateMirrorConfigRequest  true  "Fields to update"
// @Success      200  {object}  models.MirrorConfiguration
// @Failure      400  {object}  map[string]interface{}  "Invalid request, ID, or registry URL"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
// @Failure      409  {object}  map[string]interface{}  "Name conflict with another mirror"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id} [put]
// UpdateMirrorConfig updates a mirror configuration
// PUT /api/v1/admin/mirrors/:id
func (h *MirrorHandler) UpdateMirrorConfig(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	var req models.UpdateMirrorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing config
	config, err := h.mirrorRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get mirror configuration: " + err.Error()})
		return
	}
	if config == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return
	}

	// Update fields if provided
	if req.Name != nil {
		// Check if new name conflicts with another config
		if *req.Name != config.Name {
			existing, err := h.mirrorRepo.GetByName(c.Request.Context(), *req.Name)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing mirror: " + err.Error()})
				return
			}
			if existing != nil {
				c.JSON(http.StatusConflict, gin.H{"error": "Mirror configuration with this name already exists"})
				return
			}
		}
		config.Name = *req.Name
	}

	if req.Description != nil {
		config.Description = req.Description
	}

	if req.UpstreamRegistryURL != nil {
		if err := mirror.ValidateRegistryURL(*req.UpstreamRegistryURL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid registry URL: " + err.Error()})
			return
		}
		config.UpstreamRegistryURL = *req.UpstreamRegistryURL
	}

	if req.NamespaceFilter != nil {
		if len(req.NamespaceFilter) > 0 {
			jsonData, err := json.Marshal(req.NamespaceFilter)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize namespace filter: " + err.Error()})
				return
			}
			str := string(jsonData)
			config.NamespaceFilter = &str
		} else {
			config.NamespaceFilter = nil
		}
	}

	if req.ProviderFilter != nil {
		if len(req.ProviderFilter) > 0 {
			jsonData, err := json.Marshal(req.ProviderFilter)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize provider filter: " + err.Error()})
				return
			}
			str := string(jsonData)
			config.ProviderFilter = &str
		} else {
			config.ProviderFilter = nil
		}
	}

	if req.VersionFilter != nil {
		if *req.VersionFilter != "" {
			config.VersionFilter = req.VersionFilter
		} else {
			config.VersionFilter = nil
		}
	}

	if req.PlatformFilter != nil {
		if len(req.PlatformFilter) > 0 {
			jsonData, err := json.Marshal(req.PlatformFilter)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize platform filter: " + err.Error()})
				return
			}
			str := string(jsonData)
			config.PlatformFilter = &str
		} else {
			config.PlatformFilter = nil
		}
	}

	if req.OrganizationID != nil {
		if *req.OrganizationID != "" {
			parsed, err := uuid.Parse(*req.OrganizationID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
				return
			}
			config.OrganizationID = &parsed
		} else {
			config.OrganizationID = nil
		}
	}

	if req.Enabled != nil {
		config.Enabled = *req.Enabled
	}

	if req.SyncIntervalHours != nil {
		config.SyncIntervalHours = *req.SyncIntervalHours
	}

	if err := h.mirrorRepo.Update(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update mirror configuration: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, config)
}

// @Summary      Delete mirror configuration
// @Description  Delete a provider mirror configuration and its sync history. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror configuration ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: Mirror configuration deleted successfully"
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id} [delete]
// DeleteMirrorConfig deletes a mirror configuration
// DELETE /api/v1/admin/mirrors/:id
func (h *MirrorHandler) DeleteMirrorConfig(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	if err := h.mirrorRepo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete mirror configuration: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Mirror configuration deleted successfully"})
}

// @Summary      Trigger mirror sync
// @Description  Trigger an immediate sync for a mirror configuration. Returns 409 if a sync is already in progress. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                       true  "Mirror configuration ID (UUID)"
// @Param        body  body  models.TriggerSyncRequest  false  "Optional sync options"
// @Success      202  {object}  map[string]interface{}  "message: Sync triggered successfully"
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
// @Failure      409  {object}  map[string]interface{}  "Sync already in progress"
// @Failure      503  {object}  map[string]interface{}  "Sync job not configured"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id}/sync [post]
// TriggerSync triggers a manual sync for a mirror configuration
// POST /api/v1/admin/mirrors/:id/sync
func (h *MirrorHandler) TriggerSync(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	var req models.TriggerSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty body is OK for triggering full sync
		req = models.TriggerSyncRequest{}
	}

	// Get mirror config
	config, err := h.mirrorRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get mirror configuration: " + err.Error()})
		return
	}
	if config == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return
	}

	// Trigger the actual sync via the background job
	// The job will handle creating the sync history record and checking for active syncs
	if h.syncJob != nil {
		log.Printf("API: Triggering manual sync for mirror %s (ID: %s)", config.Name, id) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
		if err := h.syncJob.TriggerManualSync(c.Request.Context(), id); err != nil {
			if err.Error() == "sync already in progress for this mirror" {
				c.JSON(http.StatusConflict, gin.H{"error": "A sync is already in progress for this mirror"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to trigger sync: " + err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Sync job not configured"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Sync triggered successfully",
	})
}

// @Summary      Get mirror sync status
// @Description  Get the current sync status, active sync, and recent sync history for a mirror. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror configuration ID (UUID)"
// @Success      200  {object}  models.MirrorSyncStatus
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id}/status [get]
// GetMirrorStatus retrieves the status and sync history for a mirror configuration
// GET /api/v1/admin/mirrors/:id/status
func (h *MirrorHandler) GetMirrorStatus(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	// Get mirror config
	config, err := h.mirrorRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get mirror configuration: " + err.Error()})
		return
	}
	if config == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return
	}

	// Get active sync
	activeSync, err := h.mirrorRepo.GetActiveSyncHistory(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get active sync: " + err.Error()})
		return
	}

	// Get recent sync history (last 10)
	recentSyncs, err := h.mirrorRepo.GetSyncHistory(c.Request.Context(), id, 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sync history: " + err.Error()})
		return
	}

	// Calculate next scheduled sync
	var nextScheduled *time.Time
	if config.Enabled && config.LastSyncAt != nil {
		next := config.LastSyncAt.Add(time.Duration(config.SyncIntervalHours) * time.Hour)
		nextScheduled = &next
	}

	status := models.MirrorSyncStatus{
		MirrorConfig:  *config,
		CurrentSync:   activeSync,
		RecentSyncs:   recentSyncs,
		NextScheduled: nextScheduled,
	}

	c.JSON(http.StatusOK, status)
}

// @Summary      List mirrored providers
// @Description  List all providers that have been synced for a mirror configuration, including their synced versions. Requires admin scope.
// @Tags         Mirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror configuration ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "providers: []MirroredProviderWithVersions"
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors/{id}/providers [get]
// ListMirroredProviders lists providers synced into a mirror config with their versions
// GET /api/v1/admin/mirrors/:id/providers
func (h *MirrorHandler) ListMirroredProviders(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror ID"})
		return
	}

	config, err := h.mirrorRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get mirror configuration: " + err.Error()})
		return
	}
	if config == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return
	}

	providers, err := h.mirrorRepo.ListMirroredProviders(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list mirrored providers: " + err.Error()})
		return
	}

	type MirroredProviderWithVersions struct {
		models.MirroredProvider
		Versions []interface{} `json:"versions"`
	}

	result := make([]MirroredProviderWithVersions, 0, len(providers))
	for _, p := range providers {
		versions, err := h.mirrorRepo.ListMirroredProviderVersions(c.Request.Context(), p.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list provider versions: " + err.Error()})
			return
		}
		versionList := make([]interface{}, len(versions))
		for i, v := range versions {
			versionList[i] = v
		}
		result = append(result, MirroredProviderWithVersions{
			MirroredProvider: p,
			Versions:         versionList,
		})
	}

	c.JSON(http.StatusOK, gin.H{"providers": result})
}

// RegisterRoutes registers all mirror management routes
func (h *MirrorHandler) RegisterRoutes(router *gin.RouterGroup) {
	mirrors := router.Group("/mirrors")
	{
		mirrors.POST("", h.CreateMirrorConfig)
		mirrors.GET("", h.ListMirrorConfigs)
		mirrors.GET("/:id", h.GetMirrorConfig)
		mirrors.PUT("/:id", h.UpdateMirrorConfig)
		mirrors.DELETE("/:id", h.DeleteMirrorConfig)
		mirrors.POST("/:id/sync", h.TriggerSync)
		mirrors.GET("/:id/status", h.GetMirrorStatus)
		mirrors.GET("/:id/providers", h.ListMirroredProviders)
	}
}

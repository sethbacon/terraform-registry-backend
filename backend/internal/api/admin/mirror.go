// mirror.go implements handlers for provider mirror CRUD operations, manual sync triggering, and sync history retrieval.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/terraform-registry/terraform-registry/internal/validation"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
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
	mirrorRepo   *repositories.MirrorRepository
	orgRepo      *repositories.OrganizationRepository
	providerRepo *repositories.ProviderRepository
	syncJob      MirrorSyncJobInterface
	// egress is consulted (via mirror.ValidateRegistryURL) on every create/update
	// so a non-admin "devops"-scoped caller cannot point a mirror at a private
	// or cloud-metadata address; nil enforces the strict default deny-list.
	egress *httpsafe.Guard
}

// NewMirrorHandler creates a new mirror handler
func NewMirrorHandler(mirrorRepo *repositories.MirrorRepository, orgRepo *repositories.OrganizationRepository, providerRepo *repositories.ProviderRepository) *MirrorHandler {
	return &MirrorHandler{
		mirrorRepo:   mirrorRepo,
		orgRepo:      orgRepo,
		providerRepo: providerRepo,
	}
}

// SetSyncJob sets the sync job for triggering manual syncs
func (h *MirrorHandler) SetSyncJob(syncJob MirrorSyncJobInterface) {
	h.syncJob = syncJob
}

// SetEgressGuard installs the operator-configured egress guard
// (security.egress.allowlist) consulted when validating upstream_registry_url
// on create/update. Returns the handler for chaining.
func (h *MirrorHandler) SetEgressGuard(g *httpsafe.Guard) *MirrorHandler {
	h.egress = g
	return h
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
// validateMirrorFilters rejects namespace/provider filter entries that are not
// valid registry identifiers.
//
// These are not merely a selection filter: mirror_sync interpolates them
// directly into the storage key
//
//	fmt.Sprintf("providers/%s/%s/%s/%s/%s/%s", namespace, providerName, ...)
//
// and into the upstream registry request path. Every other segment of that key
// is a validated registry identifier or a platform value -- a comment there
// even asserts as much -- but these two arrived from admin-supplied JSON with
// no validation at all, so "../.." in a provider filter reached the object key
// (issue #752).
//
// Applied on create AND update: validating only one leaves the other as the way
// in.
func validateMirrorFilters(namespaces, providers []string) error {
	for _, group := range []struct {
		field  string
		values []string
	}{
		{"namespace_filter", namespaces},
		{"provider_filter", providers},
	} {
		for _, v := range group.values {
			if err := validation.ValidateRegistrySegment(v); err != nil {
				return fmt.Errorf("%s: %w", group.field, err)
			}
		}
	}
	return nil
}

func (h *MirrorHandler) CreateMirrorConfig(c *gin.Context) {
	var req models.CreateMirrorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate registry URL
	if err := mirror.ValidateRegistryURL(req.UpstreamRegistryURL, h.egress); err != nil {
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

	// GUARD mirror-create-target-org (issue #719): the create axis takes its
	// organization straight from the request body, so no route guard can bind
	// it — there is no existing row to resolve an owner from. Without this, any
	// holder of the flat mirrors:manage scope union could plant a mirror
	// configuration inside another organization, where it becomes a
	// pull-through source for that tenant's providers.
	//
	// The OMITTED case runs through the same guard as the supplied one. It used
	// to skip it entirely and fall through to GetDefaultOrganization with no
	// membership check, so the whole guard was bypassable by deleting one field
	// from the request body — cross-tenant write by omission.
	requestedOrg := ""
	if req.OrganizationID != nil {
		requestedOrg = *req.OrganizationID
	}
	if requestedOrg != "" {
		if _, err := uuid.Parse(requestedOrg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
	}
	targetOrg, ok := resolveTargetOrganization(c, h.orgRepo, auth.ScopeMirrorsManage, requestedOrg)
	if !ok {
		return
	}
	var orgID *uuid.UUID
	if targetOrg != "" {
		parsed, err := uuid.Parse(targetOrg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve organization"})
			return
		}
		orgID = &parsed
	}

	if err := validateMirrorFilters(req.NamespaceFilter, req.ProviderFilter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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

	pullThroughEnabled := false
	if req.PullThroughEnabled != nil {
		pullThroughEnabled = *req.PullThroughEnabled
	}

	pullThroughTTL := 24
	if req.PullThroughCacheTTLHours != nil {
		pullThroughTTL = *req.PullThroughCacheTTLHours
	}

	requiresApproval := false
	if req.RequiresApproval != nil {
		requiresApproval = *req.RequiresApproval
	}

	config := &models.MirrorConfiguration{
		ID:                       uuid.New(),
		Name:                     req.Name,
		Description:              req.Description,
		UpstreamRegistryURL:      req.UpstreamRegistryURL,
		OrganizationID:           orgID,
		NamespaceFilter:          namespaceFilter,
		ProviderFilter:           providerFilter,
		VersionFilter:            req.VersionFilter,
		PlatformFilter:           platformFilter,
		Enabled:                  enabled,
		SyncIntervalHours:        syncInterval,
		RequiresApproval:         requiresApproval,
		AutoApproveRules:         req.AutoApproveRules,
		PullThroughEnabled:       pullThroughEnabled,
		PullThroughCacheTTLHours: pullThroughTTL,
		CreatedAt:                time.Now(),
		UpdatedAt:                time.Now(),
		CreatedBy:                createdBy,
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
// @Success      200  {object}  admin.ListMirrorConfigsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/mirrors [get]
// ListMirrorConfigs lists all mirror configurations
// GET /api/v1/admin/mirrors
func (h *MirrorHandler) ListMirrorConfigs(c *gin.Context) {
	enabledOnly := c.Query("enabled") == "true"

	// GUARD mirror-list-tenant-scope (issue #719).
	//
	// The per-resource guard on /admin/mirrors/:id cannot help the list axis:
	// there is no row named in the path to resolve an owner from. Left
	// unscoped, this route enumerated every organization's mirror
	// configurations — upstream registry URLs, filters and sync state — to any
	// holder of the flat mirrors:read scope union, and handed out the very ids
	// the per-resource routes are keyed on.
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsRead)
	if !ok {
		return
	}

	configs, err := h.mirrorRepo.List(c.Request.Context(), enabledOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list mirror configurations: " + err.Error()})
		return
	}

	visible := make([]models.MirrorConfiguration, 0, len(configs))
	for _, cfg := range configs {
		orgID := ""
		if cfg.OrganizationID != nil {
			orgID = cfg.OrganizationID.String()
		}
		if scope.Permits(orgID) {
			visible = append(visible, cfg)
		}
	}

	c.JSON(http.StatusOK, gin.H{"mirrors": visible})
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

	if err := validateMirrorFilters(req.NamespaceFilter, req.ProviderFilter); err != nil {
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
		if err := mirror.ValidateRegistryURL(*req.UpstreamRegistryURL, h.egress); err != nil {
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
		// GUARD mirror-update-reparent-org (issue #719): the route's
		// per-resource guard authorized the caller against this row's CURRENT
		// owner. It says nothing about the owner being asked for. Without this
		// check, a caller legitimately holding mirrors:manage in org A could
		// re-parent A's mirror configuration into org B and then keep operating
		// it under B's tenancy — a write across the tenant boundary that every
		// by-id read guard would still pass.
		//
		// GUARD mirror-update-unparent-org (issue #719): an EMPTY STRING is the
		// same attack with a different spelling. It used to null the column
		// unconditionally, and jobs/mirror_sync.go resolves a NULL organization
		// back to the DEFAULT organization when it materialises providers — so
		// `{"organization_id": ""}` re-parented the row into the default org
		// without ever naming it, straight through the guard above. Un-owning a
		// row is a platform-operator action and is now treated as one.
		if *req.OrganizationID == "" {
			scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsManage)
			if !ok {
				return
			}
			if !scope.PlatformAdmin {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Clearing organization_id is restricted to platform administrators: " +
						"an unowned mirror configuration is synced under the default organization",
				})
				return
			}
			config.OrganizationID = nil
		} else {
			parsed, err := uuid.Parse(*req.OrganizationID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
				return
			}
			if !requireTenantScopeForOrg(c, h.orgRepo, auth.ScopeMirrorsManage, parsed.String()) {
				return
			}
			config.OrganizationID = &parsed
		}
	}

	if req.Enabled != nil {
		config.Enabled = *req.Enabled
	}

	if req.SyncIntervalHours != nil {
		config.SyncIntervalHours = *req.SyncIntervalHours
	}

	if req.PullThroughEnabled != nil {
		config.PullThroughEnabled = *req.PullThroughEnabled
	}

	if req.PullThroughCacheTTLHours != nil {
		config.PullThroughCacheTTLHours = *req.PullThroughCacheTTLHours
	}

	if req.RequiresApproval != nil {
		config.RequiresApproval = *req.RequiresApproval
	}

	if req.AutoApproveRules != nil {
		config.AutoApproveRules = req.AutoApproveRules
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
// @Success      200  {object}  admin.MessageResponse
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
// @Success      202  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid mirror ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Mirror configuration not found"
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
				c.JSON(http.StatusAccepted, gin.H{"message": "Sync already in progress"})
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
// @Param        id      path   string  true   "Mirror configuration ID (UUID)"
// @Param        limit   query  int     false  "Maximum results (default 100, max 1000)"
// @Param        offset  query  int     false  "Offset for pagination (default 0)"
// @Success      200  {object}  admin.ListMirroredProvidersResponse
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

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 1000 {
		limit = 1000
	}
	if limit < 1 {
		limit = 1
	}
	if offset < 0 {
		offset = 0
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

	providers, total, err := h.mirrorRepo.ListMirroredProvidersPaginated(c.Request.Context(), id, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list mirrored providers: " + err.Error()})
		return
	}

	// Explicit JSON projection for ProviderPlatform — the model has no json tags
	// so embedding it would serialize as "OS", "Arch" etc. (Go field names).
	type platformJSON struct {
		ID                string `json:"id"`
		ProviderVersionID string `json:"provider_version_id"`
		OS                string `json:"os"`
		Arch              string `json:"arch"`
		Filename          string `json:"filename"`
		Shasum            string `json:"shasum"`
	}

	type versionWithPlatforms struct {
		models.MirroredProviderVersion
		Platforms []platformJSON `json:"platforms"`
	}

	type mirroredProviderWithVersions struct {
		models.MirroredProvider
		Versions []versionWithPlatforms `json:"versions"`
	}

	result := make([]mirroredProviderWithVersions, 0, len(providers))
	for _, p := range providers {
		versions, err := h.mirrorRepo.ListMirroredProviderVersions(c.Request.Context(), p.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list provider versions: " + err.Error()})
			return
		}
		versionList := make([]versionWithPlatforms, 0, len(versions))
		for _, v := range versions {
			var rawPlatforms []*models.ProviderPlatform
			if h.providerRepo != nil {
				rawPlatforms, err = h.providerRepo.ListPlatforms(c.Request.Context(), v.ProviderVersionID.String())
				if err != nil {
					rawPlatforms = nil
				}
			}
			platforms := make([]platformJSON, 0, len(rawPlatforms))
			for _, pl := range rawPlatforms {
				platforms = append(platforms, platformJSON{
					ID:                pl.ID,
					ProviderVersionID: pl.ProviderVersionID,
					OS:                pl.OS,
					Arch:              pl.Arch,
					Filename:          pl.Filename,
					Shasum:            pl.Shasum,
				})
			}
			versionList = append(versionList, versionWithPlatforms{
				MirroredProviderVersion: v,
				Platforms:               platforms,
			})
		}
		result = append(result, mirroredProviderWithVersions{
			MirroredProvider: p,
			Versions:         versionList,
		})
	}

	c.JSON(http.StatusOK, gin.H{"providers": result, "total": total, "limit": limit, "offset": offset})
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

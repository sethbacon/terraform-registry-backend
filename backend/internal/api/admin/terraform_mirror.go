// terraform_mirror.go implements admin HTTP handlers for the Terraform binary mirror.
// The multi-config design mirrors the provider mirror feature: full CRUD for configs,
// per-config sync triggering, and per-config version/platform/history inspection.
//
// All endpoints are secured with mirrors:read / mirrors:manage scopes.
package admin

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TerraformMirrorSyncJobInterface is the subset of TerraformMirrorSyncJob required by the handler.
type TerraformMirrorSyncJobInterface interface {
	TriggerSync(ctx context.Context, configID uuid.UUID) error
}

// TerraformMirrorHandler handles admin endpoints for the Terraform binary mirror.
type TerraformMirrorHandler struct {
	repo    *repositories.TerraformMirrorRepository
	syncJob TerraformMirrorSyncJobInterface
}

// NewTerraformMirrorHandler creates a new TerraformMirrorHandler.
func NewTerraformMirrorHandler(repo *repositories.TerraformMirrorRepository) *TerraformMirrorHandler {
	return &TerraformMirrorHandler{repo: repo}
}

// SetSyncJob attaches the live sync job so handlers can trigger manual syncs.
func (h *TerraformMirrorHandler) SetSyncJob(syncJob TerraformMirrorSyncJobInterface) {
	h.syncJob = syncJob
}

// ---- POST /api/v1/admin/terraform-mirrors ----------------------------------

// @Summary      Create Terraform mirror configuration
// @Description  Creates a new named Terraform binary mirror configuration. Requires mirrors:manage scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.CreateTerraformMirrorConfigRequest  true  "Mirror configuration"
// @Success      201  {object}  models.TerraformMirrorConfig
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Config with this name already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors [post]
func (h *TerraformMirrorHandler) CreateConfig(c *gin.Context) {
	var req models.CreateTerraformMirrorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing, err := h.repo.GetByName(c.Request.Context(), req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing config: " + err.Error()})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "A Terraform mirror config with this name already exists"})
		return
	}

	gpgVerify := true
	if req.GPGVerify != nil {
		gpgVerify = *req.GPGVerify
	}
	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	syncIntervalHours := 24
	if req.SyncIntervalHours != nil {
		syncIntervalHours = *req.SyncIntervalHours
	}

	encoded, encErr := repositories.EncodePlatformFilter(req.PlatformFilter)
	if encErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid platform_filter: " + encErr.Error()})
		return
	}

	cfg := &models.TerraformMirrorConfig{
		Name:              req.Name,
		Description:       req.Description,
		Tool:              req.Tool,
		Enabled:           enabled,
		UpstreamURL:       req.UpstreamURL,
		PlatformFilter:    encoded,
		GPGVerify:         gpgVerify,
		SyncIntervalHours: syncIntervalHours,
	}

	if createErr := h.repo.Create(c.Request.Context(), cfg); createErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create config: " + createErr.Error()})
		return
	}

	c.JSON(http.StatusCreated, cfg)
}

// ---- GET /api/v1/admin/terraform-mirrors -----------------------------------

// @Summary      List Terraform mirror configurations
// @Description  Returns all Terraform binary mirror configurations. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  models.TerraformMirrorConfigListResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors [get]
func (h *TerraformMirrorHandler) ListConfigs(c *gin.Context) {
	configs, err := h.repo.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list configs: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TerraformMirrorConfigListResponse{
		Configs:    configs,
		TotalCount: len(configs),
	})
}

// ---- GET /api/v1/admin/terraform-mirrors/:id --------------------------------

// @Summary      Get Terraform mirror configuration
// @Description  Returns a specific Terraform binary mirror configuration. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id   path  string  true  "Mirror config UUID"
// @Success      200  {object}  models.TerraformMirrorConfig
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id} [get]
func (h *TerraformMirrorHandler) GetConfig(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get config: " + err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return
	}

	c.JSON(http.StatusOK, cfg)
}

// ---- GET /api/v1/admin/terraform-mirrors/:id/status ------------------------

// @Summary      Get Terraform mirror status
// @Description  Returns the status and summary stats for a specific mirror config. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id   path  string  true  "Mirror config UUID"
// @Success      200  {object}  models.TerraformMirrorStatusResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/status [get]
func (h *TerraformMirrorHandler) GetStatus(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get config: " + err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return
	}

	total, synced, pending, statsErr := h.repo.CountVersionStats(c.Request.Context(), id)
	if statsErr != nil {
		log.Printf("[terraform-mirror] failed to count stats for %s: %v", id, statsErr)
	}

	latest, _ := h.repo.GetLatestVersion(c.Request.Context(), id)
	var latestStr *string
	if latest != nil {
		latestStr = &latest.Version
	}

	c.JSON(http.StatusOK, models.TerraformMirrorStatusResponse{
		Config:        cfg,
		VersionCount:  synced,
		PlatformCount: total,
		PendingCount:  pending,
		LatestVersion: latestStr,
	})
}

// ---- PUT /api/v1/admin/terraform-mirrors/:id --------------------------------

// @Summary      Update Terraform mirror configuration
// @Description  Updates a Terraform binary mirror configuration. Requires mirrors:manage scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                                    true  "Mirror config UUID"
// @Param        body  body  models.UpdateTerraformMirrorConfigRequest true  "Mirror configuration update"
// @Success      200  {object}  models.TerraformMirrorConfig
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      409  {object}  map[string]interface{}  "Name already taken"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id} [put]
func (h *TerraformMirrorHandler) UpdateConfig(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	var req models.UpdateTerraformMirrorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load config: " + err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return
	}

	// Check name uniqueness if name is being changed.
	if req.Name != nil && *req.Name != cfg.Name {
		existing, checkErr := h.repo.GetByName(c.Request.Context(), *req.Name)
		if checkErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check name: " + checkErr.Error()})
			return
		}
		if existing != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "A mirror config with this name already exists"})
			return
		}
		cfg.Name = *req.Name
	}

	if req.Description != nil {
		cfg.Description = req.Description
	}
	if req.Tool != nil {
		cfg.Tool = *req.Tool
	}
	if req.UpstreamURL != nil {
		cfg.UpstreamURL = *req.UpstreamURL
	}
	if req.GPGVerify != nil {
		cfg.GPGVerify = *req.GPGVerify
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.SyncIntervalHours != nil {
		cfg.SyncIntervalHours = *req.SyncIntervalHours
	}
	if req.PlatformFilter != nil {
		encoded, encErr := repositories.EncodePlatformFilter(req.PlatformFilter)
		if encErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid platform_filter: " + encErr.Error()})
			return
		}
		cfg.PlatformFilter = encoded
	}

	if updateErr := h.repo.Update(c.Request.Context(), cfg); updateErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config: " + updateErr.Error()})
		return
	}

	c.JSON(http.StatusOK, cfg)
}

// ---- DELETE /api/v1/admin/terraform-mirrors/:id -----------------------------

// @Summary      Delete Terraform mirror configuration
// @Description  Deletes a Terraform binary mirror config and all its associated versions/history. Requires mirrors:manage scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror config UUID"
// @Success      200  {object}  map[string]interface{}  "Deleted"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id} [delete]
func (h *TerraformMirrorHandler) DeleteConfig(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up config: " + err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return
	}

	if delErr := h.repo.Delete(c.Request.Context(), id); delErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete config: " + delErr.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Mirror config deleted", "id": id, "name": cfg.Name})
}

// ---- POST /api/v1/admin/terraform-mirrors/:id/sync -------------------------

// @Summary      Trigger Terraform mirror sync
// @Description  Enqueues a manual sync for the specified mirror config. Requires mirrors:manage scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Mirror config UUID"
// @Success      202  {object}  map[string]interface{}  "Sync enqueued"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      503  {object}  map[string]interface{}  "Sync queue full"
// @Router       /api/v1/admin/terraform-mirrors/{id}/sync [post]
func (h *TerraformMirrorHandler) TriggerSync(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	// Verify config exists.
	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up config: " + err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return
	}

	if h.syncJob == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Sync job not initialised"})
		return
	}

	if err := h.syncJob.TriggerSync(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":      "Sync enqueued",
		"config_id":    id,
		"triggered_at": time.Now().UTC(),
	})
}

// ---- GET /api/v1/admin/terraform-mirrors/:id/versions ----------------------

// @Summary      List mirrored Terraform versions
// @Description  Returns all Terraform versions known to the specified mirror config. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id         path   string  true   "Mirror config UUID"
// @Param        platforms  query  bool    false  "Include per-version platform details"
// @Param        synced     query  bool    false  "Only return fully synced versions"
// @Success      200  {object}  models.TerraformVersionListResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/versions [get]
func (h *TerraformMirrorHandler) ListVersions(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	if exists, err := h.configExists(c, id); err != nil || !exists {
		return
	}

	syncedOnly := c.Query("synced") == "true"
	withPlatforms := c.Query("platforms") == "true"

	versions, err := h.repo.ListVersions(c.Request.Context(), id, syncedOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list versions: " + err.Error()})
		return
	}

	if withPlatforms {
		for i := range versions {
			platforms, platErr := h.repo.ListPlatformsForVersion(c.Request.Context(), versions[i].ID)
			if platErr != nil {
				log.Printf("[terraform-mirror] failed to load platforms for version %s: %v", versions[i].Version, platErr) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
				continue
			}
			versions[i].Platforms = platforms
		}
	}

	c.JSON(http.StatusOK, models.TerraformVersionListResponse{
		Versions:   versions,
		TotalCount: len(versions),
	})
}

// ---- GET /api/v1/admin/terraform-mirrors/:id/versions/:version -------------

// @Summary      Get a specific mirrored Terraform version
// @Description  Returns metadata and per-platform sync status for a single version. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id       path  string  true  "Mirror config UUID"
// @Param        version  path  string  true  "Terraform version (e.g. 1.7.0)"
// @Success      200  {object}  models.TerraformVersion
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/versions/{version} [get]
func (h *TerraformMirrorHandler) GetVersion(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	versionStr := c.Param("version")

	v, err := h.repo.GetVersionByString(c.Request.Context(), id, versionStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load version: " + err.Error()})
		return
	}
	if v == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	platforms, platErr := h.repo.ListPlatformsForVersion(c.Request.Context(), v.ID)
	if platErr != nil {
		log.Printf("[terraform-mirror] failed to load platforms for version %s: %v", versionStr, platErr)
	} else {
		v.Platforms = platforms
	}

	c.JSON(http.StatusOK, v)
}

// ---- DELETE /api/v1/admin/terraform-mirrors/:id/versions/:version ----------

// @Summary      Delete a mirrored Terraform version
// @Description  Removes a version and its platform records. Stored binaries are not deleted from storage. Requires mirrors:manage scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id       path  string  true  "Mirror config UUID"
// @Param        version  path  string  true  "Terraform version (e.g. 1.7.0)"
// @Success      200  {object}  map[string]interface{}  "Deleted"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/versions/{version} [delete]
func (h *TerraformMirrorHandler) DeleteVersion(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	versionStr := c.Param("version")

	v, err := h.repo.GetVersionByString(c.Request.Context(), id, versionStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up version: " + err.Error()})
		return
	}
	if v == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	if delErr := h.repo.DeleteVersion(c.Request.Context(), v.ID); delErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete version: " + delErr.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Version deleted", "version": versionStr})
}

// ---- GET /api/v1/admin/terraform-mirrors/:id/history ----------------------

// @Summary      Get Terraform mirror sync history
// @Description  Returns the most recent sync run records for the specified config. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id     path   string  true   "Mirror config UUID"
// @Param        limit  query  int     false  "Maximum number of history rows to return (default: 50)"
// @Success      200  {object}  models.TerraformSyncHistoryListResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/history [get]
func (h *TerraformMirrorHandler) GetSyncHistory(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	if exists, err := h.configExists(c, id); err != nil || !exists {
		return
	}

	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	history, err := h.repo.ListSyncHistory(c.Request.Context(), id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load history: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TerraformSyncHistoryListResponse{
		History:    history,
		TotalCount: len(history),
	})
}

// ---- GET /api/v1/admin/terraform-mirrors/:id/versions/:version/platforms ---

// @Summary      List platforms for a Terraform version
// @Description  Returns per-platform sync details for a specific version. Requires mirrors:read scope.
// @Tags         TerraformMirror
// @Security     Bearer
// @Produce      json
// @Param        id       path  string  true  "Mirror config UUID"
// @Param        version  path  string  true  "Terraform version"
// @Success      200  {object}  []models.TerraformVersionPlatform
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/terraform-mirrors/{id}/versions/{version}/platforms [get]
func (h *TerraformMirrorHandler) ListPlatforms(c *gin.Context) {
	id, ok := parseMirrorID(c)
	if !ok {
		return
	}

	versionStr := c.Param("version")

	v, err := h.repo.GetVersionByString(c.Request.Context(), id, versionStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up version: " + err.Error()})
		return
	}
	if v == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	platforms, platErr := h.repo.ListPlatformsForVersion(c.Request.Context(), v.ID)
	if platErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list platforms: " + platErr.Error()})
		return
	}

	c.JSON(http.StatusOK, platforms)
}

// ---- Helpers ---------------------------------------------------------------

// parseMirrorID parses the :id path parameter as a UUID and writes a 400 on failure.
func parseMirrorID(c *gin.Context) (uuid.UUID, bool) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror config ID"})
		return uuid.Nil, false
	}
	return id, true
}

// configExists checks whether a mirror config exists by ID and writes 404/500 on failure.
func (h *TerraformMirrorHandler) configExists(c *gin.Context, id uuid.UUID) (bool, error) {
	cfg, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up config: " + err.Error()})
		return false, err
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror config not found"})
		return false, nil
	}
	return true, nil
}

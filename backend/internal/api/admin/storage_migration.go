// storage_migration.go implements HTTP handlers for the storage migration wizard,
// allowing administrators to plan, start, monitor, and cancel migrations of
// artifacts between storage backends.
package admin

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// StorageMigrationHandler exposes endpoints for the storage migration wizard.
type StorageMigrationHandler struct {
	service *services.StorageMigrationService
}

// NewStorageMigrationHandler creates a new handler wired to the given service.
// coverage:skip:requires-infrastructure
func NewStorageMigrationHandler(service *services.StorageMigrationService) *StorageMigrationHandler {
	return &StorageMigrationHandler{service: service}
}

// planRequest is the JSON body expected by PlanMigration.
type planRequest struct {
	SourceConfigID string `json:"source_config_id" binding:"required"`
	TargetConfigID string `json:"target_config_id" binding:"required"`
}

// startMigrationRequest is the JSON body expected by StartMigration.
type startMigrationRequest struct {
	SourceConfigID string `json:"source_config_id" binding:"required"`
	TargetConfigID string `json:"target_config_id" binding:"required"`
}

// @Summary      Plan storage migration
// @Description  Counts artifacts that would be migrated between two storage configurations. Does not start a migration. Requires admin scope.
// @Tags         Storage Migration
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  admin.planRequest  true  "Source and target storage config IDs"
// @Success      200  {object}  models.MigrationPlan
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/storage/migrations/plan [post]
// PlanMigration returns a dry-run count of artifacts that would be migrated.
// coverage:skip:requires-infrastructure
func (h *StorageMigrationHandler) PlanMigration(c *gin.Context) {
	var req planRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plan, err := h.service.PlanMigration(c.Request.Context(), req.SourceConfigID, req.TargetConfigID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, plan)
}

// @Summary      Start storage migration
// @Description  Creates a new migration job and begins copying artifacts from the source to the target storage backend in the background. Requires admin scope.
// @Tags         Storage Migration
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  admin.startMigrationRequest  true  "Source and target storage config IDs"
// @Success      202  {object}  models.StorageMigration
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/storage/migrations [post]
// StartMigration creates and kicks off a new migration job.
// coverage:skip:requires-infrastructure
func (h *StorageMigrationHandler) StartMigration(c *gin.Context) {
	var req startMigrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userID string
	if uid, exists := c.Get("user_id"); exists {
		if u, ok := uid.(uuid.UUID); ok {
			userID = u.String()
		}
	}

	migration, err := h.service.StartMigration(c.Request.Context(), req.SourceConfigID, req.TargetConfigID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, migration)
}

// @Summary      List storage migrations
// @Description  Returns a paginated list of storage migration jobs. Requires admin scope.
// @Tags         Storage Migration
// @Security     Bearer
// @Produce      json
// @Param        limit   query  int  false  "Max results (default 20)"
// @Param        offset  query  int  false  "Offset for pagination (default 0)"
// @Success      200  {object}  map[string]interface{}  "migrations array and pagination"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/storage/migrations [get]
// ListMigrations returns all migration jobs, newest first.
// coverage:skip:requires-infrastructure
func (h *StorageMigrationHandler) ListMigrations(c *gin.Context) {
	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	migrations, total, err := h.service.ListMigrations(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list migrations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"migrations": migrations,
		"pagination": gin.H{
			"limit":  limit,
			"offset": offset,
			"total":  total,
		},
	})
}

// @Summary      Get storage migration status
// @Description  Returns the current progress and status of a specific migration job. Requires admin scope.
// @Tags         Storage Migration
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Migration ID (UUID)"
// @Success      200  {object}  models.StorageMigration
// @Failure      400  {object}  map[string]interface{}  "Invalid migration ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Migration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/storage/migrations/{id} [get]
// GetMigrationStatus returns the status and progress counters for one migration.
// coverage:skip:requires-infrastructure
func (h *StorageMigrationHandler) GetMigrationStatus(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid migration ID"})
		return
	}

	migration, err := h.service.GetStatus(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get migration status"})
		return
	}

	if migration == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "migration not found"})
		return
	}

	c.JSON(http.StatusOK, migration)
}

// @Summary      Cancel storage migration
// @Description  Cancels a running or pending migration. Artifacts already migrated are not rolled back. Requires admin scope.
// @Tags         Storage Migration
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Migration ID (UUID)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid ID or migration not cancellable"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Migration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/storage/migrations/{id}/cancel [post]
// CancelMigration stops a running migration.
// coverage:skip:requires-infrastructure
func (h *StorageMigrationHandler) CancelMigration(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid migration ID"})
		return
	}

	if err := h.service.CancelMigration(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "migration cancelled"})
}

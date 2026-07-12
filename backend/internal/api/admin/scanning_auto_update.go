// scanning_auto_update.go implements the admin endpoint for viewing and
// updating the scheduled scanner auto-update settings (enabled, check
// interval, approval gating, auto-approve rules). Reads/writes the same
// system_settings.scanning_config JSON column as the setup wizard and the
// activation reconciler (config.ScanningConfigDB), preserving the other
// scanning-config fields on write. Applies the new settings at runtime by
// restarting ScannerUpdateJob.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// scanningAutoUpdateInput is the PUT /api/v1/admin/scanning/auto-update request body.
type scanningAutoUpdateInput struct {
	Enabled          bool   `json:"enabled"`
	IntervalHours    int    `json:"interval_hours"`
	RequiresApproval bool   `json:"requires_approval"`
	AutoApproveRules string `json:"auto_approve_rules"`
}

// ScanningAutoUpdateHandler handles the admin scanner auto-update settings endpoint.
type ScanningAutoUpdateHandler struct {
	cfg       *config.ScanningConfig
	repo      *repositories.OIDCConfigRepository
	updateJob *jobs.ScannerUpdateJob
}

// NewScanningAutoUpdateHandler constructs a ScanningAutoUpdateHandler. cfg must be
// a pointer to the live config.Scanning struct so updates take effect in-place for
// the running ScannerUpdateJob.
func NewScanningAutoUpdateHandler(
	cfg *config.ScanningConfig,
	repo *repositories.OIDCConfigRepository,
	updateJob *jobs.ScannerUpdateJob,
) *ScanningAutoUpdateHandler {
	return &ScanningAutoUpdateHandler{
		cfg:       cfg,
		repo:      repo,
		updateJob: updateJob,
	}
}

// @Summary      Update scanner auto-update settings
// @Description  Updates the scheduled scanner version-check job's settings (enabled, check interval, approval gating, auto-approve rules), persists them, and restarts the job so the new settings apply immediately. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body      scanningAutoUpdateInput  true  "Auto-update settings"
// @Success      200  {object}  ScanningAutoUpdateResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/scanning/auto-update [put]
func (h *ScanningAutoUpdateHandler) Put(c *gin.Context) {
	var input scanningAutoUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.IntervalHours <= 0 {
		input.IntervalHours = 24
	}
	if input.IntervalHours < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "interval_hours must be at least 1"})
		return
	}

	if _, err := mirror.ParseAutoApproveRules(&input.AutoApproveRules); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid auto_approve_rules: %v", err)})
		return
	}

	ctx := c.Request.Context()

	// Read-modify-write: preserve the other persisted scanning-config fields.
	// If no row exists yet, db is left zero-valued and re-seeded from the live
	// config below, so we never blank the row.
	var db config.ScanningConfigDB
	if existing, err := h.repo.GetScanningConfig(ctx); err == nil && existing != nil {
		_ = json.Unmarshal(existing, &db)
	}

	db.AutoUpdate = config.ScannerAutoUpdateDB{
		Enabled:          input.Enabled,
		IntervalHours:    input.IntervalHours,
		RequiresApproval: input.RequiresApproval,
		AutoApproveRules: input.AutoApproveRules,
	}
	db.Enabled = h.cfg.Enabled
	db.Tool = h.cfg.Tool
	db.BinaryPath = h.cfg.BinaryPath
	db.ExpectedVersion = h.cfg.ExpectedVersion
	db.SeverityThreshold = h.cfg.SeverityThreshold
	db.TimeoutSecs = int(h.cfg.Timeout.Seconds())
	db.WorkerCount = h.cfg.WorkerCount
	db.ScanIntervalMins = h.cfg.ScanIntervalMins
	db.InstallDir = h.cfg.InstallDir

	jsonBytes, err := json.Marshal(db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal scanning configuration"})
		return
	}
	if err := h.repo.SetScanningConfig(ctx, jsonBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save scanning configuration"})
		return
	}

	// Update the in-memory config in place (never reassign h.cfg) so other
	// holders of the same pointer observe the change immediately.
	h.cfg.AutoUpdate.Enabled = input.Enabled
	h.cfg.AutoUpdate.IntervalHours = input.IntervalHours
	h.cfg.AutoUpdate.RequiresApproval = input.RequiresApproval
	h.cfg.AutoUpdate.AutoApproveRules = input.AutoApproveRules

	// Restart the job so the new enabled/interval settings apply (the job only
	// reads AutoUpdate at Start()). Stop/Start satisfy jobs.Job and return an
	// error for interface uniformity; ScannerUpdateJob never returns a real
	// one here (its disabled/already-running paths return nil), so both are
	// discarded (issue #565 finding [40]).
	if h.updateJob != nil {
		_ = h.updateJob.Stop()
		go func() { _ = h.updateJob.Start(context.Background()) }()
	}

	c.JSON(http.StatusOK, ScanningAutoUpdateResponse{
		Enabled:          h.cfg.AutoUpdate.Enabled,
		IntervalHours:    h.cfg.AutoUpdate.IntervalHours,
		RequiresApproval: h.cfg.AutoUpdate.RequiresApproval,
		AutoApproveRules: h.cfg.AutoUpdate.AutoApproveRules,
	})
}

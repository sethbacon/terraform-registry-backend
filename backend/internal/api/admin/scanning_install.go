package admin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// InstallScannerAdminInput is the request body for POST /api/v1/admin/scanning/install.
type InstallScannerAdminInput struct {
	Tool     string `json:"tool" binding:"required"`
	Version  string `json:"version"`
	Activate bool   `json:"activate"`
} // @name InstallScannerInput

// InstallScannerAdminResponse is returned by POST /api/v1/admin/scanning/install.
type InstallScannerAdminResponse struct {
	Success    bool   `json:"success"`
	Tool       string `json:"tool,omitempty"`
	Version    string `json:"version,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Sha256     string `json:"sha256,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	Activated  bool   `json:"activated,omitempty"`
	Error      string `json:"error,omitempty"`
} // @name InstallScannerResponse

// ScanningInstallHandler holds dependencies for POST /api/v1/admin/scanning/install,
// including the activation reconciler used when the request asks to activate the
// installed version immediately.
type ScanningInstallHandler struct {
	cfg          *config.ScanningConfig
	install      installer.InstallFunc
	updateJob    *jobs.ScannerUpdateJob
	sbvRepo      *repositories.ScannerBinaryVersionRepository
	approvalRepo *repositories.VersionApprovalRepository
}

// NewScanningInstallHandler constructs a ScanningInstallHandler.
func NewScanningInstallHandler(
	cfg *config.ScanningConfig,
	install installer.InstallFunc,
	updateJob *jobs.ScannerUpdateJob,
	sbvRepo *repositories.ScannerBinaryVersionRepository,
	approvalRepo *repositories.VersionApprovalRepository,
) *ScanningInstallHandler {
	return &ScanningInstallHandler{
		cfg:          cfg,
		install:      install,
		updateJob:    updateJob,
		sbvRepo:      sbvRepo,
		approvalRepo: approvalRepo,
	}
}

// @Summary      Install or upgrade a scanner binary
// @Description  Admin-only post-setup action that downloads, verifies, and installs a supported scanner binary. When activate=true, the installed version is also recorded as approved and activated (scanning configuration updated, scanner job restarted) immediately. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body      InstallScannerAdminInput  true  "Scanner to install"
// @Success      200  {object}  InstallScannerAdminResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Install directory not configured"
// @Router       /api/v1/admin/scanning/install [post]
func (h *ScanningInstallHandler) Install() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input InstallScannerAdminInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
		defer cancel()

		ok, result, errMsg := installer.Handle(ctx, h.cfg.InstallDir, h.install, input.Tool, input.Version)
		if !ok {
			if errMsg == "scanning.install_dir is not configured on the server" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
				return
			}
			slog.Warn("admin: scanner install failed", "tool", input.Tool, "version", input.Version, "error", errMsg)
			c.JSON(http.StatusOK, InstallScannerAdminResponse{
				Success: false,
				Tool:    input.Tool,
				Error:   errMsg,
			})
			return
		}

		slog.Info("admin: scanner installed", "tool", input.Tool, "version", result.Version, "path", result.BinaryPath)
		resp := InstallScannerAdminResponse{
			Success:    true,
			Tool:       input.Tool,
			Version:    result.Version,
			BinaryPath: result.BinaryPath,
			Sha256:     result.Sha256,
			SourceURL:  result.SourceURL,
		}

		if input.Activate {
			approvedStatus := models.VersionApprovalStatusApproved
			v := &models.ScannerBinaryVersion{
				ID:                uuid.New(),
				Tool:              input.Tool,
				Version:           result.Version,
				SourceURL:         &result.SourceURL,
				Sha256:            &result.Sha256,
				SignatureVerified: result.SignatureVerified,
				SignatureType:     result.SignatureType,
				SyncStatus:        "downloaded",
				BinaryPath:        &result.BinaryPath,
				ApprovalStatus:    &approvedStatus,
			}
			if err := h.sbvRepo.Upsert(ctx, v); err != nil {
				slog.Error("admin: failed to record installed scanner version", "tool", input.Tool, "version", result.Version, "error", err)
			} else if h.approvalRepo != nil {
				if err := h.approvalRepo.RecordEvent(ctx, &models.VersionApprovalEvent{
					ScannerBinaryVersionID: &v.ID,
					Action:                 models.VersionApprovalActionApproved,
					PerformedBy:            currentUserID(c),
				}); err != nil {
					slog.Error("admin: failed to record approval event for installed scanner version", "tool", input.Tool, "version", result.Version, "error", err)
				}
			}

			if h.updateJob != nil {
				if err := h.updateJob.Activate(ctx, v); err != nil {
					slog.Error("admin: failed to activate installed scanner version", "tool", input.Tool, "version", result.Version, "error", err)
				} else {
					resp.Activated = true
				}
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}

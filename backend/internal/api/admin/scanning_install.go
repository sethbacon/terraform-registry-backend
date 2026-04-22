package admin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// InstallScannerAdminInput is the request body for POST /api/v1/admin/scanning/install.
type InstallScannerAdminInput struct {
	Tool    string `json:"tool" binding:"required"`
	Version string `json:"version"`
}

// InstallScannerAdminResponse is returned by POST /api/v1/admin/scanning/install.
type InstallScannerAdminResponse struct {
	Success    bool   `json:"success"`
	Tool       string `json:"tool,omitempty"`
	Version    string `json:"version,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Sha256     string `json:"sha256,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	Error      string `json:"error,omitempty"`
}

// @Summary      Install or upgrade a scanner binary
// @Description  Admin-only post-setup action that downloads, verifies, and installs a supported scanner binary. Returns the installed binary path — updating the scanning configuration to use it is a separate admin action. Requires admin scope.
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
func InstallScannerHandler(cfg *config.ScanningConfig, install installer.InstallFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input InstallScannerAdminInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
		defer cancel()

		ok, result, errMsg := installer.Handle(ctx, cfg.InstallDir, install, input.Tool, input.Version)
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
		c.JSON(http.StatusOK, InstallScannerAdminResponse{
			Success:    true,
			Tool:       input.Tool,
			Version:    result.Version,
			BinaryPath: result.BinaryPath,
			Sha256:     result.Sha256,
			SourceURL:  result.SourceURL,
		})
	}
}

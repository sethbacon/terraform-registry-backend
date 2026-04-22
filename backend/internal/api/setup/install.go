package setup

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// InstallScannerInput is the request body for POST /api/v1/setup/scanning/install.
type InstallScannerInput struct {
	Tool    string `json:"tool" binding:"required"`
	Version string `json:"version"` // empty = latest
}

// @Summary      Install a scanner binary
// @Description  Downloads the official release of a supported scanner for this server's OS/architecture, verifies its SHA256 against the published checksum file, and installs it to the server's scanner directory. Returns the installed binary path for use in the scanning configuration. Supported tools: trivy, terrascan, checkov. Not supported: snyk (proprietary, no public checksums), custom (no catalog entry).
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body      InstallScannerInput  true  "Scanner to install"
// @Success      200  {object}  InstallScannerResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Install directory not configured"
// @Router       /api/v1/setup/scanning/install [post]
func (h *Handlers) InstallScanner(c *gin.Context) {
	var input InstallScannerInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	install := h.installFunc
	if install == nil {
		install = installer.Install
	}

	ok, result, errMsg := installer.Handle(ctx, h.cfg.Scanning.InstallDir, install, input.Tool, input.Version)
	if !ok {
		if errMsg == "scanning.install_dir is not configured on the server" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
			return
		}
		slog.Warn("setup: scanner install failed", "tool", input.Tool, "version", input.Version, "error", errMsg)
		c.JSON(http.StatusOK, InstallScannerResponse{
			Success: false,
			Tool:    input.Tool,
			Error:   errMsg,
		})
		return
	}

	slog.Info("setup: scanner installed", "tool", input.Tool, "version", result.Version, "path", result.BinaryPath)
	c.JSON(http.StatusOK, InstallScannerResponse{
		Success:    true,
		Tool:       input.Tool,
		Version:    result.Version,
		BinaryPath: result.BinaryPath,
		Sha256:     result.Sha256,
		SourceURL:  result.SourceURL,
	})
}

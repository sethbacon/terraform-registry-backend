// scanning_latest.go implements the admin endpoint that checks the latest upstream
// scanner release without downloading or installing anything.
package admin

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	goversion "github.com/hashicorp/go-version"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scanner"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

// ScannerLatestResponse is returned by GET /api/v1/admin/scanning/latest.
type ScannerLatestResponse struct {
	Tool               string `json:"tool"`
	CurrentVersion     string `json:"current_version,omitempty"`
	LatestVersion      string `json:"latest_version"`
	UpdateAvailable    bool   `json:"update_available"`
	SignatureSupported bool   `json:"signature_supported"`
} // @name ScannerLatestResponse

// @Summary      Check the latest available scanner version
// @Description  Queries the upstream GitHub release for the latest version of the given (or configured) scanner tool and compares it to the currently installed/configured version. Does not download or install anything. Requires scanning:read scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Param        tool  query  string  false  "Scanner tool to check (defaults to the configured tool)"
// @Success      200  {object}  ScannerLatestResponse
// @Failure      400  {object}  map[string]interface{}  "Unsupported tool"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Failed to resolve upstream release"
// @Router       /api/v1/admin/scanning/latest [get]
func GetScannerLatestHandler(cfg *config.ScanningConfig, egressGuard *httpsafe.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
		tool := c.Query("tool")
		if tool == "" {
			tool = cfg.Tool
		}

		if !installer.Supports(tool) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported tool", "supported": installer.SupportedTools()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		latest, err := installer.CheckLatest(ctx, installer.InstallConfig{InstallDir: cfg.InstallDir, EgressGuard: egressGuard}, tool)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		currentVersion := cfg.ExpectedVersion
		if cfg.Enabled {
			if _, ok := scanner.ResolveBinaryPath(cfg); ok {
				if s, err := scanner.New(cfg); err == nil {
					if v, err := s.Version(ctx); err == nil {
						currentVersion = v
					}
				}
			}
		}

		resp := ScannerLatestResponse{
			Tool:               tool,
			CurrentVersion:     currentVersion,
			LatestVersion:      latest.LatestVersion,
			SignatureSupported: latest.SignatureSupported,
		}

		if currentVersion == "" {
			resp.UpdateAvailable = true
		} else {
			cur, curErr := goversion.NewVersion(strings.TrimPrefix(currentVersion, "v"))
			lat, latErr := goversion.NewVersion(strings.TrimPrefix(latest.LatestVersion, "v"))
			if curErr == nil && latErr == nil {
				resp.UpdateAvailable = lat.GreaterThan(cur)
			} else {
				resp.UpdateAvailable = currentVersion != latest.LatestVersion
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}

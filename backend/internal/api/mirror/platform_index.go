// platform_index.go implements the platform-specific provider version index endpoint for the Terraform Network Mirror Protocol.
package mirror

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// @Summary      Network mirror provider platform index
// @Description  Returns download URLs and hashes for all platforms of a specific provider version, per the Terraform Network Mirror Protocol.
// @Tags         Mirror Protocol
// @Produce      json
// @Param        hostname     path  string  true  "Origin registry hostname (e.g. registry.terraform.io)"
// @Param        namespace    path  string  true  "Provider namespace"
// @Param        type         path  string  true  "Provider type (e.g. aws, azurerm)"
// @Param        versionfile  path  string  true  "Version with .json suffix (e.g. 1.2.3.json)"
// @Success      200  {object}  mirror.MirrorPlatformIndexResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid version format"
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/providers/{hostname}/{namespace}/{type}/{versionfile} [get]
// PlatformIndexHandler handles network mirror platform index requests
// Implements: GET /terraform/providers/:hostname/:namespace/:type/:version.json
// Returns download URLs and hashes for all platforms of a specific version
func PlatformIndexHandler(db *sql.DB, cfg *config.Config, auditRepo *repositories.AuditRepository) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	// storageBackend is initialized exactly once on the first request that reaches
	// the download-URL generation step.  Using sync.Once avoids both re-initialising
	// the backend on every request and failing handler setup when the storage config
	// has not been applied yet (e.g. during the setup wizard).
	var (
		storageOnce    sync.Once
		storageBackend storage.Storage
		storageErr     error
	)

	return func(c *gin.Context) {
		// Note: hostname is in the path for compatibility with Network Mirror Protocol
		hostname := c.Param("hostname")
		namespace := c.Param("namespace")
		providerType := c.Param("type")

		// Extract version from versionfile parameter (format: version.json)
		versionfile := c.Param("versionfile")

		// Strip .json suffix if present
		version := versionfile
		if len(version) > 5 && version[len(version)-5:] == ".json" {
			version = version[:len(version)-5]
		}

		// Log hostname for debugging (not used in single-tenant mode)
		_ = hostname

		// Validate semantic versioning
		if err := validation.ValidateSemver(version); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid version format - must be valid semantic versioning"},
			})
			return
		}

		// Get organization context (default org for single-tenant mode)
		org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get organization context",
			})
			return
		}
		if org == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Default organization not found - please run migrations",
			})
			return
		}

		// Get provider
		provider, err := providerRepo.GetProvider(c.Request.Context(), org.ID, namespace, providerType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider",
			})
			return
		}

		if provider == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []string{"Provider not found"},
			})
			return
		}

		// Get provider version
		providerVersion, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider version",
			})
			return
		}

		if providerVersion == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []string{"Provider version not found"},
			})
			return
		}

		// Get all platforms for this version
		platforms, err := providerRepo.ListPlatforms(c.Request.Context(), providerVersion.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list provider platforms",
			})
			return
		}

		// storageBackend is initialized once at handler setup time (not per-request)
		storageOnce.Do(func() {
			storageBackend, storageErr = storage.NewStorage(cfg)
		})
		if storageErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to initialize storage backend",
			})
			return
		}

		// Format response per Network Mirror Protocol spec
		// https://www.terraform.io/docs/internals/provider-network-mirror-protocol.html
		//
		// Response format:
		// {
		//   "archives": {
		//     "darwin_amd64": {
		//       "url": "providers/...",
		//       "hashes": ["h1:abcd...", "zh:abcd..."]
		//     },
		//     "linux_amd64": {
		//       "url": "providers/...",
		//       "hashes": ["h1:abcd...", "zh:abcd..."]
		//     }
		//   }
		// }
		archives := make(map[string]gin.H)

		for _, platform := range platforms {
			// Generate platform key (os_arch)
			platformKey := fmt.Sprintf("%s_%s", platform.OS, platform.Arch)

			// Get download URL from storage
			// For Network Mirror, we use a longer TTL (1 hour)
			downloadURL, err := storageBackend.GetURL(c.Request.Context(), platform.StoragePath, 1*time.Hour)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to generate download URL for %s", platformKey),
				})
				return
			}

			// Build the hashes list for this platform.
			// h1: (dirhash of zip contents) is the preferred scheme; include it first when
			// available so that Terraform can populate its lock file with the better hash.
			// zh: (hex SHA256 of the zip archive) is the legacy fallback and is always present.
			var hashes []string
			if platform.H1Hash != nil && *platform.H1Hash != "" {
				hashes = append(hashes, *platform.H1Hash)
			}
			hashes = append(hashes, formatZhHash(platform.Shasum))

			// Add to archives
			archives[platformKey] = gin.H{
				"url":    downloadURL,
				"hashes": hashes,
			}
		}

		response := gin.H{
			"archives": archives,
		}

		// Audit log the mirror platform index request asynchronously
		if auditRepo != nil {
			resourceType := "provider"
			action := "GET " + c.Request.URL.Path
			ip := c.ClientIP()
			versionIDForAudit := providerVersion.ID
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := auditRepo.CreateAuditLog(ctx, &models.AuditLog{
					Action:       action,
					ResourceType: &resourceType,
					ResourceID:   &versionIDForAudit,
					IPAddress:    &ip,
				}); err != nil {
					slog.Error("failed to write audit log for mirror platform index", "error", err, "action", action)
				}
			}()
		}

		// Use c.Data with plain "application/json" (no charset) to satisfy the
		// Terraform Network Mirror Protocol spec, which rejects unknown content-type
		// parameters. Gin's c.JSON would append "; charset=utf-8" and trigger a
		// [WARN] from terraform init.
		data, err := json.Marshal(response)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize response"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
	}
}

// formatZhHash converts a hex SHA256 checksum to the "zh:" format used by Terraform's
// Network Mirror Protocol. zh: is the lowercase hex SHA256 of the zip archive bytes,
// as defined by Terraform's PackageHashLegacyZipSHA scheme.
func formatZhHash(hexChecksum string) string {
	if hexChecksum == "" {
		return ""
	}
	return "zh:" + hexChecksum
}

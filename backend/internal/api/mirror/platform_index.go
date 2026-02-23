// platform_index.go implements the platform-specific provider version index endpoint for the Terraform Network Mirror Protocol.
package mirror

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
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
// @Success      200  {object}  map[string]interface{}  "archives: {\"linux_amd64\": {url, hashes}}"
// @Failure      400  {object}  map[string]interface{}  "Invalid version format"
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/providers/{hostname}/{namespace}/{type}/{versionfile} [get]
// PlatformIndexHandler handles network mirror platform index requests
// Implements: GET /terraform/providers/:hostname/:namespace/:type/:version.json
// Returns download URLs and hashes for all platforms of a specific version
func PlatformIndexHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
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

			// Format hashes according to Network Mirror Protocol
			// Network Mirror expects:
			// - "h1:" prefix = SHA256 hash in base64
			// - "zh:" prefix = ZIP hash (also SHA256, but may include file headers)
			//
			// For now, we'll provide the h1 hash from our SHA256 checksum
			hashes := []string{
				formatH1Hash(platform.Shasum),
			}

			// Add to archives
			archives[platformKey] = gin.H{
				"url":    downloadURL,
				"hashes": hashes,
			}
		}

		response := gin.H{
			"archives": archives,
		}

		c.JSON(http.StatusOK, response)
	}
}

// formatH1Hash converts a hex SHA256 checksum to the "h1:" format used by Terraform.
// "h1:" format is the SHA256 hash encoded as base64.
func formatH1Hash(hexChecksum string) string {
	hashBytes, err := hex.DecodeString(hexChecksum)
	if err != nil {
		return ""
	}
	return "h1:" + base64.StdEncoding.EncodeToString(hashBytes)
}

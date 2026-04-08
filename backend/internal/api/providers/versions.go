// versions.go implements the provider version listing endpoint for the Terraform Provider Registry Protocol.
package providers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      List provider versions
// @Description  List all available versions and platforms for a specific provider. Implements the Terraform Provider Registry Protocol.
// @Tags         Providers
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Param        limit      query int     false "Maximum results (default 100, max 1000)"
// @Param        offset     query int     false "Offset for pagination (default 0)"
// @Success      200  {object}  providers.ProviderVersionsResponse
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /v1/providers/{namespace}/{type}/versions [get]
// ListVersionsHandler handles listing all versions of a provider
// Implements: GET /v1/providers/:namespace/:type/versions
func ListVersionsHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		providerType := c.Param("type")

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

		// Get all versions for the provider with pagination
		versions, total, err := providerRepo.ListVersionsPaginated(c.Request.Context(), provider.ID, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list provider versions",
			})
			return
		}

		// Format response per Terraform Provider Registry Protocol spec
		// https://www.terraform.io/docs/internals/provider-registry-protocol.html
		versionsList := make([]gin.H, 0, len(versions))
		for _, v := range versions {
			// Get platforms for this version
			platforms, err := providerRepo.ListPlatforms(c.Request.Context(), v.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to list provider platforms",
				})
				return
			}

			// Format platforms and sum downloads
			platformsList := make([]gin.H, 0, len(platforms))
			var versionDownloadCount int64
			for _, p := range platforms {
				versionDownloadCount += p.DownloadCount
				platformsList = append(platformsList, gin.H{
					"id":             p.ID,
					"os":             p.OS,
					"arch":           p.Arch,
					"filename":       p.Filename,
					"shasum":         p.Shasum,
					"download_count": p.DownloadCount,
				})
			}

			versionData := gin.H{
				"id":             v.ID,
				"version":        v.Version,
				"protocols":      v.Protocols,
				"platforms":      platformsList,
				"published_at":   v.CreatedAt.Format(time.RFC3339),
				"deprecated":     v.Deprecated,
				"download_count": versionDownloadCount,
			}
			if v.DeprecatedAt != nil {
				versionData["deprecated_at"] = v.DeprecatedAt.Format(time.RFC3339)
			}
			if v.DeprecationMessage != nil {
				versionData["deprecation_message"] = *v.DeprecationMessage
			}
			// Include published_by info for audit tracking
			if v.PublishedBy != nil {
				versionData["published_by"] = *v.PublishedBy
			}
			if v.PublishedByName != nil {
				versionData["published_by_name"] = *v.PublishedByName
			}
			versionsList = append(versionsList, versionData)
		}

		response := gin.H{
			"versions": versionsList,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		}

		c.JSON(http.StatusOK, response)
	}
}

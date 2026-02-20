// search.go implements the provider search and discovery endpoint for the Provider Registry Protocol.
package providers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Search providers
// @Description  Search for providers by name or namespace with pagination.
// @Tags         Providers
// @Produce      json
// @Param        q          query  string  false  "Search query"
// @Param        namespace  query  string  false  "Filter by namespace"
// @Param        limit      query  int     false  "Maximum results to return (default 20, max 100)"
// @Param        offset     query  int     false  "Offset for pagination (default 0)"
// @Success      200  {object}  map[string]interface{}  "providers: [], meta: {limit, offset, total}"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/search [get]
// SearchHandler handles provider search requests
// Implements: GET /api/v1/providers/search?q=<query>&namespace=<namespace>&limit=<limit>&offset=<offset>
func SearchHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Get query parameters
		query := c.Query("q")
		namespace := c.Query("namespace")

		// Pagination parameters
		limitStr := c.DefaultQuery("limit", "20")
		offsetStr := c.DefaultQuery("offset", "0")

		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			limit = 20 // Default to 20, max 100
		}

		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			offset = 0
		}

		// Get organization context
		var orgID string
		if cfg.MultiTenancy.Enabled {
			org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get organization context",
				})
				return
			}
			if org == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Default organization not found",
				})
				return
			}
			orgID = org.ID
		}
		// In single-tenant mode, orgID will be empty string which the repository will handle

		// Search providers
		providers, total, err := providerRepo.SearchProviders(
			c.Request.Context(),
			orgID,
			query,
			namespace,
			limit,
			offset,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search providers",
			})
			return
		}

		// Format results
		results := make([]gin.H, len(providers))
		for i, p := range providers {
			// Get latest version for each provider
			versions, _ := providerRepo.ListVersions(c.Request.Context(), p.ID)
			var latestVersion string
			if len(versions) > 0 {
				latestVersion = versions[0].Version
			}

			// Get total downloads across all platforms for this provider
			totalDownloads, _ := providerRepo.GetTotalDownloadCount(c.Request.Context(), p.ID)

			results[i] = gin.H{
				"id":              p.ID,
				"namespace":       p.Namespace,
				"type":            p.Type,
				"description":     p.Description,
				"source":          p.Source,
				"latest_version":  latestVersion,
				"download_count":  totalDownloads,
				"created_by":      p.CreatedBy,
				"created_by_name": p.CreatedByName,
				"created_at":      p.CreatedAt,
				"updated_at":      p.UpdatedAt,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"providers": results,
			"meta": gin.H{
				"limit":  limit,
				"offset": offset,
				"total":  total,
			},
		})
	}
}

// search.go implements the module search and discovery endpoint for the Module Registry Protocol.
package modules

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Search modules
// @Description  Search for modules by name, namespace, or provider system with pagination.
// @Tags         Modules
// @Produce      json
// @Param        q          query  string  false  "Search query"
// @Param        namespace  query  string  false  "Filter by namespace"
// @Param        system     query  string  false  "Filter by target system"
// @Param        limit      query  int     false  "Maximum results to return (default 20, max 100)"
// @Param        offset     query  int     false  "Offset for pagination (default 0)"
// @Success      200  {object}  map[string]interface{}  "modules: [], meta: {limit, offset, total}"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/search [get]
// SearchHandler handles module search requests
// Implements: GET /api/v1/modules/search?q=<query>&namespace=<namespace>&system=<system>&limit=<limit>&offset=<offset>
func SearchHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Get query parameters
		query := c.Query("q")
		namespace := c.Query("namespace")
		system := c.Query("system")

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

		// Search modules
		modules, total, err := moduleRepo.SearchModules(
			c.Request.Context(),
			orgID,
			query,
			namespace,
			system,
			limit,
			offset,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search modules",
			})
			return
		}

		// Format results
		results := make([]gin.H, len(modules))
		for i, m := range modules {
			// Get latest version for each module
			versions, _ := moduleRepo.ListVersions(c.Request.Context(), m.ID)
			var latestVersion string
			var totalDownloads int64
			if len(versions) > 0 {
				latestVersion = versions[0].Version
				// Sum up downloads across all versions
				for _, v := range versions {
					totalDownloads += v.DownloadCount
				}
			}

			results[i] = gin.H{
				"id":              m.ID,
				"namespace":       m.Namespace,
				"name":            m.Name,
				"system":          m.System,
				"description":     m.Description,
				"source":          m.Source,
				"latest_version":  latestVersion,
				"download_count":  totalDownloads,
				"created_by":      m.CreatedBy,
				"created_by_name": m.CreatedByName,
				"created_at":      m.CreatedAt,
				"updated_at":      m.UpdatedAt,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"modules": results,
			"meta": gin.H{
				"limit":  limit,
				"offset": offset,
				"total":  total,
			},
		})
	}
}

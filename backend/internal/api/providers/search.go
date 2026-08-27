// search.go implements the provider search and discovery endpoint for the Provider Registry Protocol.
package providers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
)

// validProviderSortFields defines the allowed values for the sort query parameter.
var validProviderSortFields = map[string]bool{
	"":          true,
	"relevance": true,
	"name":      true,
	"downloads": true,
	"created":   true,
	"updated":   true,
}

// @Summary      Search providers
// @Description  Search for providers by name or namespace with pagination and sorting.
// @Tags         Providers
// @Produce      json
// @Param        q          query  string  false  "Search query"
// @Param        namespace  query  string  false  "Filter by namespace"
// @Param        sort       query  string  false  "Sort field: relevance, name, downloads, created, updated"
// @Param        order      query  string  false  "Sort order: asc or desc (default desc)"
// @Param        limit      query  int     false  "Maximum results to return (default 20, max 100). A larger value is served as 100."
// @Param        offset     query  int     false  "Offset for pagination (default 0)"
// @Success      200  {object}  providers.ProviderSearchResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid sort parameter"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/search [get]
// SearchHandler handles provider search requests
// Implements: GET /api/v1/providers/search?q=<query>&namespace=<namespace>&sort=<sort>&order=<order>&limit=<limit>&offset=<offset>
func SearchHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)

	return func(c *gin.Context) {
		// Get query parameters
		query := c.Query("q")
		namespace := c.Query("namespace")

		// Sort parameters
		sortField := c.DefaultQuery("sort", "")
		sortOrder := c.DefaultQuery("order", "")

		if !validProviderSortFields[sortField] {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid sort parameter. Allowed values: relevance, name, downloads, created, updated",
			})
			return
		}

		// GUARD per-page-clamps-to-max (issue #893). The module search axis's
		// clamp, verbatim: an over-large limit fell back to the DEFAULT of 20
		// instead of the documented maximum of 100. ClampPerPage absorbs the
		// unparseable case too: Atoi returns 0 on failure, and 0 takes the
		// default.
		limit, _ := strconv.Atoi(c.Query("limit"))
		limit = pagination.ClampPerPage(limit, 20, 100)

		offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
		if err != nil || offset < 0 {
			offset = 0
		}

		// NO ORGANIZATION PREDICATE (#976). Search is public by decision -- see
		// declaredPublicRoutes in internal/api/public_surface_class_test.go and
		// the note above these routes in router_routes.go.
		//
		// This used to be conditional on multi_tenancy.enabled, a flag whose
		// BOTH positions were wrong. False (the shipped default) applied no
		// predicate, which is this behaviour. True resolved the organization
		// literally named "default" -- never the caller's -- so every real
		// tenant saw an EMPTY registry while the default organization's
		// inventory stayed visible to everyone. It looked like the
		// multi-tenancy switch and was the first thing anyone moving toward
		// isolation would reach for; turning it on was an outage plus a
		// continuing leak. Removed rather than repaired: isolation is carried
		// by the host, not by a search filter.
		var orgID string
		// In single-tenant mode, orgID will be empty string which the repository will handle

		// Search providers with aggregated version stats in a single query
		providers, total, err := providerRepo.SearchProvidersWithStats(
			c.Request.Context(),
			orgID,
			query,
			namespace,
			limit,
			offset,
			sortField,
			sortOrder,
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
			var latestVersion string
			if p.LatestVersion != nil {
				latestVersion = *p.LatestVersion
			}

			results[i] = gin.H{
				"id":              p.ID,
				"namespace":       p.Namespace,
				"type":            p.Type,
				"description":     p.Description,
				"source":          p.Source,
				"latest_version":  latestVersion,
				"download_count":  p.TotalDownloads,
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

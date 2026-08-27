// search.go implements the module search and discovery endpoint for the Module Registry Protocol.
package modules

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
)

// validModuleSortFields defines the allowed values for the sort query parameter.
var validModuleSortFields = map[string]bool{
	"":          true,
	"relevance": true,
	"name":      true,
	"downloads": true,
	"created":   true,
	"updated":   true,
}

// @Summary      Search modules
// @Description  Search for modules by name, namespace, or provider system with pagination and sorting.
// @Tags         Modules
// @Produce      json
// @Param        q          query  string  false  "Search query"
// @Param        namespace  query  string  false  "Filter by namespace"
// @Param        system     query  string  false  "Filter by target system"
// @Param        sort       query  string  false  "Sort field: relevance, name, downloads, created, updated"
// @Param        order      query  string  false  "Sort order: asc or desc (default desc)"
// @Param        limit      query  int     false  "Maximum results to return (default 20, max 100). A larger value is served as 100."
// @Param        offset     query  int     false  "Offset for pagination (default 0)"
// @Success      200  {object}  modules.ModuleSearchResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid sort parameter"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/search [get]
// SearchHandler handles module search requests
// Implements: GET /api/v1/modules/search?q=<query>&namespace=<namespace>&system=<system>&sort=<sort>&order=<order>&limit=<limit>&offset=<offset>
func SearchHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)

	return func(c *gin.Context) {
		// Get query parameters
		query := c.Query("q")
		namespace := c.Query("namespace")
		system := c.Query("system")

		// Sort parameters
		sortField := c.DefaultQuery("sort", "")
		sortOrder := c.DefaultQuery("order", "")

		if !validModuleSortFields[sortField] {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid sort parameter. Allowed values: relevance, name, downloads, created, updated",
			})
			return
		}

		// GUARD per-page-clamps-to-max (issue #893). This clamp reset an
		// over-large limit to the DEFAULT of 20 rather than to the documented
		// maximum of 100, so `?limit=500` returned fewer modules than
		// `?limit=50`. ClampPerPage absorbs the unparseable case too: Atoi
		// returns 0 on failure, and 0 takes the default.
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

		// Search modules with aggregated version stats in a single query
		modules, total, err := moduleRepo.SearchModulesWithStats(
			c.Request.Context(),
			orgID,
			query,
			namespace,
			system,
			limit,
			offset,
			sortField,
			sortOrder,
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
			var latestVersion string
			if m.LatestVersion != nil {
				latestVersion = *m.LatestVersion
			}

			results[i] = gin.H{
				"id":                  m.ID,
				"namespace":           m.Namespace,
				"name":                m.Name,
				"system":              m.System,
				"description":         m.Description,
				"source":              m.Source,
				"latest_version":      latestVersion,
				"download_count":      m.TotalDownloads,
				"created_by":          m.CreatedBy,
				"created_by_name":     m.CreatedByName,
				"deprecated":          m.Deprecated,
				"deprecated_at":       m.DeprecatedAt,
				"deprecation_message": m.DeprecationMessage,
				"successor_module_id": m.SuccessorModuleID,
				"created_at":          m.CreatedAt,
				"updated_at":          m.UpdatedAt,
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

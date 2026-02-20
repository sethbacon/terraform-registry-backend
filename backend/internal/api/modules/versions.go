// versions.go implements the module version listing endpoint for the Terraform Module Registry Protocol.
package modules

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      List module versions
// @Description  List all available versions for a specific module. Implements the Terraform Module Registry Protocol.
// @Tags         Modules
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Success      200  {object}  map[string]interface{}  "modules: [{source, versions: [{version, ...}]}]"
// @Failure      404  {object}  map[string]interface{}  "Module not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /v1/modules/{namespace}/{name}/{system}/versions [get]
// ListVersionsHandler handles listing all versions of a module
// Implements: GET /v1/modules/:namespace/:name/:system/versions
func ListVersionsHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		name := c.Param("name")
		system := c.Param("system")

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

		// Get module
		module, err := moduleRepo.GetModule(c.Request.Context(), org.ID, namespace, name, system)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query module",
			})
			return
		}

		if module == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []string{"Module not found"},
			})
			return
		}

		// Get all versions for the module
		versions, err := moduleRepo.ListVersions(c.Request.Context(), module.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list module versions",
			})
			return
		}

		// Format response per Terraform Module Registry Protocol spec
		// https://www.terraform.io/docs/internals/module-registry-protocol.html
		versionsList := make([]map[string]interface{}, len(versions))
		for i, v := range versions {
			versionData := map[string]interface{}{
				"id":             v.ID,
				"version":        v.Version,
				"published_at":   v.CreatedAt.Format(time.RFC3339),
				"download_count": v.DownloadCount,
				"deprecated":     v.Deprecated,
			}

			// Include deprecation info if deprecated
			if v.DeprecatedAt != nil {
				versionData["deprecated_at"] = v.DeprecatedAt.Format(time.RFC3339)
			}
			if v.DeprecationMessage != nil {
				versionData["deprecation_message"] = *v.DeprecationMessage
			}

			// Include README if present
			if v.Readme != nil {
				versionData["readme"] = *v.Readme
			}

			// Include published_by info for audit tracking
			if v.PublishedBy != nil {
				versionData["published_by"] = *v.PublishedBy
			}
			if v.PublishedByName != nil {
				versionData["published_by_name"] = *v.PublishedByName
			}

			versionsList[i] = versionData
		}

		response := gin.H{
			"modules": []gin.H{
				{
					"source":   module.Source,
					"versions": versionsList,
				},
			},
		}

		c.JSON(http.StatusOK, response)
	}
}

// docs.go implements the module documentation endpoint for the modules package.
package modules

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Get module documentation
// @Description  Returns terraform-docs metadata (inputs, outputs, providers, requirements) extracted from the module archive at upload time.
// @Tags         Modules
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Module version"
// @Success      200  {object}  analyzer.ModuleDoc
// @Failure      404  {object}  map[string]interface{}  "Module, version, or docs not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/{version}/docs [get]
func GetModuleDocsHandler(db *sql.DB) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)
	docsRepo := repositories.NewModuleDocsRepository(db)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		name := c.Param("name")
		system := c.Param("system")
		version := c.Param("version")

		org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil || org == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization context"})
			return
		}

		module, err := moduleRepo.GetModule(c.Request.Context(), org.ID, namespace, name, system)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query module"})
			return
		}
		if module == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "module not found"})
			return
		}

		mv, err := moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query module version"})
			return
		}
		if mv == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "module version not found"})
			return
		}

		doc, err := docsRepo.GetModuleDocs(c.Request.Context(), mv.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query module docs"})
			return
		}
		if doc == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no documentation found for this module version"})
			return
		}

		c.JSON(http.StatusOK, doc)
	}
}

// scans.go implements the admin endpoint for querying module security scan results.
package admin

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Get module version scan result
// @Description  Returns the latest security scan for a module version, including tool name, version, severity counts, and raw output. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Provider system (e.g. aws)"
// @Param        version    path  string  true  "Module version"
// @Success      200  {object}  models.ModuleScan
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Module version or scan not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules/{namespace}/{name}/{system}/versions/{version}/scan [get]
func GetModuleScanHandler(db *sql.DB) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	scanRepo := repositories.NewModuleScanRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

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

		scan, err := scanRepo.GetLatestScan(c.Request.Context(), mv.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query scan result"})
			return
		}
		if scan == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no scan found for this module version"})
			return
		}

		c.JSON(http.StatusOK, scan)
	}
}

// @Summary      Get scan result by ID
// @Description  Returns a security scan record by its unique ID, including severity counts and raw output. Requires scanning:read scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Scan ID (UUID)"
// @Success      200  {object}  models.ModuleScan
// @Failure      400  {object}  map[string]interface{}  "Invalid scan ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Scan not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/scanning/scans/{id} [get]
func GetScanByIDHandler(db *sql.DB) gin.HandlerFunc {
	scanRepo := repositories.NewModuleScanRepository(db)

	return func(c *gin.Context) {
		id := c.Param("id")
		if _, err := uuid.Parse(id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan ID"})
			return
		}

		scan, err := scanRepo.GetScanByID(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query scan result"})
			return
		}
		if scan == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}

		c.JSON(http.StatusOK, scan)
	}
}

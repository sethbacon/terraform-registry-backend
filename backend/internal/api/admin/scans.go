// scans.go implements the admin endpoint for querying module security scan results.
package admin

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/auth"
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

		// GUARD scan-byversion-tenant-scope: the by-id sibling below resolves the
		// caller's tenant scope; this axis resolved the DEFAULT organization
		// regardless of who was asking, so scanning:read held anywhere read the
		// default org's vulnerability findings. Same class as #783, missed
		// because addressing a module by namespace/name/system hides the fact
		// that the lookup needs an organization at all.
		//
		// 404 rather than 403, matching the by-id axis: the body is another
		// tenant's findings, so confirming the module exists is itself the
		// disclosure.
		scope, ok := resolveTenantScope(c, orgRepo, auth.ScopeScanningRead)
		if !ok {
			return
		}

		org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil || org == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get organization context"})
			return
		}
		if !scope.Permits(org.ID) {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
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

		// The module was already resolved within an organization above, so the
		// scan is bound to that same organization -- a scan cannot be returned
		// for a module version the caller did not just look up.
		scan, err := scanRepo.GetLatestScan(c.Request.Context(), mv.ID,
			repositories.OrgScopeOrganizations(module.OrganizationID))
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
func GetScanByIDHandler(db *sql.DB, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	scanRepo := repositories.NewModuleScanRepository(db)

	return func(c *gin.Context) {
		id := c.Param("id")
		if _, err := uuid.Parse(id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan ID"})
			return
		}

		// GUARD scan-byid-tenant-scope (issue #783): the by-id axis of the
		// #718/#719 class. The row is organization-owned transitively, through
		// module_versions -> modules, so nothing about the scan row itself says
		// whose it is -- which is why fetching by primary key looked harmless.
		//
		// Out of scope answers 404, not 403: the response body is another
		// tenant's vulnerability findings, so confirming the id exists is itself
		// the disclosure. Indistinguishable from an id that was never issued.
		scope, ok := resolveTenantScope(c, orgRepo, auth.ScopeScanningRead)
		if !ok {
			return
		}

		scan, err := scanRepo.GetScanByID(c.Request.Context(), id, scope.OrgScope())
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

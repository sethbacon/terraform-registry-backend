// Package modules implements the Terraform Module Registry Protocol v1 HTTP handlers
// (as defined at https://developer.hashicorp.com/terraform/internals/module-registry-protocol).
// These endpoints are intentionally unauthenticated — the protocol requires public discoverability
// so that `terraform init` can resolve module sources without credentials. Write access (upload,
// deprecation) is handled by the admin package which enforces authentication.
package modules

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// @Summary      Download module version
// @Description  Returns a 204 response with an X-Terraform-Get header containing the download URL. Implements the Terraform Module Registry Protocol.
// @Tags         Modules
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Target system (e.g. aws, azurerm)"
// @Param        version    path  string  true  "Semantic version (e.g. 1.2.3)"
// @Success      204  "No Content — X-Terraform-Get header contains the download URL"
// @Failure      400  {object}  map[string]interface{}  "Invalid version format"
// @Failure      404  {object}  map[string]interface{}  "Module or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /v1/modules/{namespace}/{name}/{system}/{version}/download [get]
// DownloadHandler handles module download requests
// Implements: GET /v1/modules/:namespace/:name/:system/:version/download
// Returns 204 No Content with X-Terraform-Get header pointing to download URL
func DownloadHandler(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		name := c.Param("name")
		system := c.Param("system")
		version := c.Param("version")

		// Validate semantic versioning
		if err := validation.ValidateSemver(version); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid version format - must be valid semantic versioning"},
			})
			return
		}

		// Get organization context
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

		// Get specific version
		moduleVersion, err := moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query module version",
			})
			return
		}
		if moduleVersion == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []string{"Module version not found"},
			})
			return
		}

		// Get download URL from storage backend
		// TTL of 15 minutes for signed URLs
		downloadURL, err := storageBackend.GetURL(c.Request.Context(), moduleVersion.StoragePath, 15*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate download URL",
			})
			return
		}

		// Increment download counter asynchronously (don't block the response)
		versionID := moduleVersion.ID
		go func() {
			// Use background context to avoid cancellation when request completes
			if err := moduleRepo.IncrementDownloadCount(context.Background(), versionID); err != nil {
				// Log error but don't fail the request
				// TODO: Add proper logging in Phase 9
			}
		}()

		// Return 204 No Content with X-Terraform-Get header
		// This is the Terraform Module Registry Protocol standard response
		c.Header("X-Terraform-Get", downloadURL)
		c.Status(http.StatusNoContent)
	}
}

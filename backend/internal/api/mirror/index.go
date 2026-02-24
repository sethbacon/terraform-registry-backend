// Package mirror implements the Terraform Network Mirror Protocol v1 HTTP handlers
// (https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol).
// The mirror protocol allows Terraform to use the registry as a local cache of provider binaries,
// enabling air-gapped deployments and reducing upstream registry dependencies.
// These endpoints are unauthenticated by protocol design.
package mirror

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Network mirror provider version index
// @Description  Returns all available versions for a provider in the Terraform Network Mirror Protocol format.
// @Tags         Mirror Protocol
// @Produce      json
// @Param        hostname   path  string  true  "Origin registry hostname (e.g. registry.terraform.io)"
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type (e.g. aws, azurerm)"
// @Success      200  {object}  map[string]interface{}  "versions: {\"1.0.0\": {}, \"2.0.0\": {}}"
// @Failure      404  {object}  map[string]interface{}  "Provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/providers/{hostname}/{namespace}/{type}/index.json [get]
// IndexHandler handles network mirror index requests
// Implements: GET /terraform/providers/:hostname/:namespace/:type/index.json
// Returns a simple JSON object with all available versions
func IndexHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Note: hostname is in the path for compatibility with Network Mirror Protocol
		// It represents the origin registry hostname (e.g., registry.terraform.io)
		// We don't use it for routing, but it's part of the spec
		hostname := c.Param("hostname")
		namespace := c.Param("namespace")
		providerType := c.Param("type")

		// Log hostname for debugging (not used in single-tenant mode)
		_ = hostname

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

		// Get all versions for the provider
		versions, err := providerRepo.ListVersions(c.Request.Context(), provider.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list provider versions",
			})
			return
		}

		// Format response per Network Mirror Protocol spec
		// https://www.terraform.io/docs/internals/provider-network-mirror-protocol.html
		//
		// Response format:
		// {
		//   "versions": {
		//     "1.0.0": {},
		//     "1.1.0": {},
		//     "2.0.0": {}
		//   }
		// }
		versionsMap := make(map[string]interface{})
		for _, v := range versions {
			// Each version is an empty object per the spec
			versionsMap[v.Version] = gin.H{}
		}

		response := gin.H{
			"versions": versionsMap,
		}

		// Use c.Data with plain "application/json" (no charset) to satisfy the
		// Terraform Network Mirror Protocol spec, which rejects unknown content-type
		// parameters. Gin's c.JSON would append "; charset=utf-8" and trigger a
		// [WARN] from terraform init.
		data, err := json.Marshal(response)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize response"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
	}
}

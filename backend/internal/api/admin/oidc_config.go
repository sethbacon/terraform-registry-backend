// oidc_config.go implements admin handlers for reading and updating the active OIDC
// configuration, focusing on the group-to-role mapping settings that can be
// managed at runtime without re-running the setup wizard.
package admin

import (
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// OIDCConfigAdminHandlers handles admin OIDC configuration endpoints
type OIDCConfigAdminHandlers struct {
	oidcConfigRepo *repositories.OIDCConfigRepository
}

// NewOIDCConfigAdminHandlers creates a new OIDCConfigAdminHandlers instance
func NewOIDCConfigAdminHandlers(oidcConfigRepo *repositories.OIDCConfigRepository) *OIDCConfigAdminHandlers {
	return &OIDCConfigAdminHandlers{oidcConfigRepo: oidcConfigRepo}
}

// @Summary      Get active OIDC configuration
// @Description  Returns the currently active OIDC configuration including group mapping settings. Client secret is never returned. Requires admin scope.
// @Tags         OIDC
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  models.OIDCConfigResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "No active OIDC group configuration"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/oidc/config [get]
func (h *OIDCConfigAdminHandlers) GetActiveOIDCConfig(c *gin.Context) {
	ctx := c.Request.Context()

	cfg, err := h.oidcConfigRepo.GetActiveOIDCConfig(ctx)
	if identityerr.Missing(cfg, err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active OIDC group configuration"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve OIDC group configuration"})
		return
	}

	c.JSON(http.StatusOK, models.OIDCConfigToResponse(cfg))
}

// @Summary      Update OIDC group mapping settings
// @Description  Updates the group claim name, group-to-role mappings, and default role for the active OIDC configuration. Takes effect on the next login. Requires admin scope.
// @Tags         OIDC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.OIDCGroupMappingInput  true  "Group mapping configuration"
// @Success      200  {object}  models.OIDCConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "No active OIDC group configuration"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/oidc/group-mapping [put]
func (h *OIDCConfigAdminHandlers) UpdateGroupMapping(c *gin.Context) {
	ctx := c.Request.Context()

	var input models.OIDCGroupMappingInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg, err := h.oidcConfigRepo.GetActiveOIDCConfig(ctx)
	if identityerr.Missing(cfg, err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active OIDC group configuration"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve OIDC configuration"})
		return
	}

	if err := cfg.SetGroupMappingConfig(input.GroupClaimName, models.ToIdentityGroupMappings(input.GroupMappings), input.DefaultRole); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode group mapping"})
		return
	}

	// Raced against a config delete/deactivate between the read above and this
	// write: 404, matching the read's own answer for a missing active config,
	// rather than the 200 the old contract returned for a save that wrote
	// nothing — which left the admin UI showing a group mapping the deployment
	// was not actually using.
	if err := h.oidcConfigRepo.UpdateOIDCConfigExtraConfig(ctx, cfg.ID, cfg.ExtraConfig); err != nil {
		if identityerr.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "No active OIDC group configuration"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save group mapping"})
		return
	}

	// Return the updated config
	updated, err := h.oidcConfigRepo.GetActiveOIDCConfig(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve updated configuration"})
		return
	}

	c.JSON(http.StatusOK, models.OIDCConfigToResponse(updated))
}

package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/policy"
)

// PolicyHandler exposes admin endpoints for the OPA policy engine.
type PolicyHandler struct {
	engine *policy.PolicyEngine
	cfg    config.PolicyConfig
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(engine *policy.PolicyEngine, cfg config.PolicyConfig) *PolicyHandler {
	return &PolicyHandler{engine: engine, cfg: cfg}
}

// GetPolicyConfig returns the current policy engine configuration.
//
// @Summary      Get policy configuration
// @Description  Returns the current policy engine configuration (enabled, mode, bundle URL, refresh interval).
// @Tags         System
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /api/v1/admin/policy/config [get]
func (h *PolicyHandler) GetPolicyConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled":                 h.cfg.Enabled,
		"mode":                    h.cfg.Mode,
		"bundle_url":              h.cfg.BundleURL,
		"bundle_refresh_interval": h.cfg.BundleRefreshInterval,
		"active":                  h.engine.IsEnabled(),
	})
}

// ReloadBundle forces an immediate bundle reload.
//
// @Summary      Reload policy bundle
// @Description  Forces an immediate reload of the Rego policy bundle from the configured URL.
// @Tags         System
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "No bundle URL configured"
// @Failure      401  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /api/v1/admin/policy/reload [post]
func (h *PolicyHandler) ReloadBundle(c *gin.Context) {
	if h.cfg.BundleURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no bundle_url configured"})
		return
	}
	if err := h.engine.Reload(c.Request.Context(), h.cfg.BundleURL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "reloaded"})
}

// EvaluateInput evaluates an ad-hoc input map against the loaded policies.
//
// @Summary      Evaluate policy input
// @Description  Evaluates an arbitrary input map against the currently loaded policy bundle.
// @Tags         System
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  map[string]interface{}  true  "Input to evaluate"
// @Success      200  {object}  policy.PolicyResult
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /api/v1/admin/policy/evaluate [post]
func (h *PolicyHandler) EvaluateInput(c *gin.Context) {
	var input map[string]interface{}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON input"})
		return
	}
	result, err := h.engine.Evaluate(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

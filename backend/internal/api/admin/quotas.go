// quotas.go implements the admin endpoint that feeds the frontend per-org
// quota dashboard. READ-ONLY: it computes a QuotaStatus per organization by
// joining org_quotas with today's row in org_quota_usage. The frontend reads
// `response.data.quotas`.
//
// Enforcement (429 + X-Quota-Reset middleware) and admin write endpoints for
// setting per-org limits are tracked separately and intentionally out of scope.
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// QuotaHandlers serves the admin quotas dashboard endpoint.
type QuotaHandlers struct {
	quotaRepo *repositories.OrgQuotaRepository
}

// NewQuotaHandlers constructs a QuotaHandlers.
func NewQuotaHandlers(db *sqlx.DB) *QuotaHandlers {
	return &QuotaHandlers{quotaRepo: repositories.NewOrgQuotaRepository(db)}
}

// quotaListResponse is the wrapper expected by the frontend (`response.data.quotas`).
type quotaListResponse struct {
	Quotas []models.QuotaStatus `json:"quotas"`
}

// @Summary      List per-org quota status (admin)
// @Description  Returns one QuotaStatus per organization with current limits and today's usage. Optional `organization_id` filter narrows the result to a single org. Requires admin scope. Limits of `0` mean unlimited and produce a utilization ratio of `0`.
// @Tags         Quotas
// @Security     Bearer
// @Produce      json
// @Param        organization_id  query  string  false  "Optional: scope the result to a single organization (UUID)"
// @Success      200  {object}  map[string]interface{}  "{\"quotas\": []QuotaStatus}"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/quotas [get]
// ListQuotas returns the per-org quota status snapshot used by the dashboard.
// GET /api/v1/admin/quotas
func (h *QuotaHandlers) ListQuotas() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Query("organization_id")
		statuses, err := h.quotaRepo.ListQuotaStatuses(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load quotas"})
			return
		}
		c.JSON(http.StatusOK, quotaListResponse{Quotas: statuses})
	}
}

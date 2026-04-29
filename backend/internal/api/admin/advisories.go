// advisories.go implements admin endpoints for managing CVE advisories.
package admin

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
)

// AdvisoryHandlers handles admin CVE advisory endpoints.
type AdvisoryHandlers struct {
	cveRepo *repositories.CVERepository
	pollJob *jobs.CVEPollJob
}

// NewAdvisoryHandlers creates a new AdvisoryHandlers.
func NewAdvisoryHandlers(db *sql.DB, pollJob *jobs.CVEPollJob) *AdvisoryHandlers {
	return &AdvisoryHandlers{
		cveRepo: repositories.NewCVERepository(db),
		pollJob: pollJob,
	}
}

// @Summary      List all CVE advisories (admin)
// @Description  Returns all advisories including withdrawn ones. Requires admin scope.
// @Tags         Vulnerability Advisories
// @Security     Bearer
// @Produce      json
// @Param        kind  query  string  false  "Filter by target kind: binary, provider, scanner"
// @Success      200  {array}   object
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/advisories [get]
// ListAdvisories returns all CVE advisories for admin review.
// GET /api/v1/admin/advisories
func (h *AdvisoryHandlers) ListAdvisories() gin.HandlerFunc {
	return func(c *gin.Context) {
		kind := c.Query("kind")
		advisories, err := h.cveRepo.ListAll(c.Request.Context(), kind)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch advisories"})
			return
		}

		type advisoryItem struct {
			ID          string   `json:"id"`
			SourceID    string   `json:"source_id"`
			Severity    string   `json:"severity"`
			Summary     string   `json:"summary"`
			References  []string `json:"references"`
			Withdrawn   bool     `json:"withdrawn"`
			TargetCount int      `json:"target_count"`
		}

		response := make([]advisoryItem, 0, len(advisories))
		for _, a := range advisories {
			response = append(response, advisoryItem{
				ID:          a.ID.String(),
				SourceID:    a.SourceID,
				Severity:    string(a.Severity),
				Summary:     a.Summary,
				References:  a.References,
				Withdrawn:   a.WithdrawnAt != nil,
				TargetCount: len(a.Targets),
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"advisories": response,
			"total":      len(response),
		})
	}
}

// @Summary      Trigger a CVE poll (admin)
// @Description  Queues an immediate CVE poll pass outside the normal schedule. Requires admin scope.
// @Tags         Vulnerability Advisories
// @Security     Bearer
// @Produce      json
// @Success      202  {object}  map[string]interface{}  "Poll queued"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      503  {object}  map[string]interface{}  "CVE poll job not running"
// @Router       /api/v1/admin/advisories/poll [post]
// TriggerPoll queues an immediate CVE poll outside the normal schedule.
// POST /api/v1/admin/advisories/poll
func (h *AdvisoryHandlers) TriggerPoll() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.pollJob == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "CVE polling is not enabled"})
			return
		}
		h.pollJob.TriggerPoll()
		c.JSON(http.StatusAccepted, gin.H{"message": "CVE poll queued"})
	}
}

// Package advisories provides the public handler for querying active CVE advisories.
// The single GET endpoint is intentionally cache-friendly (5 min public cache header)
// and is consumed by the frontend banner component.
package advisories

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Handlers holds the public advisory endpoints.
type Handlers struct {
	cveRepo *repositories.CVERepository
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(db *sql.DB) *Handlers {
	return &Handlers{
		cveRepo: repositories.NewCVERepository(db),
	}
}

// @Summary      List active CVE advisories
// @Description  Returns all CVE advisories that have at least one non-deprecated affected version.
// @Description  Withdrawn advisories and advisories where all affected versions have been deprecated are excluded.
// @Description  Results are cached for 5 minutes.
// @Tags         Vulnerability Advisories
// @Produce      json
// @Success      200  {array}   models.CVEActiveAdvisoryResponse
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/advisories/active [get]
// ListActive returns all currently active CVE advisories.
// GET /api/v1/advisories/active
func (h *Handlers) ListActive() gin.HandlerFunc {
	return func(c *gin.Context) {
		advisories, err := h.cveRepo.ListActive(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch advisories"})
			return
		}

		response := make([]models.CVEActiveAdvisoryResponse, 0, len(advisories))
		for _, a := range advisories {
			primaryKind := models.CVETargetKind("")
			if len(a.Targets) > 0 {
				primaryKind = a.Targets[0].TargetKind
			}
			response = append(response, models.CVEActiveAdvisoryResponse{
				ID:         a.ID,
				SourceID:   a.SourceID,
				Severity:   a.Severity,
				Summary:    a.Summary,
				References: a.References,
				TargetKind: primaryKind,
				Targets:    a.Targets,
			})
		}

		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, response)
	}
}

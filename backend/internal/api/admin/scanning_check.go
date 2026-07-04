// scanning_check.go implements the admin endpoint that triggers an immediate
// scanner update check, bypassing the scheduled interval.
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/jobs"
)

// TriggerScannerCheckResponse is returned by POST /api/v1/admin/scanning/check.
type TriggerScannerCheckResponse struct {
	Message string `json:"message"`
} // @name TriggerScannerCheckResponse

// @Summary      Trigger an immediate scanner update check
// @Description  Signals the scheduled scanner update job to run a check now instead of waiting for its next tick. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Success      202  {object}  TriggerScannerCheckResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/scanning/check [post]
func TriggerScannerCheckHandler(job *jobs.ScannerUpdateJob) gin.HandlerFunc {
	return func(c *gin.Context) {
		job.TriggerCheck()
		c.JSON(http.StatusAccepted, TriggerScannerCheckResponse{Message: "scanner update check triggered"})
	}
}

// user_gdpr.go implements GDPR data-subject endpoints:
// - GET  /api/v1/admin/users/:id/export — export all user data as JSON (Article 15/20)
// - POST /api/v1/admin/users/:id/erase  — tombstone user and anonymize PII (Article 17)
// coverage:skip:requires-running-server
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// GDPRHandlers provides GDPR data-subject endpoints.
type GDPRHandlers struct {
	userSvc *services.UserService
}

// NewGDPRHandlers creates a new GDPRHandlers.
func NewGDPRHandlers(userSvc *services.UserService) *GDPRHandlers {
	return &GDPRHandlers{userSvc: userSvc}
}

// @Summary      Export user data (GDPR)
// @Description  Export all personal data associated with a user as JSON. Implements GDPR Article 15 (right of access) and Article 20 (data portability). Requires admin scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  services.UserDataExport
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/users/{id}/export [get]
func (h *GDPRHandlers) ExportUserDataHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		data, err := h.userSvc.ExportUserDataJSON(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found or export failed"})
			return
		}

		filename := "user-data-" + userID + ".json"
		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, "application/json", data)
	}
}

// @Summary      Erase user data (GDPR)
// @Description  Anonymize a user's PII and revoke all access (GDPR Article 17 — right to erasure). Audit log entries are preserved with the anonymized user ID for compliance. Requires admin scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  map[string]interface{}  "User data erased"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/users/{id}/erase [post]
func (h *GDPRHandlers) EraseUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		// Get the admin performing the erasure from the auth context
		erasedBy, _ := c.Get("user_id")
		erasedByStr, _ := erasedBy.(string)
		if erasedByStr == "" {
			erasedByStr = "system"
		}

		if err := h.userSvc.EraseUser(c.Request.Context(), userID, erasedByStr); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "User data has been erased. Audit log entries are preserved with anonymized identifiers.",
			"user_id": userID,
		})
	}
}

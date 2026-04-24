// approval_handler.go implements the single-use approval token redemption endpoint.
// When an approver clicks a link containing a token, this endpoint marks the
// associated mirror approval request as "approved" without requiring admin login.
package webhooks

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ApprovalHandler handles webhook-based approval token redemption.
type ApprovalHandler struct {
	rbacRepo *repositories.RBACRepository
}

// NewApprovalHandler creates a new ApprovalHandler.
func NewApprovalHandler(rbacRepo *repositories.RBACRepository) *ApprovalHandler {
	return &ApprovalHandler{rbacRepo: rbacRepo}
}

// @Summary      Redeem approval token
// @Description  Redeems a single-use approval token generated via the admin API. When valid,
//
//	the associated mirror approval request is set to "approved". Tokens expire after
//	24 hours and can only be used once. This endpoint requires no authentication —
//	possession of the token is the credential.
//
// @Tags         Webhooks
// @Produce      json
// @Param        token  path  string  true  "Single-use approval token"
// @Success      200  {object}  map[string]interface{}  "Approval request approved"
// @Failure      400  {object}  map[string]interface{}  "Invalid token format"
// @Failure      404  {object}  map[string]interface{}  "Token not found, already used, or expired"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /webhooks/approvals/{token} [post]
// RedeemApprovalToken handles POST /webhooks/approvals/:token
func (h *ApprovalHandler) RedeemApprovalToken(c *gin.Context) {
	plainToken := c.Param("token")
	if len(plainToken) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token format"})
		return
	}

	// Hash the plain token the same way it was stored.
	sum := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(sum[:])

	approvalID, err := h.rbacRepo.RedeemApprovalToken(c.Request.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found, already used, or expired"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to redeem approval token"})
		return
	}

	// Approve the associated request with a system/zero reviewer UUID.
	if err := h.rbacRepo.UpdateApprovalStatus(c.Request.Context(), approvalID,
		models.ApprovalStatusApproved, uuid.Nil, "Approved via single-use webhook token"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update approval status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":             "Approval request approved",
		"approval_request_id": approvalID.String(),
	})
}

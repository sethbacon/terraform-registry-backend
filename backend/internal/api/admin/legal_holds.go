// legal_holds.go is the operator surface for legal hold: place one, release
// one, see what is in force. Issue #872.
//
// PLACING A HOLD IS ITSELF A PRIVILEGED ACT, and it is recorded as one. A hold
// suspends the deletion of audit history, which is the mechanism a deployment
// relies on to bound how long that history is kept — so the ability to place
// one indefinitely is the ability to retain evidence indefinitely, and the
// ability to release one is the ability to let it be destroyed. Both write
// audit entries, on the same connection the holds themselves live on.
package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	idmodels "github.com/sethbacon/terraform-suite-identity/identity/models"

	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/safego"
)

// Audit actions written by this file. Named for what happened to the hold, not
// for the route that caused it, so a reader of the audit trail does not have to
// know the API shape.
const (
	actionLegalHoldPlaced   = "legal_hold.placed"
	actionLegalHoldReleased = "legal_hold.released"
	resourceLegalHold       = "legal_hold"
)

// LegalHoldHandlers serves the legal-hold admin routes.
type LegalHoldHandlers struct {
	holds     *audit.LegalHoldStore
	auditRepo *repositories.AuditRepository

	// unavailable, when non-empty, is why this deployment cannot honour holds:
	// the legal_holds table did not resolve on the connection the retention
	// sweep runs on. The routes still exist and answer 503 with this reason.
	//
	// The alternative — not registering them — was tried and is worse in two
	// ways. It makes the router's shape depend on a runtime probe, which the
	// route-class guard correctly reports as the AST inventing routes gin does
	// not serve; and it answers an operator's POST with 404, which reads as "no
	// such feature" when the truth is "this feature exists and is misconfigured
	// in a way that would destroy the evidence you are trying to preserve".
	unavailable string
}

// NewLegalHoldHandlers constructs the handlers.
//
// Both dependencies must be on the connection that reaches audit_logs: the
// holds are read there by the retention sweep, and the audit entries recorded
// here are audit_logs rows themselves.
func NewLegalHoldHandlers(holds *audit.LegalHoldStore, auditRepo *repositories.AuditRepository) *LegalHoldHandlers {
	return &LegalHoldHandlers{holds: holds, auditRepo: auditRepo}
}

// NewUnavailableLegalHoldHandlers serves the same routes for a deployment whose
// holds table the sweep cannot read, answering 503 with the reason.
func NewUnavailableLegalHoldHandlers(reason string) *LegalHoldHandlers {
	return &LegalHoldHandlers{unavailable: reason}
}

// refuseIfUnavailable answers 503 and reports whether it did.
//
// PLACING is the dangerous one — a hold accepted here but invisible to the
// sweep is the precise failure #872 exists to prevent — but LISTING refuses
// too, because an empty list from a deployment that cannot read the table is
// indistinguishable from "nothing is held", and that is a worse answer than an
// error.
func (h *LegalHoldHandlers) refuseIfUnavailable(c *gin.Context) bool {
	if h.unavailable == "" {
		return false
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Legal hold is not available in this deployment: " + h.unavailable,
	})
	return true
}

// PlaceLegalHoldRequest is the body of POST /api/v1/admin/legal-holds.
type PlaceLegalHoldRequest struct {
	Name      string    `json:"name" binding:"required"`
	Reason    string    `json:"reason"`
	StartDate time.Time `json:"start_date" binding:"required"`
	EndDate   time.Time `json:"end_date" binding:"required"`
}

// LegalHoldsResponse is returned by GET /api/v1/admin/legal-holds.
type LegalHoldsResponse struct {
	LegalHolds []audit.LegalHold `json:"legal_holds"`
}

// PlaceLegalHold godoc
// @Summary      Place a legal hold on a window of audit history
// @Description  Audit entries whose created_at falls inside the hold's inclusive date range are exempted from the retention sweep until the hold is released.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        request  body      PlaceLegalHoldRequest  true  "Hold to place"
// @Success      201      {object}  audit.LegalHold
// @Failure      400      {object}  map[string]interface{}  "Invalid request"
// @Failure      403      {object}  map[string]interface{}  "Forbidden"
// @Failure      503      {object}  map[string]interface{}  "Legal hold unavailable in this deployment"
// @Failure      500      {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/legal-holds [post]
func (h *LegalHoldHandlers) PlaceLegalHold(c *gin.Context) {
	if h.refuseIfUnavailable(c) {
		return
	}
	var req PlaceLegalHoldRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor := actorUserID(c)
	hold := &audit.LegalHold{
		Name:      req.Name,
		Reason:    req.Reason,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		PlacedBy:  actor,
	}
	if err := h.holds.Place(c.Request.Context(), hold); err != nil {
		// A rejected window is the caller's mistake, not the server's.
		if errors.Is(err, audit.ErrHoldNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if isHoldValidationError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		slog.Error("failed to place legal hold", "error", err, "name", req.Name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to place legal hold"})
		return
	}

	h.recordHoldAction(c, actionLegalHoldPlaced, hold, actor)
	c.JSON(http.StatusCreated, hold)
}

// ReleaseLegalHold godoc
// @Summary      Release a legal hold
// @Description  Deactivates the hold. The row is kept as the record of what was preserved and when; the entries it covered become deletable on the next retention sweep.
// @Tags         admin
// @Produce      json
// @Param        id   path      string  true  "Legal hold id"
// @Success      200  {object}  audit.LegalHold
// @Failure      404  {object}  map[string]interface{}  "Not found or already released"
// @Failure      503  {object}  map[string]interface{}  "Legal hold unavailable in this deployment"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/legal-holds/{id}/release [post]
func (h *LegalHoldHandlers) ReleaseLegalHold(c *gin.Context) {
	if h.refuseIfUnavailable(c) {
		return
	}
	actor := actorUserID(c)
	hold, err := h.holds.Release(c.Request.Context(), c.Param("id"), actor)
	if errors.Is(err, audit.ErrHoldNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Legal hold not found or already released"})
		return
	}
	if err != nil {
		slog.Error("failed to release legal hold", "error", err, "id", c.Param("id"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to release legal hold"})
		return
	}

	h.recordHoldAction(c, actionLegalHoldReleased, hold, actor)
	c.JSON(http.StatusOK, hold)
}

// ListLegalHolds godoc
// @Summary      List legal holds
// @Tags         admin
// @Produce      json
// @Param        active  query     bool  false  "Only holds still in force"
// @Success      200     {object}  LegalHoldsResponse
// @Failure      503     {object}  map[string]interface{}  "Legal hold unavailable in this deployment"
// @Failure      500     {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/legal-holds [get]
func (h *LegalHoldHandlers) ListLegalHolds(c *gin.Context) {
	if h.refuseIfUnavailable(c) {
		return
	}
	activeOnly := c.Query("active") == "true"
	holds, err := h.holds.List(c.Request.Context(), activeOnly)
	if err != nil {
		slog.Error("failed to list legal holds", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list legal holds"})
		return
	}
	c.JSON(http.StatusOK, LegalHoldsResponse{LegalHolds: holds})
}

// recordHoldAction writes the audit entry for a hold that was just placed or
// released.
//
// Asynchronous, like the other audit writes in this package: the hold is
// already committed, and failing the operator's request because the record of
// it could not be written would leave them believing the hold does not exist
// when it does — the more dangerous of the two wrong beliefs.
func (h *LegalHoldHandlers) recordHoldAction(c *gin.Context, action string, hold *audit.LegalHold, actor *string) {
	if h.auditRepo == nil {
		return
	}
	ip := c.ClientIP()
	resourceType := resourceLegalHold
	holdID := hold.ID
	metadata := map[string]interface{}{
		"name":       hold.Name,
		"start_date": hold.StartDate.UTC().Format(time.RFC3339),
		"end_date":   hold.EndDate.UTC().Format(time.RFC3339),
	}
	if hold.Reason != "" {
		metadata["reason"] = hold.Reason
	}

	safego.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.auditRepo.CreateAuditLog(ctx, &idmodels.AuditLog{
			Action:       action,
			ResourceType: &resourceType,
			ResourceID:   &holdID,
			IPAddress:    &ip,
			UserID:       actor,
			Metadata:     metadata,
		}); err != nil {
			slog.Error("failed to write audit log for legal hold", "error", err, "action", action, "hold_id", holdID)
		}
	})
}

// actorUserID returns the acting user id, or nil for a principal with no user
// row behind it (an mTLS certificate, for instance).
func actorUserID(c *gin.Context) *string {
	v, ok := c.Get("user_id")
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

// isHoldValidationError reports whether err is one of the store's own argument
// rejections rather than a database failure.
func isHoldValidationError(err error) bool {
	msg := err.Error()
	return msg == "legal hold name is required" || msg == "end_date must not be before start_date"
}

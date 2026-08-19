// version_approvals.go implements the admin endpoints for the version approval
// gate. They surface gated provider- and terraform-mirror versions through one
// uniform shape, let administrators approve or reject them (individually or in
// bulk), expose the per-version audit trail, and provide the pending count for
// the dashboard badge.
//
// Read endpoints require mirrors:read; mutations require the admin scope —
// route wiring lives in router.go.
package admin

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// VersionApprovalHandler holds dependencies for the version-approval endpoints.
type VersionApprovalHandler struct {
	repo *repositories.VersionApprovalRepository
	// orgRepo resolves the caller's memberships so the read endpoints can be
	// scoped to the organizations owning the mirror configurations that
	// produced each gated version. Set via WithOrgRepo; nil makes every
	// non-admin scope empty, which fails closed (issue #719).
	orgRepo *repositories.OrganizationRepository
}

// NewVersionApprovalHandler constructs a VersionApprovalHandler.
func NewVersionApprovalHandler(repo *repositories.VersionApprovalRepository) *VersionApprovalHandler {
	return &VersionApprovalHandler{repo: repo}
}

// WithOrgRepo wires in the organization repository so the version-approval READ
// routes can be scoped to the caller's organizations. Returns the handler for
// chaining.
func (h *VersionApprovalHandler) WithOrgRepo(orgRepo *repositories.OrganizationRepository) *VersionApprovalHandler {
	h.orgRepo = orgRepo
	return h
}

// tenantFilter builds the mandatory tenant constraint shared by every
// version-approval read axis, writing the 500 and reporting ok=false on a
// membership lookup failure.
//
// GUARD version-approval-tenant-scope (issue #719). This whole route family was
// missed by the first pass: the handler built a filter straight from query
// parameters with no organization predicate at all, so any holder of the flat
// mirrors:read scope union saw every tenant's gated provider versions, their
// mirror configuration names and ids, and a pending count that moved with other
// organizations' activity.
func (h *VersionApprovalHandler) tenantFilter(c *gin.Context) (repositories.VersionApprovalFilter, bool) {
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsRead)
	if !ok {
		return repositories.VersionApprovalFilter{}, false
	}
	return repositories.VersionApprovalFilter{Scope: scope.OrgScope()}, true
}

// @Summary      List version approvals
// @Description  Lists mirrored provider and terraform versions that are subject to the approval gate, filtered by status, type, and mirror config.
// @Tags         Version Approvals
// @Security     Bearer
// @Produce      json
// @Param        status     query  string  false  "Filter by status (pending_approval, approved, rejected)"
// @Param        type       query  string  false  "Filter by type (provider, terraform)"
// @Param        config_id  query  string  false  "Filter by mirror config UUID"
// @Param        limit      query  int     false  "Max results (default 100, max 500). A larger value is served as 500."
// @Param        offset     query  int     false  "Offset for pagination"
// @Success      200  {object}  models.VersionApprovalListResponse
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/version-approvals [get]
func (h *VersionApprovalHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filter, ok := h.tenantFilter(c)
	if !ok {
		return
	}
	filter.Status = c.Query("status")
	filter.Type = c.Query("type")
	filter.ConfigID = c.Query("config_id")
	filter.Limit = limit
	filter.Offset = offset

	items, total, err := h.repo.List(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list version approvals"})
		return
	}

	c.JSON(http.StatusOK, models.VersionApprovalListResponse{Items: items, Total: total})
}

// @Summary      Pending version approval count
// @Description  Returns the number of versions awaiting approval across all mirrors. Used for the admin dashboard badge.
// @Tags         Version Approvals
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]int  "count"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/version-approvals/pending-count [get]
func (h *VersionApprovalHandler) PendingCount(c *gin.Context) {
	filter, ok := h.tenantFilter(c)
	if !ok {
		return
	}
	count, err := h.repo.PendingCount(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count pending approvals"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": count})
}

// @Summary      Approve a version
// @Description  Approves a single gated version, making it visible to Terraform clients.
// @Tags         Version Approvals
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Version row UUID"
// @Param        body  body  models.VersionApprovalActionRequest  false  "Optional notes"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid id"
// @Failure      404  {object}  map[string]interface{}  "Version not found or not gated"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/version-approvals/{id}/approve [put]
func (h *VersionApprovalHandler) Approve(c *gin.Context) {
	h.setStatus(c, models.VersionApprovalStatusApproved)
}

// @Summary      Reject a version
// @Description  Rejects a single gated version, permanently hiding it from Terraform clients.
// @Tags         Version Approvals
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Version row UUID"
// @Param        body  body  models.VersionApprovalActionRequest  false  "Optional notes"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid id"
// @Failure      404  {object}  map[string]interface{}  "Version not found or not gated"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/version-approvals/{id}/reject [put]
func (h *VersionApprovalHandler) Reject(c *gin.Context) {
	h.setStatus(c, models.VersionApprovalStatusRejected)
}

// setStatus is the shared implementation for the single approve/reject endpoints.
func (h *VersionApprovalHandler) setStatus(c *gin.Context, status string) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version id"})
		return
	}

	var req models.VersionApprovalActionRequest
	_ = c.ShouldBindJSON(&req) // body is optional

	err = h.repo.SetStatus(c.Request.Context(), id, status, currentUserID(c), req.Notes)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found or not subject to approval"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update version status"})
		return
	}
	c.JSON(http.StatusOK, MessageResponse{Message: "Version " + status})
}

// @Summary      Bulk approve versions
// @Description  Approves multiple gated versions in one request. Returns per-id failures without aborting the batch.
// @Tags         Version Approvals
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.VersionApprovalBulkRequest  true  "IDs and optional notes"
// @Success      200  {object}  models.VersionApprovalBulkResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Router       /api/v1/admin/version-approvals/bulk-approve [post]
func (h *VersionApprovalHandler) BulkApprove(c *gin.Context) {
	h.bulk(c, models.VersionApprovalStatusApproved)
}

// @Summary      Bulk reject versions
// @Description  Rejects multiple gated versions in one request. Returns per-id failures without aborting the batch.
// @Tags         Version Approvals
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.VersionApprovalBulkRequest  true  "IDs and optional notes"
// @Success      200  {object}  models.VersionApprovalBulkResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Router       /api/v1/admin/version-approvals/bulk-reject [post]
func (h *VersionApprovalHandler) BulkReject(c *gin.Context) {
	h.bulk(c, models.VersionApprovalStatusRejected)
}

// bulk is the shared implementation for the bulk approve/reject endpoints.
func (h *VersionApprovalHandler) bulk(c *gin.Context, status string) {
	var req models.VersionApprovalBulkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids is required"})
		return
	}

	userID := currentUserID(c)
	resp := models.VersionApprovalBulkResponse{Failures: []string{}}
	for _, raw := range req.IDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			resp.Failures = append(resp.Failures, raw)
			continue
		}
		if err := h.repo.SetStatus(c.Request.Context(), id, status, userID, req.Notes); err != nil {
			resp.Failures = append(resp.Failures, raw)
			continue
		}
		if status == models.VersionApprovalStatusApproved {
			resp.Approved++
		} else {
			resp.Rejected++
		}
	}

	c.JSON(http.StatusOK, resp)
}

// @Summary      Version approval audit trail
// @Description  Returns the chronological approval events (auto/manual) for a single version.
// @Tags         Version Approvals
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Version row UUID"
// @Success      200  {array}   models.VersionApprovalEvent
// @Failure      400  {object}  map[string]interface{}  "Invalid id"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/version-approvals/{id}/events [get]
func (h *VersionApprovalHandler) Events(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version id"})
		return
	}

	// GUARD version-approval-events-scope (issue #719): the by-id axis of the
	// same resource the list axis scopes. The event trail names who approved
	// what and when, with free-text notes, and the row is addressable by a bare
	// UUID — so without resolving the version's owning organization first, the
	// scoping on List was worth nothing to anyone holding an id.
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsRead)
	if !ok {
		return
	}
	ownerOrg, found, err := h.repo.OrganizationForVersion(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve version ownership"})
		return
	}
	// Out-of-scope versions read as absent, matching the audit by-id axis, so
	// this route cannot be used to probe for another organization's rows.
	if !found || !scope.PermitsPtr(ownerOrg) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
		return
	}

	events, err := h.repo.Events(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list approval events"})
		return
	}
	c.JSON(http.StatusOK, events)
}

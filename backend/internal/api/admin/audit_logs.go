// audit_logs.go implements handlers for retrieving audit log entries with pagination and filtering.
package admin

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
)

// AuditLogHandlers handles audit log read endpoints
type AuditLogHandlers struct {
	db        *sql.DB
	auditRepo *repositories.AuditRepository
	// orgRepo resolves the caller's memberships so audit reads can be scoped to
	// the organizations they actually belong to (issue #719).
	orgRepo *repositories.OrganizationRepository
}

// NewAuditLogHandlers creates a new AuditLogHandlers instance
func NewAuditLogHandlers(db *sql.DB) *AuditLogHandlers {
	return &AuditLogHandlers{
		db:        db,
		orgRepo:   repositories.NewOrganizationRepository(db),
		auditRepo: repositories.NewAuditRepository(db),
	}
}

// @Summary      List audit logs
// @Description  Get a paginated, filterable list of audit log entries. Requires audit:read scope.
// @Tags         Audit
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        page           query  int     false  "Page number (default 1)"
// @Param        per_page       query  int     false  "Items per page, max 200 (default 25)"
// @Param        action         query  string  false  "Filter by action string (exact match)"
// @Param        resource_type  query  string  false  "Filter by resource type (module, provider, user, mirror, api_key, organization)"
// @Param        user_id        query  string  false  "Filter by actor user ID (exact match)"
// @Param        user_email     query  string  false  "Filter by actor email (partial, case-insensitive)"
// @Param        start_date     query  string  false  "Filter entries at or after this RFC3339 timestamp"
// @Param        end_date       query  string  false  "Filter entries at or before this RFC3339 timestamp"
// @Success      200  {object}  admin.AuditLogListResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid query parameters"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — audit:read scope required"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/audit-logs [get]
// ListAuditLogsHandler returns paginated, filtered audit log entries.
// GET /api/v1/admin/audit-logs
func (h *AuditLogHandlers) ListAuditLogsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Pagination
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "25"))
		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 200 {
			perPage = 25
		}
		offset := (page - 1) * perPage

		// Build filters
		filters := repositories.AuditFilters{}

		if v := c.Query("action"); v != "" {
			filters.Action = &v
		}
		if v := c.Query("resource_type"); v != "" {
			filters.ResourceType = &v
		}
		if v := c.Query("user_id"); v != "" {
			filters.UserID = &v
		}
		if v := c.Query("user_email"); v != "" {
			filters.UserEmail = &v
		}
		if v := c.Query("start_date"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "start_date must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)"})
				return
			}
			filters.StartDate = &t
		}
		if v := c.Query("end_date"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "end_date must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)"})
				return
			}
			filters.EndDate = &t
		}

		// GUARD audit-list-tenant-scope (issue #719). audit:read is granted
		// per-organization by the `auditor` role template, but it arrives in the
		// session JWT as part of a flat, org-less scope union (#652) — so
		// without this an auditor in one organization read every organization's
		// audit trail.
		//
		// Platform admins deliberately still see the whole estate: an audit
		// trail nobody can review across tenants is not much of an audit trail,
		// and `admin` is an explicitly-granted platform-wide scope, consistent
		// with the admin exemption in the per-org guards.
		//
		// BEHAVIOUR CHANGE, documented in docs/upgrade-guide.md: an existing
		// non-admin auditor who could previously see all organizations will now
		// see only their own.
		auditScope, ok := h.auditScope(c)
		if !ok {
			return
		}
		if requested := c.Query("organization_id"); requested != "" {
			if !auditScope.PermitsOrganization(requested) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
				return
			}
			filters.OrganizationID = &requested
		}

		logs, total, err := h.auditRepo.ListAuditLogs(c.Request.Context(), filters, auditScope, perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
			return
		}

		// Map to response structs
		items := make([]AuditLogResponse, 0, len(logs))
		for _, l := range logs {
			items = append(items, AuditLogResponse{
				ID:             l.ID,
				UserID:         l.UserID,
				UserEmail:      l.UserEmail,
				UserName:       l.UserName,
				OrganizationID: l.OrganizationID,
				Action:         l.Action,
				ResourceType:   l.ResourceType,
				ResourceID:     l.ResourceID,
				Metadata:       l.Metadata,
				IPAddress:      l.IPAddress,
				CreatedAt:      l.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, AuditLogListResponse{
			Logs: items,
			Pagination: PaginationMeta{
				Page:    page,
				PerPage: perPage,
				Total:   int64(total),
			},
		})
	}
}

// @Summary      Get audit log entry
// @Description  Retrieve a single audit log entry by ID. Requires audit:read scope.
// @Tags         Audit
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Audit log entry ID"
// @Success      200  {object}  admin.AuditLogResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — audit:read scope required"
// @Failure      404  {object}  map[string]interface{}  "Audit log entry not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/audit-logs/{id} [get]
// GetAuditLogHandler returns a single audit log entry by ID.
// GET /api/v1/admin/audit-logs/:id
func (h *AuditLogHandlers) GetAuditLogHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		logID := c.Param("id")

		// GUARD audit-byid-tenant-scope (issue #719).
		//
		// The by-id axis of the same resource the list axis already scopes.
		// The #719 fix landed on ListAuditLogsHandler only, so any holder of
		// the flat audit:read scope union could still read any single entry of
		// any organization by id — and ListAuditLogs conveniently hands out the
		// ids within one's own tenant, while entry ids are UUIDs discoverable
		// from cross-referenced metadata elsewhere in the API.
		//
		// The scope is passed INTO the query, not applied to its result: the
		// database must stop returning the row, not return it for this handler
		// to discard. GetAuditLog reports an out-of-scope entry as absent, so
		// this route cannot be used to probe for the existence of another
		// organization's audit entries either.
		auditScope, ok := h.auditScope(c)
		if !ok {
			return
		}

		// BOTH "no such entry" and "out of this caller's scope" arrive as
		// store.ErrNotFound, and both must keep mapping to 404. Splitting them
		// — 404 for absent, 403 for out-of-scope — would hand back exactly the
		// existence oracle the scoped query above exists to deny: a 403 tells
		// the caller the id is real and belongs to someone else. The handler's
		// inability to tell the two apart is the property, not a limitation.
		log, err := h.auditRepo.GetAuditLog(c.Request.Context(), logID, auditScope)
		if identityerr.Missing(log, err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Audit log entry not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit log entry"})
			return
		}

		c.JSON(http.StatusOK, AuditLogResponse{
			ID:             log.ID,
			UserID:         log.UserID,
			UserEmail:      log.UserEmail,
			UserName:       log.UserName,
			OrganizationID: log.OrganizationID,
			Action:         log.Action,
			ResourceType:   log.ResourceType,
			ResourceID:     log.ResourceID,
			Metadata:       log.Metadata,
			IPAddress:      log.IPAddress,
			CreatedAt:      log.CreatedAt,
		})
	}
}

// auditScope translates this request's tenant scope into the store.AuditScope
// that every audit read accessor requires, writing the 500 and reporting
// ok=false on a membership lookup failure.
//
// One helper for all three axes on purpose: three private copies of "who is
// asking" is how the list axis and the by-id axis came to disagree in the first
// place. It is also the single place where the registry's answer to "what about
// rows with no organization" is stated — AuditScopeOrganizations, not
// AuditScopeOrganizationsAndUnowned, because on this deployment an audit entry
// with a NULL organization_id is an unattributed row rather than a platform
// event, and the same rule governs every other org-owned table here
// (internal/tenantscope, Scope.Permits). terraform-state-manager, whose NULLs
// genuinely are platform events, is the consumer the ...AndUnowned variant
// exists for.
func (h *AuditLogHandlers) auditScope(c *gin.Context) (repositories.AuditScope, bool) {
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeAuditRead)
	if !ok {
		return repositories.AuditScope{}, false
	}
	if scope.PlatformAdmin {
		return repositories.AuditScopeAllOrganizations(), true
	}
	// A caller with no qualifying organization gets the fail-closed scope,
	// which every accessor short-circuits to an empty result — not an
	// unfiltered query.
	return repositories.AuditScopeOrganizations(scope.OrgIDs...), true
}

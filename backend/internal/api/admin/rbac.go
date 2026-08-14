// rbac.go implements handlers for role template management, approval requests, and mirror access policy configuration.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/notify"
	"github.com/terraform-registry/terraform-registry/internal/safego"
)

// RBACHandlers handles RBAC-related API endpoints
type RBACHandlers struct {
	rbacRepo *repositories.RBACRepository
	// creds invalidates BOTH credential families that snapshot the scopes of a
	// role template when that template is edited or deleted: the per-user JWT
	// revoke-all watermark (issue #559 finding [9]) and the affected members'
	// API keys in the organizations where they held the template (issue #732).
	// An API key's scopes are stored on the api_keys row at creation and are
	// never re-derived from the template, so editing or deleting the template
	// had no effect on keys at all.
	// May be nil in tests; the sweep is skipped when unset.
	creds *credlifecycle.Sweeper

	// notifCfg, cveCfg, and mailer back the approval_pending notification sent
	// when a new mirror approval request is created. Set via WithNotifications;
	// nil until then, in which case the notification is skipped.
	notifCfg *config.NotificationsConfig
	cveCfg   *config.CVEConfig
	mailer   *notify.Mailer
	// notifier fans approval_pending out to admin-configured notification
	// channels (webhook/Slack/Teams/email), in addition to the direct
	// recipients email above. Set via WithNotifier; nil is a no-op.
	notifier *notify.Notifier

	// orgRepo resolves the caller's memberships for the list axes of the
	// org-owned resources this handler serves (mirror policies, mirror approval
	// requests). The per-resource route guard covers their /:id axes; a list has
	// no row in the path to resolve an owner from, so the check has to happen
	// here. Set via WithOrgRepo; nil makes every non-admin scope empty, which
	// fails closed (issue #719).
	orgRepo *repositories.OrganizationRepository

	// mirrorRepo resolves the organization owning the mirror configuration an
	// approval request is filed against. CreateApprovalRequest is handed a
	// mirror_config_id off the wire and nothing else, so this is the only way
	// it can derive the row's tenancy from the resource rather than from the
	// requester. Set via WithMirrorRepo; nil fails the create axis closed
	// (issue #719).
	mirrorRepo *repositories.MirrorRepository
}

// NewRBACHandlers creates a new RBAC handlers instance. apiKeys backs the
// API-key half of the credential sweep and lives on the identity connection;
// it may be nil, in which case only the JWT half runs. Passing nil for both
// disables the sweep entirely (the pre-existing test convention).
func NewRBACHandlers(rbacRepo *repositories.RBACRepository, userRevocations *repositories.UserTokenRevocationRepository, apiKeys *repositories.APIKeyRepository) *RBACHandlers {
	return &RBACHandlers{rbacRepo: rbacRepo, creds: credlifecycle.NewSweeper(userRevocations, apiKeys)}
}

// WithOrgRepo wires in the organization repository so the mirror-policy and
// approval-request LIST routes can be scoped to the caller's organizations.
// Returns the handler for chaining.
func (h *RBACHandlers) WithOrgRepo(orgRepo *repositories.OrganizationRepository) *RBACHandlers {
	h.orgRepo = orgRepo
	return h
}

// WithMirrorRepo wires in the mirror repository so CreateApprovalRequest can
// resolve the owning organization of the mirror configuration named in the
// request body. Returns the handler for chaining.
func (h *RBACHandlers) WithMirrorRepo(mirrorRepo *repositories.MirrorRepository) *RBACHandlers {
	h.mirrorRepo = mirrorRepo
	return h
}

// approvalTargetOrg resolves the organization that owns the mirror
// configuration an approval request is being filed against, and authorizes the
// caller in it. Returns (orgID, true) on success; on failure the response has
// already been written.
//
// GUARD approval-create-config-org (issue #719).
func (h *RBACHandlers) approvalTargetOrg(c *gin.Context, mirrorConfigID uuid.UUID) (*uuid.UUID, bool) {
	if h.mirrorRepo == nil {
		// Wired without a mirror repository: the owning organization cannot be
		// established, so the write cannot be authorized. Denying is the only
		// safe answer — the alternative is the unguarded behaviour this guard
		// replaces.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Mirror configuration lookup is not available"})
		return nil, false
	}

	cfg, err := h.mirrorRepo.GetByID(c.Request.Context(), mirrorConfigID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve mirror configuration"})
		return nil, false
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror configuration not found"})
		return nil, false
	}

	ownerOrg := ""
	if cfg.OrganizationID != nil {
		ownerOrg = cfg.OrganizationID.String()
	}

	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsManage)
	if !ok {
		return nil, false
	}
	if !scope.Permits(ownerOrg) {
		// Same unowned-row contract as everywhere else: a mirror configuration
		// with a NULL organization is a platform-administrator concern.
		c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the organization owning this mirror configuration"})
		return nil, false
	}

	return cfg.OrganizationID, true
}

// WithNotifications wires in the shared notifications/CVE config so
// CreateApprovalRequest can send an approval_pending admin notification email.
// Returns the handler for chaining.
func (h *RBACHandlers) WithNotifications(notifCfg *config.NotificationsConfig, cveCfg *config.CVEConfig) *RBACHandlers {
	h.notifCfg = notifCfg
	h.cveCfg = cveCfg
	h.mailer = notify.New(&notifCfg.SMTP)
	return h
}

// WithNotifier wires in the channel notifier so CreateApprovalRequest also
// fans approval_pending out to admin-configured notification channels
// (webhook/Slack/Teams/email). Returns the handler for chaining.
func (h *RBACHandlers) WithNotifier(n *notify.Notifier) *RBACHandlers {
	h.notifier = n
	return h
}

// revokeRoleTemplateMemberCredentials sweeps every credential family carrying a
// snapshot of roleTemplateID's scopes, for every member currently assigned it:
// their JWT revoke-all watermark and their API keys in the organization where
// they hold the template.
//
// Best-effort: the scope edit has already been committed, so a lookup or
// revocation failure is logged rather than turned into a misleading error
// response for an otherwise-successful edit. It is REPORTED, though: the
// returned bool is false when any part of the sweep did not land, so the
// handler can surface revocation_incomplete instead of answering a clean 200
// for an authority reduction whose credentials are still live.
func (h *RBACHandlers) revokeRoleTemplateMemberCredentials(c *gin.Context, roleTemplateID uuid.UUID, retained []string, reason string) bool {
	if h.creds == nil {
		return true
	}
	memberships, err := h.rbacRepo.ListRoleTemplateMemberships(c.Request.Context(), roleTemplateID)
	if err != nil {
		slog.Error("failed to list role template members for credential revocation",
			"role_template_id", roleTemplateID, "reason", reason, "error", err)
		return false
	}
	return h.sweepRoleTemplateMemberships(c, memberships, roleTemplateID, retained, reason)
}

// sweepRoleTemplateMemberships runs the credential sweep over an already-loaded
// membership set. DeleteRoleTemplate has to snapshot the memberships BEFORE the
// delete commits (the FK is ON DELETE SET NULL), so it cannot use the
// load-then-sweep helper above. Returns false when any member's sweep was
// incomplete.
func (h *RBACHandlers) sweepRoleTemplateMemberships(c *gin.Context, memberships []repositories.RoleTemplateMembership, roleTemplateID uuid.UUID, retained []string, reason string) bool {
	if h.creds == nil {
		return true
	}
	complete := true
	for _, m := range memberships {
		out := h.creds.OrgAuthorityReduced(c.Request.Context(), m.UserID, m.OrganizationID, retained, reason)
		if out.Incomplete {
			slog.Error("credential sweep incomplete after role template change",
				"user_id", m.UserID, "organization_id", m.OrganizationID,
				"role_template_id", roleTemplateID, "reason", reason)
			complete = false
		}
	}
	return complete
}

// notifyApprovalPending emails the configured admin recipients and fans out
// to admin-configured notification channels (webhook/Slack/Teams/email) when
// a new mirror provider approval request is created. The direct email is
// gated on notifications being enabled and the approval_pending event type
// not having been opted out of; channels have their own independent enabled
// flag and event subscription. Runs detached (fire-and-forget) so SMTP/
// webhook latency never delays the API response; send failures are logged
// only. A nil notifCfg (WithNotifications never called, e.g. in tests) skips
// only the direct email — the channel fan-out is independent.
func (h *RBACHandlers) notifyApprovalPending(approval *models.MirrorApprovalRequest) {
	target := approval.ProviderNamespace
	if approval.ProviderName != nil && *approval.ProviderName != "" {
		target = fmt.Sprintf("%s/%s", approval.ProviderNamespace, *approval.ProviderName)
	}
	subject := fmt.Sprintf("New approval pending: mirror request for %s", target)
	body := fmt.Sprintf(
		"A new mirror provider approval request requires review.\n\nProvider: %s\nReason: %s\n\nLog in to the Terraform Registry admin UI to review and approve or reject it.\n\n— Terraform Registry",
		target, approval.Reason,
	)

	safego.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		h.notifier.Notify(ctx, notify.Event{Type: notify.EventApprovalPending, Title: subject, Message: body})

		if h.notifCfg == nil || !h.notifCfg.Enabled || h.notifCfg.SMTP.Host == "" || !h.notifCfg.Events.ApprovalPending {
			return
		}
		recipients := h.notifCfg.Recipients
		if len(recipients) == 0 && h.cveCfg != nil {
			recipients = h.cveCfg.EmailRecipients
		}
		if len(recipients) == 0 {
			return
		}
		if err := h.mailer.Send(recipients, subject, body); err != nil {
			slog.Warn("failed to send approval-pending notification email", "error", err)
		}
	})
}

// ============================================================================
// Role Templates
// ============================================================================

// @Summary      List role templates
// @Description  Returns all available RBAC role templates. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Success      200  {array}   models.RoleTemplateView
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/role-templates [get]
// ListRoleTemplates returns all available role templates
// GET /api/v1/admin/role-templates
func (h *RBACHandlers) ListRoleTemplates(c *gin.Context) {
	templates, err := h.rbacRepo.ListRoleTemplates(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list role templates"})
		return
	}

	c.JSON(http.StatusOK, templates)
}

// @Summary      Get role template
// @Description  Returns a specific role template by ID. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Role template ID (UUID)"
// @Success      200  {object}  models.RoleTemplateView
// @Failure      400  {object}  map[string]interface{}  "Invalid role template ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Role template not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/role-templates/{id} [get]
// GetRoleTemplate returns a single role template
// GET /api/v1/admin/role-templates/:id
func (h *RBACHandlers) GetRoleTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role template ID"})
		return
	}

	template, err := h.rbacRepo.GetRoleTemplate(c.Request.Context(), id)
	if identityerr.Missing(template, err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role template not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get role template"})
		return
	}

	c.JSON(http.StatusOK, template)
}

// adminScopeAcceptedOnATemplate reports whether the submitted scope list may
// be written to a role template, answering the request itself when it may not
// (issue #766, migration 000054).
//
// WHY PR 3 CLOSES THIS PATH TOO, stated because it was a real decision.
// Migration 000054 takes `admin` off the seeded templates and every membership
// write refuses an admin-bearing one — but both of those are about the state of
// the data, and this route is how the data gets written. Leaving it open would
// mean the thing just removed could be put back by the same principal, on the
// same afternoon, with no migration and no restart. The removal would be a
// one-time cleanup rather than a property.
//
// Nothing is lost by closing it. `admin` on a template confers no authority
// from this release on: the auth middleware strips it from the session union
// and only the `platform_admins` carrier adds it back. So the only templates
// this refuses are ones that would have been inert AND unassignable — a
// template no membership write would accept, whose holders could never be
// re-assigned to their own role.
//
// 400 rather than 403: the caller holds `admin` and is entitled to this route.
// It is the body that is not writable, which is what 400 says.
func adminScopeAcceptedOnATemplate(c *gin.Context, scopes []string) bool {
	if err := auth.ValidateProvisionableScopes(scopes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "the `admin` scope cannot be placed on a role template; platform administration is " +
				"granted through POST /api/v1/admin/platform-admins",
		})
		return false
	}
	return true
}

// CreateRoleTemplateRequest represents the request to create a role template
type CreateRoleTemplateRequest struct {
	Name        string   `json:"name" binding:"required"`
	DisplayName string   `json:"display_name" binding:"required"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes" binding:"required"`
}

// @Summary      Create role template
// @Description  Create a new custom RBAC role template with specified scopes. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateRoleTemplateRequest  true  "Role template"
// @Success      201  {object}  models.RoleTemplateView
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Role template with this name already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/role-templates [post]
// CreateRoleTemplate creates a new role template
// POST /api/v1/admin/role-templates
func (h *RBACHandlers) CreateRoleTemplate(c *gin.Context) {
	var req CreateRoleTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !adminScopeAcceptedOnATemplate(c, req.Scopes) {
		return
	}

	// Check if name already exists.
	//
	// Existence probe: not-found is the SUCCESS case here. Leaving this as a
	// bare `err != nil -> 500` would make creating a role template with any
	// free name impossible.
	existing, err := h.rbacRepo.GetRoleTemplateByName(c.Request.Context(), req.Name)
	switch {
	case identityerr.Missing(existing, err):
		// Name is free — fall through and create.
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing template"})
		return
	default:
		c.JSON(http.StatusConflict, gin.H{"error": "Role template with this name already exists"})
		return
	}

	template := &models.RoleTemplate{
		ID:          uuid.New(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: &req.Description,
		Scopes:      req.Scopes,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.rbacRepo.CreateRoleTemplate(c.Request.Context(), template); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role template"})
		return
	}

	c.JSON(http.StatusCreated, template)
}

// @Summary      Update role template
// @Description  Update an existing custom role template. Cannot modify system role templates. Requires admin scope. When the edit NARROWS the template's scopes, the affected members' sessions and over-asking API keys are revoked; if that sweep does not fully land the 200 body carries an extra `revocation_incomplete: true` field.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Role template ID (UUID)"
// @Param        body  body  CreateRoleTemplateRequest  true  "Updated role template"
// @Success      200  {object}  models.RoleTemplateView
// @Failure      400  {object}  map[string]interface{}  "Invalid request or ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Cannot modify system role templates"
// @Failure      404  {object}  map[string]interface{}  "Role template not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/role-templates/{id} [put]
// UpdateRoleTemplate updates an existing role template
// PUT /api/v1/admin/role-templates/:id
func (h *RBACHandlers) UpdateRoleTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role template ID"})
		return
	}

	existing, err := h.rbacRepo.GetRoleTemplate(c.Request.Context(), id)
	if identityerr.Missing(existing, err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role template not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get role template"})
		return
	}
	if existing.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot modify system role templates"})
		return
	}

	var req CreateRoleTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !adminScopeAcceptedOnATemplate(c, req.Scopes) {
		return
	}

	// Only a REDUCTION invalidates anything. Adding scopes, or reordering an
	// otherwise identical list, leaves every existing credential asking for no
	// more than its holder still has -- and sweeping on those would revoke
	// every affected member's sessions and irreversibly delete their org-bound
	// API keys fleet-wide for a change that granted them more, not less.
	// AuthorityRetained compares by scope semantics rather than slice order,
	// so a pure reordering is correctly a no-op.
	authorityReduced := !credlifecycle.AuthorityRetained(existing.Scopes, req.Scopes)

	existing.DisplayName = req.DisplayName
	existing.Description = &req.Description
	existing.Scopes = req.Scopes
	existing.UpdatedAt = time.Now()

	if err := h.rbacRepo.UpdateRoleTemplate(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role template"})
		return
	}

	// A scope REDUCTION changes what a fresh JWT would embed for every member
	// currently assigned this template, and equally strands the scope snapshot
	// frozen on those members' API keys, which are never re-derived from the
	// template (issue #732); sweep both so the change takes effect immediately
	// instead of waiting out the JWT TTL (issue #559 finding [9]) or, for the
	// keys, never. req.Scopes is what those members retain, so keys that ask
	// for no more than the new list survive.
	//
	// A failed sweep is surfaced to the caller, exactly as DeleteRoleTemplate,
	// RemoveMemberHandler and DeleteOrganizationHandler do. Narrowing a
	// template's scopes and receiving a clean 200 while the affected members'
	// API keys are still live is the same silent failure those handlers were
	// changed to stop reporting as success.
	if authorityReduced && !h.revokeRoleTemplateMemberCredentials(c, id, req.Scopes, "role template scopes reduced") {
		// Embedding promotes the template's own fields, so the success body is
		// unchanged apart from the added flag.
		c.JSON(http.StatusOK, struct {
			*models.RoleTemplate
			RevocationIncomplete bool `json:"revocation_incomplete"`
		}{existing, true})
		return
	}

	c.JSON(http.StatusOK, existing)
}

// @Summary      Delete role template
// @Description  Delete a custom role template. Cannot delete system role templates. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Role template ID (UUID)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid role template ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Cannot delete system role templates"
// @Failure      404  {object}  map[string]interface{}  "Role template not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/role-templates/{id} [delete]
// DeleteRoleTemplate deletes a role template
// DELETE /api/v1/admin/role-templates/:id
func (h *RBACHandlers) DeleteRoleTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role template ID"})
		return
	}

	existing, err := h.rbacRepo.GetRoleTemplate(c.Request.Context(), id)
	if identityerr.Missing(existing, err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role template not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get role template"})
		return
	}
	if existing.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete system role templates"})
		return
	}

	// Snapshot the affected members before the delete: the FK is ON DELETE SET
	// NULL, so a member's role_template_id is gone the instant the delete
	// commits, and ListRoleTemplateMemberships would find nobody afterward.
	// This lookup only feeds the best-effort revocation loop below and is not
	// itself a precondition for the deletion, so a failure here is logged and
	// swallowed rather than blocking the delete: the security-relevant action
	// (removing an over-privileged or compromised role template) must not be
	// held hostage by a transient failure in unrelated bookkeeping. This is
	// the same posture RemoveMemberHandler takes on its analogous membership
	// pre-check, and like that handler, a failed lookup here is surfaced to
	// the caller via revocation_incomplete rather than silently masked behind
	// an identical success response.
	var memberships []repositories.RoleTemplateMembership
	revocationLookupFailed := false
	if h.creds != nil {
		var lookupErr error
		memberships, lookupErr = h.rbacRepo.ListRoleTemplateMemberships(c.Request.Context(), id)
		if lookupErr != nil {
			slog.Error("failed to look up role template members before deletion; affected members' credentials will not be revoked",
				"role_template_id", id, "error", lookupErr)
			memberships = nil
			revocationLookupFailed = true
		}
	}

	if err := h.rbacRepo.DeleteRoleTemplate(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role template"})
		return
	}

	// Deleting the template unconditionally removes its scopes from every
	// member who held it (unlike an edit, there's no "was this a no-op"
	// question to gate on) -- sweep both credential families that snapshot
	// those scopes: the JWT watermark, which otherwise carries them until the
	// TTL expires (issue #559 finding [9]), and the members' org-bound API
	// keys, which otherwise carry them forever because nothing re-derives a
	// key's scopes from its role template (issue #732). The delete has already
	// committed, so a revocation failure here is logged rather than turned
	// into a misleading error response for an otherwise-successful deletion,
	// matching revokeRoleTemplateMemberCredentials' own best-effort posture.
	// retained is nil: the template is gone, so its members retain none of the
	// scopes it granted (their membership rows are ON DELETE SET NULL'd to no
	// role template at all).
	if !h.sweepRoleTemplateMemberships(c, memberships, id, nil, "role template deleted") {
		// The members were known but at least one sweep failed -- the same
		// "reduction landed, credentials did not" state the lookup failure
		// below reports, reached one step later.
		revocationLookupFailed = true
	}

	response := gin.H{"message": "Role template deleted"}
	if revocationLookupFailed {
		// The delete itself succeeded, but we couldn't determine which
		// members to sweep -- surface that so the caller doesn't assume the
		// affected members' credentials were actually invalidated.
		response["revocation_incomplete"] = true
	}
	c.JSON(http.StatusOK, response)
}

// ============================================================================
// Mirror Approval Requests
// ============================================================================

// @Summary      List approval requests
// @Description  List mirror approval requests, optionally filtered by organization or status. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        organization_id  query  string  false  "Filter by organization ID (UUID)"
// @Param        status           query  string  false  "Filter by status (pending, approved, rejected)"
// @Success      200  {array}   models.MirrorApprovalRequest
// @Failure      400  {object}  map[string]interface{}  "Invalid organization ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/approvals [get]
// ListApprovalRequests lists all approval requests
// GET /api/v1/admin/approvals
func (h *RBACHandlers) ListApprovalRequests(c *gin.Context) {
	// GUARD approval-list-tenant-scope (issue #719).
	//
	// organization_id here is a caller-supplied query parameter, so the fact
	// that the repository query has an organization predicate proves nothing:
	// omit the parameter and it listed every organization's pending mirror
	// approvals; supply someone else's and it listed theirs. Either way this is
	// the enumeration step for POST /admin/approvals/:id/token, whose minted
	// token is redeemable without authentication.
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsRead)
	if !ok {
		return
	}

	var orgID *uuid.UUID
	if orgIDStr := c.Query("organization_id"); orgIDStr != "" {
		id, err := uuid.Parse(orgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
		if !scope.Permits(id.String()) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
			return
		}
		orgID = &id
	}

	var status *models.ApprovalStatus
	if statusStr := c.Query("status"); statusStr != "" {
		s := models.ApprovalStatus(statusStr)
		status = &s
	}

	requests, err := h.rbacRepo.ListApprovalRequests(c.Request.Context(), orgID, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list approval requests"})
		return
	}

	visible := make([]*models.MirrorApprovalRequest, 0, len(requests))
	for _, r := range requests {
		ownerOrg := ""
		if r.OrganizationID != nil {
			ownerOrg = r.OrganizationID.String()
		}
		if scope.Permits(ownerOrg) {
			visible = append(visible, r)
		}
	}

	c.JSON(http.StatusOK, visible)
}

// @Summary      Get approval request
// @Description  Returns a specific mirror approval request by ID. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Approval request ID (UUID)"
// @Success      200  {object}  models.MirrorApprovalRequest
// @Failure      400  {object}  map[string]interface{}  "Invalid approval request ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Approval request not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/approvals/{id} [get]
// GetApprovalRequest returns a single approval request
// GET /api/v1/admin/approvals/:id
func (h *RBACHandlers) GetApprovalRequest(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval request ID"})
		return
	}

	req, err := h.rbacRepo.GetApprovalRequest(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get approval request"})
		return
	}

	if req == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval request not found"})
		return
	}

	c.JSON(http.StatusOK, req)
}

// CreateApprovalRequestRequest represents the request to create an approval request
type CreateApprovalRequestRequest struct {
	MirrorConfigID    string  `json:"mirror_config_id" binding:"required"`
	ProviderNamespace string  `json:"provider_namespace" binding:"required"`
	ProviderName      *string `json:"provider_name"`
	Reason            string  `json:"reason"`
}

// @Summary      Create approval request
// @Description  Create a new mirror provider approval request. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateApprovalRequestRequest  true  "Approval request"
// @Success      201  {object}  models.MirrorApprovalRequest
// @Failure      400  {object}  map[string]interface{}  "Invalid request or mirror config ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/approvals [post]
// CreateApprovalRequest creates a new approval request
// POST /api/v1/admin/approvals
func (h *RBACHandlers) CreateApprovalRequest(c *gin.Context) {
	var req CreateApprovalRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mirrorConfigID, err := uuid.Parse(req.MirrorConfigID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mirror config ID"})
		return
	}

	// GUARD approval-create-config-org (issue #719). The create-axis sibling of
	// the approval list and /:id reads this batch guarded, and it was left
	// unguarded in a subtler way than the others: it names no organization at
	// all, it names a MIRROR CONFIG, and the row's organization was taken from
	// the caller's own ambient context instead of from the config being
	// approved against. So a caller could file an approval request against
	// another organization's mirror configuration and have it stamped with
	// their own organization — the row then reads as theirs to every downstream
	// per-org guard, including POST /admin/approvals/:id/token, which mints a
	// credential redeemable without authentication.
	//
	// The owning organization is resolved from the CONFIG, and the caller must
	// hold mirrors:manage there. Deriving the row's tenancy from the resource
	// it points at, rather than from the requester, is what makes the /:id
	// guards downstream mean anything.
	orgID, ok := h.approvalTargetOrg(c, mirrorConfigID)
	if !ok {
		return
	}

	// Get user ID from context
	var requestedBy *uuid.UUID
	if userIDStr, exists := c.Get("user_id"); exists {
		if idStr, ok := userIDStr.(string); ok {
			if id, err := uuid.Parse(idStr); err == nil {
				requestedBy = &id
			}
		}
	}

	approval := &models.MirrorApprovalRequest{
		ID:                uuid.New(),
		MirrorConfigID:    mirrorConfigID,
		OrganizationID:    orgID,
		RequestedBy:       requestedBy,
		ProviderNamespace: req.ProviderNamespace,
		ProviderName:      req.ProviderName,
		Reason:            req.Reason,
		Status:            models.ApprovalStatusPending,
		AutoApproved:      false,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := h.rbacRepo.CreateApprovalRequest(c.Request.Context(), approval); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create approval request"})
		return
	}

	h.notifyApprovalPending(approval)

	c.JSON(http.StatusCreated, approval)
}

// ReviewApprovalRequest represents the request to review an approval
type ReviewApprovalRequest struct {
	Status string `json:"status" binding:"required"` // "approved" or "rejected"
	Notes  string `json:"notes"`
}

// @Summary      Review approval request
// @Description  Approve or reject a mirror provider approval request. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                 true  "Approval request ID (UUID)"
// @Param        body  body  ReviewApprovalRequest  true  "Review decision (status: approved or rejected)"
// @Success      200  {object}  models.MirrorApprovalRequest
// @Failure      400  {object}  map[string]interface{}  "Invalid ID or status value"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/approvals/{id}/review [put]
// ReviewApproval approves or rejects an approval request
// PUT /api/v1/admin/approvals/:id/review
func (h *RBACHandlers) ReviewApproval(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval request ID"})
		return
	}

	var req ReviewApprovalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	status := models.ApprovalStatus(req.Status)
	if status != models.ApprovalStatusApproved && status != models.ApprovalStatusRejected {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Status must be 'approved' or 'rejected'"})
		return
	}

	// Get reviewer ID from context
	var reviewerID uuid.UUID
	if userIDStr, exists := c.Get("user_id"); exists {
		if idStr, ok := userIDStr.(string); ok {
			if id, err := uuid.Parse(idStr); err == nil {
				reviewerID = id
			}
		}
	}

	if err := h.rbacRepo.UpdateApprovalStatus(c.Request.Context(), id, status, reviewerID, req.Notes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update approval status"})
		return
	}

	// Fetch updated approval
	approval, err := h.rbacRepo.GetApprovalRequest(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get updated approval"})
		return
	}

	c.JSON(http.StatusOK, approval)
}

// ============================================================================
// Mirror Policies
// ============================================================================

// @Summary      List mirror policies
// @Description  List mirror access policies, optionally filtered by organization. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        organization_id  query  string  false  "Filter by organization ID (UUID)"
// @Success      200  {array}   models.MirrorPolicy
// @Failure      400  {object}  map[string]interface{}  "Invalid organization ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies [get]
// ListMirrorPolicies lists all mirror policies
// GET /api/v1/admin/policies
func (h *RBACHandlers) ListMirrorPolicies(c *gin.Context) {
	// GUARD policy-list-tenant-scope (issue #719). Same shape as
	// approval-list-tenant-scope: the organization filter is whatever the caller
	// asked for, so an omitted or foreign organization_id read across tenants.
	// Mirror policies are the allow/deny rules governing what another
	// organization is permitted to mirror.
	scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsRead)
	if !ok {
		return
	}

	var orgID *uuid.UUID
	if orgIDStr := c.Query("organization_id"); orgIDStr != "" {
		id, err := uuid.Parse(orgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
		if !scope.Permits(id.String()) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of the requested organization"})
			return
		}
		orgID = &id
	}

	policies, err := h.rbacRepo.ListMirrorPolicies(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list mirror policies"})
		return
	}

	// GUARD policy-list-unowned-rows (issue #719). A policy with a NULL
	// organization_id is visible to platform administrators only — the same
	// answer middleware.RequireOrgScopeForResource gives on GET /:id of THIS
	// resource ("Resource is not owned by any organization"), and the same
	// answer tenantscope.Scope.Permits gives everywhere else.
	//
	// An earlier revision of this batch let the list axis through on the theory
	// that a NULL policy is a global rule everyone is governed by, while the
	// /:id axis it added in the same diff refused it. That is the #719 defect
	// in miniature: two axes of one resource disagreeing about who owns a row.
	// Whichever reading is right, the two axes must not each pick their own,
	// and between "show it" and "deny it" a remediation takes the closed one:
	// scope.Permits is the single definition, and it says no.
	visible := make([]*models.MirrorPolicy, 0, len(policies))
	for _, p := range policies {
		ownerOrg := ""
		if p.OrganizationID != nil {
			ownerOrg = p.OrganizationID.String()
		}
		if scope.Permits(ownerOrg) {
			visible = append(visible, p)
		}
	}

	c.JSON(http.StatusOK, visible)
}

// @Summary      Get mirror policy
// @Description  Returns a specific mirror access policy by ID. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Policy ID (UUID)"
// @Success      200  {object}  models.MirrorPolicy
// @Failure      400  {object}  map[string]interface{}  "Invalid policy ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Policy not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies/{id} [get]
// GetMirrorPolicy returns a single mirror policy
// GET /api/v1/admin/policies/:id
func (h *RBACHandlers) GetMirrorPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	policy, err := h.rbacRepo.GetMirrorPolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policy"})
		return
	}

	if policy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// CreateMirrorPolicyRequest represents the request to create a mirror policy
type CreateMirrorPolicyRequest struct {
	OrganizationID   *string `json:"organization_id"`
	Name             string  `json:"name" binding:"required"`
	Description      string  `json:"description"`
	PolicyType       string  `json:"policy_type" binding:"required"` // "allow" or "deny"
	UpstreamRegistry *string `json:"upstream_registry"`
	NamespacePattern *string `json:"namespace_pattern"`
	ProviderPattern  *string `json:"provider_pattern"`
	Priority         int     `json:"priority"`
	IsActive         bool    `json:"is_active"`
	RequiresApproval bool    `json:"requires_approval"`
}

// @Summary      Create mirror policy
// @Description  Create a new mirror access policy (allow or deny). Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateMirrorPolicyRequest  true  "Mirror policy"
// @Success      201  {object}  models.MirrorPolicy
// @Failure      400  {object}  map[string]interface{}  "Invalid request or policy type"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies [post]
// CreateMirrorPolicy creates a new mirror policy
// POST /api/v1/admin/policies
func (h *RBACHandlers) CreateMirrorPolicy(c *gin.Context) {
	var req CreateMirrorPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policyType := models.PolicyType(req.PolicyType)
	if policyType != models.PolicyTypeAllow && policyType != models.PolicyTypeDeny {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy type must be 'allow' or 'deny'"})
		return
	}

	// GUARD policy-create-target-org (issue #719). The create-axis sibling of
	// the policy list and /:id reads this batch guarded, and it was left
	// unguarded: organization_id comes off the request body and a
	// mirror_policies row was written under it with no membership check. A
	// mirror policy is an allow/deny rule over what a tenant may mirror, so
	// planting one in another organization silently changes what that
	// organization is permitted to pull.
	//
	// A NULL organization_id (field omitted) means a GLOBAL policy governing
	// every tenant, so resolveTargetOrganization is not the right helper here —
	// it would bind an omitted field to the caller's own organization and
	// quietly change what this endpoint creates. Instead: an explicit
	// organization must be one the caller holds the scope in, and creating a
	// global policy stays a platform-administrator action.
	var orgID *uuid.UUID
	if req.OrganizationID != nil && *req.OrganizationID != "" {
		id, err := uuid.Parse(*req.OrganizationID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
		if !requireTenantScopeForOrg(c, h.orgRepo, auth.ScopeMirrorsManage, id.String()) {
			return
		}
		orgID = &id
	} else {
		scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeMirrorsManage)
		if !ok {
			return
		}
		if !scope.PlatformAdmin {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "organization_id is required: a policy with no organization is a global policy and may only be created by a platform administrator",
			})
			return
		}
	}

	// Get creator ID from context
	var createdBy *uuid.UUID
	if userIDStr, exists := c.Get("user_id"); exists {
		if idStr, ok := userIDStr.(string); ok {
			if id, err := uuid.Parse(idStr); err == nil {
				createdBy = &id
			}
		}
	}

	policy := &models.MirrorPolicy{
		ID:               uuid.New(),
		OrganizationID:   orgID,
		Name:             req.Name,
		Description:      &req.Description,
		PolicyType:       policyType,
		UpstreamRegistry: req.UpstreamRegistry,
		NamespacePattern: req.NamespacePattern,
		ProviderPattern:  req.ProviderPattern,
		Priority:         req.Priority,
		IsActive:         req.IsActive,
		RequiresApproval: req.RequiresApproval,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		CreatedBy:        createdBy,
	}

	if err := h.rbacRepo.CreateMirrorPolicy(c.Request.Context(), policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// @Summary      Update mirror policy
// @Description  Update an existing mirror access policy. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Policy ID (UUID)"
// @Param        body  body  CreateMirrorPolicyRequest  true  "Updated mirror policy"
// @Success      200  {object}  models.MirrorPolicy
// @Failure      400  {object}  map[string]interface{}  "Invalid request, ID, or policy type"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Policy not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies/{id} [put]
// UpdateMirrorPolicy updates an existing mirror policy
// PUT /api/v1/admin/policies/:id
func (h *RBACHandlers) UpdateMirrorPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	existing, err := h.rbacRepo.GetMirrorPolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policy"})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req CreateMirrorPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policyType := models.PolicyType(req.PolicyType)
	if policyType != models.PolicyTypeAllow && policyType != models.PolicyTypeDeny {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy type must be 'allow' or 'deny'"})
		return
	}

	existing.Name = req.Name
	existing.Description = &req.Description
	existing.PolicyType = policyType
	existing.UpstreamRegistry = req.UpstreamRegistry
	existing.NamespacePattern = req.NamespacePattern
	existing.ProviderPattern = req.ProviderPattern
	existing.Priority = req.Priority
	existing.IsActive = req.IsActive
	existing.RequiresApproval = req.RequiresApproval
	existing.UpdatedAt = time.Now()

	if err := h.rbacRepo.UpdateMirrorPolicy(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	c.JSON(http.StatusOK, existing)
}

// @Summary      Delete mirror policy
// @Description  Delete a mirror access policy. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Policy ID (UUID)"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid policy ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies/{id} [delete]
// DeleteMirrorPolicy deletes a mirror policy
// DELETE /api/v1/admin/policies/:id
func (h *RBACHandlers) DeleteMirrorPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	if err := h.rbacRepo.DeleteMirrorPolicy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// EvaluatePolicyRequest represents a request to evaluate policies for a provider
type EvaluatePolicyRequest struct {
	Registry  string `json:"registry" binding:"required"`
	Namespace string `json:"namespace" binding:"required"`
	Provider  string `json:"provider" binding:"required"`
}

// @Summary      Evaluate mirror policies
// @Description  Evaluate all mirror policies for a specific provider to determine if access is allowed or denied. Requires admin scope.
// @Tags         RBAC
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        organization_id  query  string                 false  "Organization ID (UUID) for scoped evaluation"
// @Param        body             body   EvaluatePolicyRequest  true   "Provider to evaluate (registry, namespace, provider)"
// @Success      200  {object}  models.PolicyEvaluationResult
// @Failure      400  {object}  map[string]interface{}  "Invalid request or organization ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/policies/evaluate [post]
// EvaluatePolicy evaluates policies for a given provider
// POST /api/v1/admin/policies/evaluate
func (h *RBACHandlers) EvaluatePolicy(c *gin.Context) {
	var req EvaluatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// GUARD policy-evaluate-tenant-scope: the write axis of this route block is
	// admin-gated and the by-id read axis carries RequireOrgScopeForResource,
	// but this one took organization_id straight off the query string and
	// evaluated against it with no caller check. mirrors:read is granted by the
	// seeded `viewer` template -- the lowest-privilege role in the product -- so
	// the result (matched policy name, allow/deny, requires_approval) was
	// readable across tenants by any member of any organization.
	//
	// Omitting organization_id stays open to every caller: ListMirrorPolicies
	// then matches only `organization_id IS NULL`, the global policies, which
	// are not owned by any tenant. It is supplying someone else's id that has to
	// be earned, so the check hangs off the parameter rather than the route.
	var orgID *uuid.UUID
	if orgIDStr := c.Query("organization_id"); orgIDStr != "" {
		id, err := uuid.Parse(orgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
			return
		}
		if !requireTenantScopeForOrg(c, h.orgRepo, auth.ScopeMirrorsRead, id.String()) {
			return
		}
		orgID = &id
	}

	result, err := h.rbacRepo.EvaluatePolicies(c.Request.Context(), orgID, req.Registry, req.Namespace, req.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to evaluate policies"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ============================================================================
// Webhook Approval Token Generation
// ============================================================================

// ApprovalTokenResponse is returned when a token is generated.
type ApprovalTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	// ApprovalURL is informational — the caller should embed the token in the
	// appropriate webhook URL before sending it to an approver.
	ApprovalURL string `json:"approval_url,omitempty"`
}

// @Summary      Generate webhook approval token
// @Description  Generates a single-use HMAC token that can be sent to an approver via email
//
//	or Slack. When the recipient POSTs the token to /webhooks/approvals/:token the
//	approval request is approved without requiring admin login. Tokens expire after
//	24 hours. Requires mirrors:manage scope.
//
// @Tags         RBAC
// @Security     Bearer
// @Produce      json
// @Param        id    path  string  true  "Approval request ID (UUID)"
// @Success      201  {object}  admin.ApprovalTokenResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid approval request ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — mirrors:manage scope required"
// @Failure      404  {object}  map[string]interface{}  "Approval request not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/approvals/{id}/token [post]
// GenerateApprovalToken creates a single-use approval token for an approval request.
// POST /api/v1/admin/approvals/:id/token
func (h *RBACHandlers) GenerateApprovalToken(c *gin.Context) {
	idStr := c.Param("id")
	approvalID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval request ID"})
		return
	}

	// Verify the approval request exists and is still pending.
	approval, err := h.rbacRepo.GetApprovalRequest(c.Request.Context(), approvalID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval request not found"})
		return
	}
	if approval.Status != models.ApprovalStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Approval request is not pending"})
		return
	}

	// Generate a 32-byte cryptographically random token.
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	plainToken := hex.EncodeToString(rawBytes)

	// Hash before storage — we never store the plain token.
	sum := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(sum[:])

	expiresAt := time.Now().Add(24 * time.Hour)
	if err := h.rbacRepo.CreateApprovalToken(c.Request.Context(), tokenHash, approvalID, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store approval token"})
		return
	}

	c.JSON(http.StatusCreated, ApprovalTokenResponse{
		Token:       plainToken,
		ExpiresAt:   expiresAt,
		ApprovalURL: "/webhooks/approvals/" + plainToken,
	})
}

// platform_admins.go implements the management surface for the platform-admin
// carrier — the grant table that holds platform-admin authority outside
// `organization_members` (issue #766, migration 000051, PR 2 of 3).
//
// PR 1 shipped the table and the per-request read that elevates a session's
// effective scopes from it. Until this file existed the only way to add or
// remove a row was hand-written SQL, which means the highest privilege in the
// product could change hands with nothing in the audit trail saying so. Closing
// that is the point of this PR; the grant/revoke handlers below write an audit
// entry naming the actor, the target and the moment, in addition to the coarse
// route-level entry AuditMiddleware already writes.
//
// AUTHORIZATION IS THE `admin` SCOPE, NOT THE CARRIER DIRECTLY.
// These routes are mounted behind middleware.RequireScope(auth.ScopeAdmin),
// the same gate as /admin/role-templates and the other eleven admin surfaces.
// After PR 1 that scope already means "carrier OR the role-template union", and
// at PR 3 — when authority derives from the carrier alone — it will mean
// "carrier" with no edit here. Gating on the carrier directly instead would
// have bought no security (during the transition a union-only administrator
// still holds `admin` at all twelve other sites, including /admin/role-templates
// where they can mint themselves another one) while creating one real hazard:
// an administrator added by role template between PR 1 and PR 3 would be locked
// out of the only surface that can grant them a carrier row, and the recovery
// would be the SQL this API replaces.
package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
)

// Audit actions written by this file. Dotted, like the rest of the estate's
// hand-written actions ("mirror.created", "provider.delete").
//
// ALIASES, not literals, since issue #766's floor work: migration 000052's
// trigger matches on these exact strings, and the carrier now has callers in
// two other packages (the setup wizard's bootstrap grant, and the lifecycle
// cleanups that retire a destroyed principal's grant). A second spelling
// anywhere is not a wrong audit entry, it is a failed COMMIT, so there is one
// definition — repositories/platform_admin_audit_actions.go — and these names
// stay for the readers of this file.
const (
	auditActionPlatformAdminGranted = repositories.AuditActionPlatformAdminGranted
	auditActionPlatformAdminRevoked = repositories.AuditActionPlatformAdminRevoked
	auditResourcePlatformAdmin      = repositories.AuditResourcePlatformAdmin
)

// maxPlatformAdminNoteLen bounds the operator note. The column is TEXT; the
// limit is here so an unbounded body cannot be parked in the carrier.
const maxPlatformAdminNoteLen = 500

// errLastPlatformAdmin is the refusal from the last-standing guard.
var errLastPlatformAdmin = errors.New("cannot revoke the last platform administrator")

// errIdentityUnavailable marks a failure to resolve a user, as distinct from
// resolving them to "no such user". The two must not collapse: an identity
// store that is down would otherwise read as "every remaining grant is an
// orphan", and the guard would let the final administrator revoke themselves.
var errIdentityUnavailable = errors.New("identity lookup failed")

// PlatformAdminHandlers serves /api/v1/admin/platform-admins.
type PlatformAdminHandlers struct {
	// floor is the deployment-wide administrator-floor lock (issue #766). Only
	// its Serialize is used: the last-standing REFUSAL below is this file's
	// own, and is deliberately stricter than the floor's. What the lock adds is
	// ordering against the membership paths, which the FOR UPDATE on
	// platform_admins cannot reach -- without it, a carrier revoke and a
	// role-template demotion could each observe the other's administrator still
	// standing and both commit. May be nil in tests.
	floor *adminfloor.Guard
	// carrier is the platform_admins table, on the REGISTRY's connection.
	carrier *repositories.PlatformAdminRepository
	// userRepo resolves a grant's user_id to a person. It lives on the IDENTITY
	// connection, which is why the carrier carries no foreign key to users
	// (migration 000051) and why resolution is a lookup here rather than a join
	// there.
	userRepo *repositories.UserRepository
	// outbox records the grant/revoke trail. It is on the REGISTRY connection,
	// beside the carrier, so the record commits in the same transaction as the
	// mutation; the relay delivers it to audit_logs on the identity connection
	// afterwards (issue #766, migration 000052).
	outbox *audit.Outbox
}

// NewPlatformAdminHandlers constructs the handlers.
func NewPlatformAdminHandlers(carrier *repositories.PlatformAdminRepository, userRepo *repositories.UserRepository, outbox *audit.Outbox) *PlatformAdminHandlers {
	return &PlatformAdminHandlers{carrier: carrier, userRepo: userRepo, outbox: outbox}
}

// WithAdminFloor attaches the deployment-wide administrator-floor lock
// (issue #766).
func (h *PlatformAdminHandlers) WithAdminFloor(g *adminfloor.Guard) *PlatformAdminHandlers {
	h.floor = g
	return h
}

// userResolver resolves user ids to people, memoised for the duration of one
// request so a list whose grants share a grantor does not re-read the same row.
//
// A miss is cached as a nil user and reported as (nil, nil) — "resolved to
// nobody". A FAILURE is never cached and is returned as an error, so the
// callers can keep the two apart.
type userResolver struct {
	repo *repositories.UserRepository
	seen map[string]*models.User
}

func newUserResolver(repo *repositories.UserRepository) *userResolver {
	return &userResolver{repo: repo, seen: map[string]*models.User{}}
}

func (u *userResolver) get(ctx context.Context, id string) (*models.User, error) {
	if id == "" {
		return nil, nil
	}
	if cached, ok := u.seen[id]; ok {
		return cached, nil
	}
	if u.repo == nil {
		return nil, fmt.Errorf("%w: no user repository wired", errIdentityUnavailable)
	}
	user, err := u.repo.GetUserByID(ctx, id, repositories.OrgScopeAllOrganizations())
	if identityerr.Missing(user, err) {
		u.seen[id] = nil
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errIdentityUnavailable, err)
	}
	u.seen[id] = user
	return user, nil
}

// toItem renders one grant, resolving the holder and the grantor.
//
// ORPHAN GRANTS ARE SHOWN, FLAGGED — not hidden, and not rendered as a nameless
// ghost. The carrier has no foreign key to users (migration 000051: identity
// data may live in another schema or another database entirely), so deleting a
// user leaves the grant row behind. Dropping it from the listing would hide a
// row from the only surface that can remove it; showing it unlabelled would
// read as a corrupt record. `user_resolved: false` says exactly what is true —
// there is a grant, and nobody answers to it — which is the same choice
// migration 000050 made for orphaned api_keys: keep the row visible to an
// operator rather than make it disappear.
func (h *PlatformAdminHandlers) toItem(ctx context.Context, res *userResolver, g repositories.PlatformAdminGrant) (PlatformAdminItem, error) {
	item := PlatformAdminItem{
		UserID:    g.UserID,
		GrantedBy: g.GrantedBy,
		GrantedAt: g.GrantedAt,
		Note:      g.Note,
	}
	holder, err := res.get(ctx, g.UserID)
	if err != nil {
		return PlatformAdminItem{}, err
	}
	if holder != nil {
		item.UserResolved = true
		item.Email = holder.Email
		item.Name = holder.Name
	}
	if g.GrantedBy != nil {
		grantor, err := res.get(ctx, *g.GrantedBy)
		if err != nil {
			return PlatformAdminItem{}, err
		}
		if grantor != nil {
			item.GrantedByEmail = grantor.Email
		}
	}
	return item, nil
}

// @Summary      List platform administrators
// @Description  List every platform-admin grant, with its provenance. A grant whose user no longer resolves is returned with user_resolved=false rather than hidden. Requires admin scope.
// @Tags         Platform Admins
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Success      200  {object}  admin.ListPlatformAdminsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/platform-admins [get]
// ListPlatformAdmins returns every carrier row.
// GET /api/v1/admin/platform-admins
func (h *PlatformAdminHandlers) ListPlatformAdmins(c *gin.Context) {
	grants, err := h.carrier.List(c.Request.Context())
	if err != nil {
		slog.Error("failed to list platform admins", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list platform administrators"})
		return
	}

	res := newUserResolver(h.userRepo)
	items := make([]PlatformAdminItem, 0, len(grants))
	for _, g := range grants {
		item, err := h.toItem(c.Request.Context(), res, g)
		if err != nil {
			slog.Error("failed to resolve platform admin identities", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve platform administrator identities"})
			return
		}
		items = append(items, item)
	}
	c.JSON(http.StatusOK, ListPlatformAdminsResponse{PlatformAdmins: items})
}

// GrantPlatformAdminRequest is the body of POST /api/v1/admin/platform-admins.
type GrantPlatformAdminRequest struct {
	// UserID is the principal to grant platform-admin authority to.
	UserID string `json:"user_id" binding:"required"`
	// Note is a free-text operator note recorded alongside the grant.
	Note string `json:"note"`
}

// @Summary      Grant platform admin
// @Description  Grant platform-admin authority to a user and record who granted it. Requires admin scope.
// @Tags         Platform Admins
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        request  body  admin.GrantPlatformAdminRequest  true  "Grant request"
// @Success      201  {object}  admin.PlatformAdminResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      409  {object}  map[string]interface{}  "User already holds platform-admin"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/platform-admins [post]
// GrantPlatformAdmin adds a carrier row.
// POST /api/v1/admin/platform-admins
func (h *PlatformAdminHandlers) GrantPlatformAdmin(c *gin.Context) {
	var req GrantPlatformAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}
	targetID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be a UUID"})
		return
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > maxPlatformAdminNoteLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("note must be at most %d characters", maxPlatformAdminNoteLen)})
		return
	}

	// GUARD platform-admin-grant-target-exists. Granting to a UUID that resolves
	// to nobody would mint an orphan row on purpose: inert (the middlewares load
	// the user before consulting the carrier) but indistinguishable, later, from
	// a grant whose user was deleted afterwards. Refusing here keeps the orphan
	// class down to the one cause the schema genuinely cannot prevent.
	res := newUserResolver(h.userRepo)
	target, err := res.get(c.Request.Context(), targetID.String())
	if err != nil {
		slog.Error("failed to resolve platform-admin grant target", "error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve user"})
		return
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var grantedBy *string
	if actor := c.GetString("user_id"); actor != "" {
		grantedBy = &actor
	}
	var notePtr *string
	if note != "" {
		notePtr = &note
	}

	// The audit intent travels INTO the mutation's transaction. There is no
	// "grant succeeded but the audit write failed" branch below any more,
	// because that combination can no longer commit.
	grant, err := h.carrier.Grant(c.Request.Context(), targetID.String(), grantedBy, notePtr,
		h.auditIntent(c, auditActionPlatformAdminGranted, targetID.String(), map[string]interface{}{
			"target_user_id":    targetID.String(),
			"target_user_email": target.Email,
			"note":              note,
		}))
	if errors.Is(err, repositories.ErrAlreadyPlatformAdmin) {
		c.JSON(http.StatusConflict, gin.H{"error": "User already holds platform-admin"})
		return
	}
	if unaudited(err) {
		slog.Error("refused to grant platform admin: the change could not be recorded",
			"error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": errUnauditableMutation})
		return
	}
	if err != nil {
		slog.Error("failed to grant platform admin", "error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to grant platform administrator"})
		return
	}

	item, err := h.toItem(c.Request.Context(), res, *grant)
	if err != nil {
		// The grant landed and is audited; only the display enrichment failed.
		// Report what is certainly true rather than a 500 that invites a retry
		// which would then 409.
		slog.Error("granted platform admin but failed to render it", "error", err, "target_user_id", grant.UserID)
		item = PlatformAdminItem{UserID: grant.UserID, GrantedBy: grant.GrantedBy, GrantedAt: grant.GrantedAt, Note: grant.Note}
	}
	c.JSON(http.StatusCreated, PlatformAdminResponse{PlatformAdmin: item})
}

// @Summary      Revoke platform admin
// @Description  Remove a user's platform-admin authority. Refuses to remove the last remaining administrator. Self-revocation is permitted, subject to that same rule. Requires admin scope.
// @Tags         Platform Admins
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        user_id  path  string  true  "User ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid user ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — admin scope required"
// @Failure      404  {object}  map[string]interface{}  "User does not hold platform-admin"
// @Failure      409  {object}  map[string]interface{}  "Cannot revoke the last platform administrator"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/platform-admins/{user_id} [delete]
// RevokePlatformAdmin removes a carrier row.
// DELETE /api/v1/admin/platform-admins/{user_id}
//
// SELF-REVOCATION IS ALLOWED, subject to the last-standing guard. Two reasons.
// The hazard being defended against is a deployment reaching ZERO
// administrators, and the guard below addresses exactly that, for a self-revoke
// as for any other — so a separate "not yourself" rule would forbid nothing
// dangerous. And forbidding it would make standing down require a second live
// administrator to do it for you, which is the same single-point-of-failure
// shape in the other direction: an operator who wants to drop a privilege they
// should no longer hold would have to keep holding it.
func (h *PlatformAdminHandlers) RevokePlatformAdmin(c *gin.Context) {
	targetID, err := uuid.Parse(strings.TrimSpace(c.Param("user_id")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be a UUID"})
		return
	}

	// GUARD admin-floor-serialization (issue #766). The refusal itself is
	// unchanged -- requireAnotherExercisableAdmin under FOR UPDATE, PR #862 --
	// and is not delegated to the floor, which is deliberately more permissive
	// here (it would accept a role-template administrator as the one who
	// remains). Only the ORDERING is new: the row lock below serialises this
	// revoke against another revoke, but not against a demotion committed on
	// the identity connection, so the two could each see the other's
	// administrator still standing.
	res := newUserResolver(h.userRepo)

	// Resolved BEFORE the revocation, because the audit intent is now written
	// inside the revoking transaction and has to be complete by then. A lookup
	// failure leaves the address empty rather than blocking the revocation —
	// the same tolerance the post-hoc write had, and unrelated to the
	// last-standing guard's own refusal to proceed on an unresolved answer.
	targetEmail := ""
	if user, uerr := res.get(c.Request.Context(), targetID.String()); uerr == nil && user != nil {
		targetEmail = user.Email
	}

	// GUARD admin-floor-serialization (issue #766). The refusal itself is
	// unchanged -- requireAnotherExercisableAdmin under FOR UPDATE, PR #862 --
	// and is not delegated to the floor, which is deliberately more permissive
	// here (it would accept a role-template administrator as the one who
	// remains). Only the ORDERING is new: the row lock inside Revoke serialises
	// this revoke against another revoke, but not against a membership demotion
	// committed on the identity connection, so the two could each see the
	// other's administrator still standing.
	//
	// THE FLOOR'S LOCK AND THE AUDIT INTENT DO NOT INTERACT. Serialize holds a
	// write-free transaction open on the registry connection purely to scope
	// pg_advisory_xact_lock; Revoke opens its OWN transaction, on its own
	// pooled connection, and that is the one migration 000052's trigger
	// examines for a matching pg_current_xact_id(). Nesting the revoke inside
	// the lock therefore changes neither the intent nor the trigger's answer.
	err = h.floor.Serialize(c.Request.Context(), func(ctx context.Context) error {
		_, revokeErr := h.carrier.Revoke(ctx, targetID.String(), func(ctx context.Context, remaining []repositories.PlatformAdminGrant) error {
			return h.requireAnotherExercisableAdmin(ctx, res, remaining)
		}, h.auditIntent(c, auditActionPlatformAdminRevoked, targetID.String(), map[string]interface{}{
			"target_user_id":    targetID.String(),
			"target_user_email": targetEmail,
			"self_revocation":   c.GetString("user_id") == targetID.String(),
		}))
		return revokeErr
	})
	switch {
	case errors.Is(err, adminfloor.ErrIndeterminate):
		slog.Error("failed to serialize the platform-admin revoke", "error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify remaining platform administrators"})
		return
	case errors.Is(err, repositories.ErrNotPlatformAdmin):
		c.JSON(http.StatusNotFound, gin.H{"error": "User does not hold platform-admin"})
		return
	case errors.Is(err, errLastPlatformAdmin):
		c.JSON(http.StatusConflict, gin.H{
			"error":   "Cannot revoke the last platform administrator",
			"details": "Grant platform-admin to another user first; a deployment with no platform administrator cannot be recovered through this API.",
		})
		return
	case errors.Is(err, errIdentityUnavailable):
		// Deliberately NOT a revocation. The guard could not establish that
		// another administrator remains, and an unresolved answer must not be
		// served as a yes.
		slog.Error("failed to verify remaining platform admins", "error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify remaining platform administrators"})
		return
	case unaudited(err):
		slog.Error("refused to revoke platform admin: the change could not be recorded",
			"error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": errUnauditableMutation})
		return
	case err != nil:
		slog.Error("failed to revoke platform admin", "error", err, "target_user_id", targetID.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke platform administrator"})
		return
	}

	c.JSON(http.StatusOK, MessageResponse{Message: "Platform administrator revoked"})
}

// requireAnotherExercisableAdmin is the last-standing predicate handed to
// PlatformAdminRepository.Revoke (GUARD platform-admin-last-standing).
//
// It accepts as soon as ONE remaining grant resolves to a live user. A grant
// that resolves to nobody is skipped rather than counted, because it cannot be
// exercised: both auth middlewares load the user and abort before reaching the
// carrier, so an orphan row is a record, not an administrator. Counting rows
// instead would let the final real administrator revoke themselves whenever a
// deleted colleague's grant was still on the table.
//
// A lookup FAILURE aborts rather than skipping. Treating an unreachable
// identity store as "this one does not count" would turn an outage into the
// lockout the guard exists to prevent.
func (h *PlatformAdminHandlers) requireAnotherExercisableAdmin(ctx context.Context, res *userResolver, remaining []repositories.PlatformAdminGrant) error {
	for _, g := range remaining {
		user, err := res.get(ctx, g.UserID)
		if err != nil {
			return err
		}
		if user != nil {
			return nil
		}
	}
	return errLastPlatformAdmin
}

// errUnauditableMutation is what a caller is told when the change was refused
// because it could not be recorded. Distinct from a generic failure on purpose:
// a retry will not help until the audit outbox is reachable, and the operator
// needs to know the privilege did NOT change hands.
const errUnauditableMutation = "Refused: the change could not be recorded in the audit trail, so it was not made"

// unaudited reports whether err is a refusal to proceed unrecorded, as opposed
// to an ordinary failure of the mutation itself.
func unaudited(err error) bool {
	return errors.Is(err, repositories.ErrAuditIntentRequired) ||
		errors.Is(err, audit.ErrNoOutbox) ||
		errors.Is(err, audit.ErrIntentIncomplete)
}

// auditIntent builds the audit record for a grant or revoke and returns it as
// the writer the carrier repository runs INSIDE the mutation's transaction.
//
// TRANSACTIONAL, not "written afterwards and hoped for" (issue #766, migration
// 000052). This is the record the whole design exists to produce, and the
// previous version of it — a second write, on a second connection, after the
// mutation had already committed — could fail while the mutation still reported
// success. Now the record is an audit_outbox row on the SAME connection as the
// carrier: it commits with the grant or neither commits, migration 000052's
// deferred constraint trigger refuses the commit if it is missing, and the
// relay (internal/audit) delivers it to audit_logs afterwards, at least once
// and idempotently.
//
// organization_id is left NULL deliberately: platform-admin is not an
// organization-owned fact, and audit_logs' platform-wide scope
// (OrgScopeAllOrganizations, which every platform administrator's audit read
// uses) admits NULL-owner rows, so the entry is readable by the principals
// entitled to review it.
//
// The actor's address is captured HERE rather than resolved at delivery, so an
// actor deleted between the grant and its delivery is still named. Absent it,
// the sink falls back to resolving it, exactly as the identity store's own
// insert does.
func (h *PlatformAdminHandlers) auditIntent(c *gin.Context, action, targetUserID string, metadata map[string]interface{}) repositories.AuditIntentWriter {
	resourceType := auditResourcePlatformAdmin
	ip := c.ClientIP()
	intent := &audit.Intent{
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &targetUserID,
		IPAddress:    &ip,
		Metadata:     metadata,
	}
	if actor := c.GetString("user_id"); actor != "" {
		intent.ActorUserID = &actor
	}
	if actor, ok := c.Get("user"); ok {
		if u, ok := actor.(*models.User); ok && u != nil && u.Email != "" {
			email := u.Email
			intent.ActorEmail = &email
		}
	}
	return func(ctx context.Context, tx *sql.Tx) error {
		return h.outbox.Enqueue(ctx, tx, intent)
	}
}

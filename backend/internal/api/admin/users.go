// users.go implements handlers for user account CRUD operations including listing, creating, updating, and deleting users.
package admin

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
)

// UserHandlers handles user management endpoints
type UserHandlers struct {
	cfg      *config.Config
	db       *sql.DB
	userRepo *repositories.UserRepository
	orgRepo  *repositories.OrganizationRepository
	// creds invalidates the credential families a deleted principal would
	// otherwise leave behind. May be nil in tests; the sweep is skipped.
	creds *credlifecycle.Sweeper
	// floor holds the never-zero administrator invariants across a principal
	// deletion (issue #766). May be nil in tests; see WithUserAdminFloor.
	floor *adminfloor.Guard
	// carrier removes the deleted principal's platform_admins row. Migration
	// 000051 declines the foreign key that would do this in SQL -- identity
	// data may live in another schema or another database -- so the row would
	// otherwise outlive its user, inert but indistinguishable from a live
	// grant to anything counting rows. May be nil in tests.
	carrier *platformadmin.Carrier
	// outbox carries the audit intent for that retirement into the deleting
	// transaction; migration 000052's constraint trigger refuses the commit
	// without one.
	outbox *auditoutbox.Outbox
	// scmTokens destroys the deleted principal's SCM OAuth tokens. Migration
	// 000056 drops the ON DELETE CASCADE that used to do this (issue #883):
	// scm_oauth_tokens lives on the registry's own connection while users may
	// live in another schema or another database, so no foreign key can span
	// them. Deliberately a REGISTRY-connection repository, unlike every other
	// field here -- see WithUserSCMTokens. May be nil in tests.
	scmTokens *repositories.SCMRepository
}

// UserHandlersOption configures optional UserHandlers dependencies.
type UserHandlersOption func(*UserHandlers)

// userAxisScope resolves the tenancy this caller may act in on the /users
// family, in the spelling the user-axis accessors want.
//
// The whole family used to pass OrgScopeAllOrganizations(). Every route in it is
// gated on the FLAT users:read / users:write scope, and those are granted by the
// per-organization user_manager and org_owner role templates, then unioned
// org-lessly into the JWT (#652) -- so a role holder in organization A read and
// wrote users whose only memberships were in organizations they belong to
// nowhere. On GET /users/:id the disclosed field was the user's organization
// list itself: the owning tenant was both the thing being protected and the
// thing being handed out (identity #161).
//
// .WithUnowned() is deliberate and is the one widening here. A user is tenant-
// scoped through organization_members, so a user with NO memberships matches no
// organization scope and would 404 for every non-platform-admin -- including the
// caller who just created them, since POST /users leaves a user membership-less
// until they are added to an organization. There is no tenant boundary to cross
// on such a user, which is the same call terraform-state-manager's
// requireSharedOrgAdminWithTargetUser makes, and identity documents
// .WithUnowned() as the spelling for exactly this case.
//
// GUARD users-family-tenant-scope (identity #161): the /users routes address
// only users sharing an organization with the caller, plus the unowned.
func userAxisScope(c *gin.Context, orgRepo *repositories.OrganizationRepository, required auth.Scope) (repositories.OrgScope, bool) {
	scope, ok := resolveTenantScope(c, orgRepo, required)
	if !ok {
		return repositories.OrgScope{}, false
	}
	return scope.OrgScope().WithUnowned(), true
}

// WithUserCredentialSweeper wires the credential sweeper used when a principal
// is deleted.
func WithUserCredentialSweeper(s *credlifecycle.Sweeper) UserHandlersOption {
	return func(h *UserHandlers) { h.creds = s }
}

// WithUserSCMTokens wires the repository that destroys a deleted principal's
// SCM OAuth tokens (issue #883).
//
// The argument MUST be built on the registry's own connection, not the identity
// one every other dependency of these handlers uses. scm_oauth_tokens is a
// registry feature table; it does not move to the identity schema at cutover,
// and reading it through the identity pool would resolve a table that is not
// there. This is the deliberate exception to the wiring rule that
// internal/api/identity_db_wiring_test.go enforces -- SCMRepository is not an
// identity repository constructor, so the guard does not claim it.
func WithUserSCMTokens(r *repositories.SCMRepository) UserHandlersOption {
	return func(h *UserHandlers) { h.scmTokens = r }
}

// WithUserAdminFloor wires the never-zero administrator guard, the
// platform-admin carrier, and the audit outbox that carrier writes through
// (issue #766).
//
// One option rather than three: the carrier read the floor makes, the carrier
// row the delete removes, and the intent that removal must commit with are the
// same fact seen three ways. A deployment that wired one without the others
// would either count a grant it was about to strand, or fail its commit against
// migration 000052's trigger.
func WithUserAdminFloor(floor *adminfloor.Guard, carrier *platformadmin.Carrier, outbox *auditoutbox.Outbox) UserHandlersOption {
	return func(h *UserHandlers) {
		h.floor = floor
		h.carrier = carrier
		h.outbox = outbox
	}
}

// NewUserHandlers creates a new UserHandlers instance
func NewUserHandlers(cfg *config.Config, db *sql.DB, opts ...UserHandlersOption) *UserHandlers {
	h := &UserHandlers{
		cfg:      cfg,
		db:       db,
		userRepo: repositories.NewUserRepository(db),
		orgRepo:  repositories.NewOrganizationRepository(db),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// noFloorTheDeleteAlreadyCleared is the explicit "this call site has no floor"
// predicate. Named, so a reader of Revoke's argument list sees a decision
// rather than an omission: the floor ran in the delete handler, under its lock,
// against the state this cleanup follows.
func noFloorTheDeleteAlreadyCleared(context.Context, []platformadmin.Grant) error { return nil }

// deleteSCMTokens destroys a principal's SCM OAuth tokens before the principal
// itself is deleted, and reports whether the caller may proceed. It writes its
// own error response when it returns false.
//
// Nil repository means the dependency was not wired (tests, and any caller that
// predates issue #883); that is a no-op rather than a refusal, matching how
// h.creds and h.carrier behave.
func (h *UserHandlers) deleteSCMTokens(c *gin.Context, userID string) bool {
	if h.scmTokens == nil {
		return true
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		// Not reachable through the routes -- the id was already used to load
		// the user -- but a non-UUID here would silently sweep nothing, so it
		// fails rather than passing.
		slog.Error("cannot sweep SCM tokens for a non-UUID user id", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to revoke the user's SCM credentials; user was not deleted",
		})
		return false
	}
	n, err := h.scmTokens.DeleteAllUserTokens(c.Request.Context(), uid)
	if err != nil {
		slog.Error("failed to delete a principal's SCM OAuth tokens; refusing to delete the principal",
			"user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to revoke the user's SCM credentials; user was not deleted",
		})
		return false
	}
	if n > 0 {
		slog.Info("deleted a principal's SCM OAuth tokens", "user_id", userID, "tokens_deleted", n)
	}
	return true
}

// revokePlatformAdminCarrier removes a destroyed principal's platform_admins
// row (issue #766).
//
// The carrier carries no foreign key to users -- migration 000051 explains at
// length why it cannot -- so nothing in the schema retires this row when its
// user goes away. It is inert either way, but an inert row that still looks
// like a grant is what would let the LAST real administrator be removed
// against a count of two, so the floor and the management API both have to
// keep skipping it forever. Deleting it keeps the carrier honest instead.
//
// The last-standing predicate accepts unconditionally, stated in one explicit
// line (noFloorTheDeleteAlreadyCleared) rather than passed as nil: this is not
// an operator revoking a live administrator, it is cleanup after a delete the
// floor has already cleared, and re-checking here would refuse to tidy up the
// very row the floor just discounted. The carrier refuses a nil predicate
// outright, because "no predicate" is the one way the floor can be silently
// absent.
//
// The AUDIT INTENT is mandatory, not optional in the same way. Migration
// 000052's deferred constraint trigger refuses any commit that deletes a
// carrier row without a matching intent, so this carries one — with the action
// the trigger pins, and metadata saying the grant went because its principal
// was deleted rather than because an operator revoked it.
//
// Best-effort. The user is already gone; a failure leaves an orphan the
// management API renders as user_resolved=false, which is exactly what it is.
func (h *UserHandlers) revokePlatformAdminCarrier(c *gin.Context, userID string) {
	if h.carrier == nil {
		return
	}
	resourceType := platformadmin.AuditResourceType
	target := userID
	ip := c.ClientIP()
	intent := &auditoutbox.Intent{
		Action:       platformadmin.AuditActionRevoked,
		ResourceType: &resourceType,
		ResourceID:   &target,
		IPAddress:    &ip,
		Metadata: map[string]interface{}{
			"target_user_id": userID,
			"reason":         "user deleted by administrator",
		},
	}
	if actor := c.GetString("user_id"); actor != "" {
		intent.ActorUserID = &actor
	}

	_, err := h.carrier.Revoke(c.Request.Context(), userID, noFloorTheDeleteAlreadyCleared, func(ctx context.Context, tx *sql.Tx) error {
		return h.outbox.Enqueue(ctx, tx, intent)
	})
	if err == nil {
		slog.Info("removed the platform-admin grant of a deleted principal", "user_id", userID)
		return
	}
	if errors.Is(err, platformadmin.ErrNotPlatformAdmin) {
		return // the ordinary case: most principals hold no grant
	}
	slog.Error("failed to remove a deleted principal's platform-admin grant; it survives as an orphan",
		"user_id", userID, "error", err)
}

// @Summary      List users
// @Description  Get a paginated list of all users with their organization role templates. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        page      query  int  false  "Page number (default 1)"
// @Param        per_page  query  int  false  "Items per page, max 100 (default 20). A larger value is served as 100."
// @Success      200  {object}  admin.ListUsersResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users [get]
// ListUsersHandler lists all users with pagination
// GET /api/v1/users?page=1&per_page=20
func (h *UserHandlers) ListUsersHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// GUARD per-page-clamps-to-max (issue #893). The organization list's
		// clamp, copy-pasted: `?per_page=200` served 20 users.
		page := pagination.ClampPage(queryInt(c, "page"))
		perPage := pagination.ClampPerPage(queryInt(c, "per_page"), userPerPageDefault, userPerPageMax)
		offset := pagination.Offset(page, perPage)

		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
		if !ok {
			return
		}

		// Get users with memberships (2 queries total, not N+1)
		users, total, err := h.userRepo.ListUsersWithMemberships(c.Request.Context(), perPage, offset, scope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list users",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"users":      users,
			"pagination": countedPage(page, perPage, offset, len(users), total),
		})
	}
}

// @Summary      Get user
// @Description  Get a user by ID with their organization memberships. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  admin.UserWithOrgsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id} [get]
// GetUserHandler retrieves a specific user by ID
// GET /api/v1/users/:id
func (h *UserHandlers) GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
		if !ok {
			return
		}

		// Out of scope is 404, not 403: on this route the organization list IS
		// the disclosed field, so answering "exists, but not yours" would leak
		// the membership the scope exists to withhold. Indistinguishable from a
		// user id that was never issued.
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID, scope)
		if identityerr.Missing(user, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		// Get user's organizations -- the same scope, so a shared user's
		// memberships elsewhere stay withheld even though the user is visible.
		orgs, err := h.orgRepo.GetUserOrganizations(c.Request.Context(), userID, scope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user organizations",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user":          user,
			"organizations": orgs,
		})
	}
}

// CreateUserRequest represents the request to create a new user
type CreateUserRequest struct {
	Email   string  `json:"email" binding:"required,email"`
	Name    string  `json:"name" binding:"required"`
	OIDCSub *string `json:"oidc_sub"`
}

// @Summary      Create user
// @Description  Create a new user. Typically users are created via OIDC; this endpoint is for admin use. Requires users:write scope.
// @Tags         Users
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateUserRequest  true  "User creation request"
// @Success      201  {object}  admin.UserResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "User with this email already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users [post]
// CreateUserHandler creates a new user (admin only, typically users are created via OIDC)
// POST /api/v1/users
func (h *UserHandlers) CreateUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		// Check if user already exists.
		//
		// Existence probe: not-found is the SUCCESS case. A bare
		// `err != nil -> 500` would make creating ANY new user impossible,
		// because every new user's email is by definition not yet taken.
		existingUser, err := h.userRepo.GetUserByEmail(c.Request.Context(), req.Email)
		switch {
		case identityerr.Missing(existingUser, err):
			// Email is free — fall through and create.
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing user",
			})
			return
		default:
			c.JSON(http.StatusConflict, gin.H{
				"error": "User with this email already exists",
			})
			return
		}

		// Create user
		user := &models.User{
			Email:   req.Email,
			Name:    req.Name,
			OIDCSub: req.OIDCSub,
		}

		if err := h.userRepo.CreateUser(c.Request.Context(), user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create user",
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"user": user,
		})
	}
}

// UpdateUserRequest represents the request to update a user
// Note: Role templates are now assigned per-organization via organization memberships
type UpdateUserRequest struct {
	Name  *string `json:"name"`
	Email *string `json:"email,omitempty"`
}

// @Summary      Update user
// @Description  Update a user's name or email. Requires users:write scope.
// @Tags         Users
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string             true  "User ID"
// @Param        body  body  UpdateUserRequest  true  "User update request"
// @Success      200  {object}  admin.UserResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      409  {object}  map[string]interface{}  "Email already in use by another user"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id} [put]
// UpdateUserHandler updates a user
// PUT /api/v1/users/:id
func (h *UserHandlers) UpdateUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		var req UpdateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersWrite)
		if !ok {
			return
		}

		// Get existing user
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID, scope)
		if identityerr.Missing(user, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		// Update fields
		if req.Name != nil {
			user.Name = *req.Name
		}

		if req.Email != nil {
			// Availability probe: not-found means the address is FREE, which is
			// the ordinary case for a user changing their email. Note the
			// existing carve-out for re-submitting one's OWN address is
			// preserved — it lives in the default branch below.
			existingUser, err := h.userRepo.GetUserByEmail(c.Request.Context(), *req.Email)
			switch {
			case identityerr.Missing(existingUser, err):
				// Email is free — fall through and apply.
			case err != nil:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check email availability",
				})
				return
			default:
				if existingUser.ID != userID {
					c.JSON(http.StatusConflict, gin.H{
						"error": "Email already in use by another user",
					})
					return
				}
			}

			user.Email = *req.Email
		}

		// Update in database
		// Raced against a concurrent delete: 404, matching the existence
		// pre-check at the top of this handler, instead of the false 200 the
		// pre-v0.24.0 contract returned for an update that changed nothing.
		// Same scope as the pre-check, so the row written is the row authorized:
		// a membership removed between the two turns this into the 404 above
		// rather than a write the caller is no longer entitled to make.
		if err := h.userRepo.UpdateUser(c.Request.Context(), user, scope); err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "User not found",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update user",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
	}
}

// @Summary      Delete user
// @Description  Delete a user by ID. Cascading deletes will handle related records. Requires users:write scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      409  {object}  map[string]interface{}  "Would leave no administrator"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id} [delete]
// DeleteUserHandler deletes a user
// DELETE /api/v1/users/:id
func (h *UserHandlers) DeleteUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersWrite)
		if !ok {
			return
		}

		// Check if user exists
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID, scope)
		if identityerr.Missing(user, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		// Sweep the principal's credentials BEFORE the row goes away.
		//
		// It is tempting to rely on the FK cascade here, and the registry's own
		// legacy schema does declare api_keys.user_id ON DELETE CASCADE
		// (internal/db/migrations/000001_initial_schema.up.sql). The shared
		// identity schema -- which is what the identity connection actually
		// serves, and which owns this table in the shared-database deployment
		// mode -- declares the opposite:
		//
		//	identity.api_keys.user_id UUID REFERENCES identity.users(id) ON DELETE SET NULL
		//
		// So deleting a principal DETACHES its API keys rather than destroying
		// them, and a detached key is worse than an orphan: it is an org-bound
		// key with a NULL user_id, which is exactly the shape
		// NamespaceAuthorizer.verifyKeyOwnerAuthority reads as an organization
		// SERVICE credential and exempts from any membership check. Deleting a
		// user would silently promote their personal keys to unattributable,
		// permanently valid org credentials.
		//
		// The sweep must therefore run first: after the delete there is no
		// user_id left to find the rows by. If the delete then fails the user
		// keeps their account but loses their credentials -- the fail-closed
		// direction, and recoverable by re-issuing keys.
		if h.creds != nil {
			// Platform-wide, deliberately: the principal itself is about to be
			// destroyed, so a key left standing in ANY organization outlives its
			// owner. That is the stranded-credential shape (#736), and after the
			// row is gone there is no user_id left to find it by.
			out := h.creds.UserDeprovisioned(c.Request.Context(), userID,
				repositories.OrgScopeAllOrganizations(), "user deleted by administrator")
			if out.Incomplete {
				slog.Error("credential sweep incomplete before user deletion; deleting anyway would detach surviving keys",
					"user_id", userID)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to revoke the user's credentials; user was not deleted",
				})
				return
			}
		}

		// Same sweep, second credential family. Runs here rather than after the
		// delete for the same fail-closed reason as the block above, and it is a
		// separate call because the rows live on a different connection: the
		// sweeper above holds identity repositories, scm_oauth_tokens is the
		// registry's own table. Failure aborts the delete -- these are live SCM
		// credentials, and a principal that keeps its account keeps them
		// legitimately, whereas a principal that loses its account and keeps
		// them is exactly the orphan #732/#736 were about.
		if !h.deleteSCMTokens(c, userID) {
			return
		}

		// Delete user (cascading deletes will handle related records).
		// Already gone: 404, the same answer the existence pre-check gives a
		// second DELETE, so both routes to "no such user" agree.
		// Scoped like the pre-check above. The credential sweep just before it is
		// deliberately NOT -- see its own comment: the principal is being
		// destroyed, so a key surviving in any organization outlives its owner.
		// Authorization is tenant-scoped; the cleanup that follows from it is
		// whole-principal, and the two are different questions.
		//
		// GUARD admin-floor (issue #766). Deleting a principal takes away every
		// membership it holds -- by FK cascade, so no membership statement
		// appears here at all -- and makes its platform_admins row inert without
		// deleting it. Both invariants are therefore in play, and the change is
		// DestroysPrincipal so the floor stops counting this user's own carrier
		// grant as an administrator who remains.
		err = h.floor.Protect(c.Request.Context(), adminfloor.Change{
			UserID:            userID,
			RemovesMembership: true,
			DestroysPrincipal: true,
		}, func(ctx context.Context) error {
			return h.userRepo.DeleteUser(ctx, userID, scope)
		})
		if respondAdminFloor(c, err) {
			return
		}
		if err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "User not found",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete user",
			})
			return
		}

		// The carrier row the missing foreign key leaves behind. Removed AFTER
		// the delete, not before: a failure here leaves a grant naming a user
		// that no longer exists, which every consumer already treats as inert
		// (both middlewares load the user first, and the management API renders
		// it as user_resolved=false), whereas removing it first and then
		// failing the delete would silently strip a live administrator's
		// authority. Best-effort and logged, like the credential sweep.
		h.revokePlatformAdminCarrier(c, userID)

		c.JSON(http.StatusOK, gin.H{
			"message": "User deleted successfully",
		})
	}
}

// @Summary      Search users
// @Description  Search users by email or name. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        q         query  string  true   "Search query"
// @Param        page      query  int     false  "Page number (default 1)"
// @Param        per_page  query  int     false  "Items per page, max 100 (default 20). A larger value is served as 100."
// @Success      200  {object}  admin.ListUsersResponse
// @Failure      400  {object}  map[string]interface{}  "Search query is required"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/search [get]
// SearchUsersHandler searches users by email or name
// GET /api/v1/users/search?q=query&page=1&per_page=20
func (h *UserHandlers) SearchUsersHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Search query is required",
			})
			return
		}

		// GUARD per-page-clamps-to-max (issue #893), the user list's sibling.
		page := pagination.ClampPage(queryInt(c, "page"))
		perPage := pagination.ClampPerPage(queryInt(c, "per_page"), userPerPageDefault, userPerPageMax)
		offset := pagination.Offset(page, perPage)

		// Search users with memberships
		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
		if !ok {
			return
		}

		// Probe one row past the page: this axis has no counting query either,
		// so it emitted `{page, per_page}` and left a consumer no way to tell a
		// last page from a truncated one (issue #893).
		users, err := h.userRepo.SearchWithMemberships(c.Request.Context(), query, pagination.Probe(perPage), offset, scope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search users",
			})
			return
		}
		users, hasMore := pagination.Trim(users, perPage)

		c.JSON(http.StatusOK, gin.H{
			"users":      users,
			"pagination": probedPage(page, perPage, hasMore),
		})
	}
}

// @Summary      Get current user memberships
// @Description  Get the organization memberships for the currently authenticated user. No special scopes required.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  admin.UserMembershipsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/me/memberships [get]
// GetCurrentUserMembershipsHandler retrieves organization memberships for the current authenticated user
// GET /api/v1/users/me/memberships
// This endpoint allows any authenticated user to view their own memberships without special scopes
func (h *UserHandlers) GetCurrentUserMembershipsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get current user ID from context
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			return
		}

		userID, ok := userIDVal.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Get user's memberships
		memberships, err := h.orgRepo.GetUserMemberships(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user memberships",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"memberships": memberships,
		})
	}
}

// @Summary      Get user memberships
// @Description  Get the organization memberships for a specific user. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  admin.UserMembershipsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id}/memberships [get]
// GetUserMembershipsHandler retrieves organization memberships for a user
// GET /api/v1/users/:id/memberships
// Requires users:read scope (use /users/me/memberships for self-access)
func (h *UserHandlers) GetUserMembershipsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
		if !ok {
			return
		}

		// Check if user exists
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID, scope)
		if identityerr.Missing(user, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		// Get user's memberships
		memberships, err := h.orgRepo.GetUserMemberships(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user memberships",
			})
			return
		}

		// Filtered in Go, and that is a gap rather than a preference:
		// OrganizationRepository.GetUserMemberships is the one user-axis
		// accessor in the shared module with NO scope parameter, so there is
		// nothing to hand it. This is the reinvent-the-constraint-per-consumer
		// shape identity #161 exists to remove -- filed upstream as its sibling.
		// Until the accessor takes a scope, the rows are read and then dropped,
		// which withholds them from the response but still fetches them.
		if !scope.IsAllOrganizations() {
			permitted := make([]*models.UserMembership, 0, len(memberships))
			for _, m := range memberships {
				if scope.PermitsOrganization(m.OrganizationID) {
					permitted = append(permitted, m)
				}
			}
			memberships = permitted
		}

		c.JSON(http.StatusOK, gin.H{
			"memberships": memberships,
		})
	}
}

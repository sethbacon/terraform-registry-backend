// organizations.go implements handlers for organization CRUD operations and membership management.
package admin

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// OrganizationHandlers handles organization management endpoints
type OrganizationHandlers struct {
	cfg       *config.Config
	db        *sql.DB
	orgRepo   *repositories.OrganizationRepository
	claimRepo *repositories.NamespaceClaimRepository
	// creds invalidates BOTH credential families that snapshot a member's
	// org-derived authority when that authority is reduced: the JWT revoke-all
	// watermark (issue #559 finding [9]) and the member's org-bound API keys
	// (issue #732). Sweeping only the JWTs left an offboarded member holding a
	// working modules:write/providers:write credential into the organization's
	// namespaces forever, because AuthMiddleware reads an API key's scopes and
	// organization_id straight off the api_keys row.
	//
	// May be nil in tests; the sweep is skipped when unset, matching the
	// pre-existing convention that the revocation subsystem is wired as a unit.
	creds *credlifecycle.Sweeper

	// floor holds the two never-zero administrator invariants (issue #766):
	// the deployment always has a platform administrator, and an organization
	// with members always has one of its own. It spans both connections —
	// platform_admins is on the registry's, memberships on identity's — so it
	// cannot be built from this handler's single db handle and is injected.
	//
	// May be nil, on the same "wired as a unit" convention as creds; see
	// WithAdminFloor, and admin_floor_class_test.go for the check that stops
	// the router from quietly leaving it unset.
	floor *adminfloor.Guard

	// scmProviders and mirrors hold the two invariants migration 000056 took
	// away and nothing replaced (issue #899). Both tables carried
	// organization_id ON DELETE CASCADE into organizations until #883 dropped
	// it, and both outlive their organization now that it is gone:
	//
	//	scm_providers      -- client_secret_encrypted + webhook_secret, and the
	//	                      SCM webhook endpoint is UNAUTHENTICATED and does
	//	                      no organization check, so an orphan keeps
	//	                      publishing into a tenant that no longer exists.
	//	mirror_configurations -- MirrorSyncJob keeps running it on schedule and
	//	                      stamps every provider it creates with the dead
	//	                      organization id, while tenantscope.Permits hides
	//	                      the row from every non-platform administrator who
	//	                      might have stopped it.
	//
	// DELIBERATELY ON THE REGISTRY CONNECTION, unlike every other field here.
	// Both are registry feature tables that stay in the registry's schema at
	// the identity cutover; reading them through identityDB would resolve
	// tables that are not there in the separate-identity-database topology.
	// Same deliberate exception WithUserSCMTokens makes on the /users family.
	//
	// May be nil in tests, on the "wired as a unit" convention above; the
	// checks are then skipped. org_delete_guard_wiring_test.go is what stops
	// the router from leaving them unset.
	scmProviders *repositories.SCMRepository
	mirrors      *repositories.MirrorRepository
}

// WithOrgIntegrationGuards injects the registry-connection repositories that
// DeleteOrganizationHandler consults before it will delete an organization
// (issue #899).
//
// One option rather than two: the two refusals are one rule -- an organization
// is not deletable while it still owns an outbound integration -- and a
// deployment that wired one without the other would enforce half of it while
// reporting the same 200.
func (h *OrganizationHandlers) WithOrgIntegrationGuards(scmProviders *repositories.SCMRepository, mirrors *repositories.MirrorRepository) *OrganizationHandlers {
	h.scmProviders = scmProviders
	h.mirrors = mirrors
	return h
}

// WithAdminFloor injects the never-zero administrator guard (issue #766).
func (h *OrganizationHandlers) WithAdminFloor(floor *adminfloor.Guard) *OrganizationHandlers {
	h.floor = floor
	return h
}

// NewOrganizationHandlers creates a new OrganizationHandlers instance. db
// backs identity data access (organizations, members); userRevocations runs
// on the registry's domain connection.
//
// claimRepo is accepted as a parameter rather than constructed internally
// from db: db here is identityDB, but namespace_claims is a feature table
// that only ever receives this repo's own migrations on the registry's own
// db connection (see router.go's "feature repositories... stay on db"
// comment) -- in the documented shared/separate identity-database deployment
// mode, identityDB can be a genuinely different physical Postgres instance
// with no namespace_claims table at all. Callers must pass the SAME
// *NamespaceClaimRepository instance wired to db that the NamespaceAuthorizer
// middleware uses, so the pre-delete ownership check in
// DeleteOrganizationHandler queries the database that actually has the data.
func NewOrganizationHandlers(cfg *config.Config, db *sql.DB, claimRepo *repositories.NamespaceClaimRepository, userRevocations *repositories.UserTokenRevocationRepository) *OrganizationHandlers {
	h := &OrganizationHandlers{
		cfg:       cfg,
		db:        db,
		orgRepo:   repositories.NewOrganizationRepository(db),
		claimRepo: claimRepo,
	}
	// The API-key half of the sweep rides the same wiring gate as the JWT half:
	// db here is the identity connection that owns api_keys, so the repository
	// can be constructed locally, but leaving the sweeper nil when the caller
	// did not wire revocation preserves the documented "revocation is skipped
	// when unset" contract that existing callers and tests rely on.
	if userRevocations != nil {
		h.creds = credlifecycle.NewSweeper(userRevocations, repositories.NewAPIKeyRepository(db))
	}
	return h
}

// revokeOrgCredentials invalidates every credential family carrying a snapshot
// of the authority userID derived from orgID: the JWT revoke-all watermark and
// the user's org-bound API keys.
//
// Best-effort by design: the privilege change itself has already been
// committed, so a failed sweep is logged loudly rather than turned into a
// misleading error response (retrying the admin action re-runs the sweep).
// Returns true when the sweep completed, false when some part of it did not,
// so the handler can surface revocation_incomplete to the caller.
//
// retained is the scope set the user still holds in orgID after the change
// (nil for a removal); keys asking for no more than that are left alone
// because deleting an API key is irreversible.
func (h *OrganizationHandlers) revokeOrgCredentials(c *gin.Context, userID, orgID string, retained []string, reason string) bool {
	if h.creds == nil {
		return true
	}
	out := h.creds.OrgAuthorityReduced(c.Request.Context(), userID, orgID, retained, reason)
	if out.Incomplete {
		slog.Error("credential sweep incomplete after privilege change",
			"user_id", userID, "organization_id", orgID, "reason", reason)
	}
	return !out.Incomplete
}

// retainedOrgScopes reads the scopes a member still derives from an
// organization after a role change, for use as the sweep's retention filter.
//
// A lookup failure returns nil, i.e. "retains nothing", which sweeps every
// key. That is the fail-closed direction and the right one here: the caller
// has just reduced or reassigned this member's role, and we cannot prove any
// key is still within the new authority.
func (h *OrganizationHandlers) retainedOrgScopes(c *gin.Context, orgID, userID string) []string {
	member, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID, repositories.OrgScopeOrganizations(orgID))
	// "No longer a member" is the EXPECTED outcome on the removal path, not a
	// failure: it retains nothing, so every org-bound key is swept. Separating
	// it from the error branch keeps that ordinary case from logging as a
	// lookup failure and burying the real ones.
	if identityerr.Missing(member, err) {
		return nil
	}
	if err != nil {
		slog.Error("failed to read post-change role scopes; sweeping all org-bound keys for this member",
			"user_id", userID, "organization_id", orgID, "error", err)
		return nil
	}
	return member.RoleTemplateScopes
}

// @Summary      List namespace ownership claims
// @Description  List every namespace ownership claim with its resolved organization name, so operators can audit which organization owns each module/provider namespace.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  admin.ListNamespaceClaimsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/namespaces [get]
// ListNamespaceClaimsHandler lists every namespace ownership claim with its
// resolved organization name, so operators can audit which organization owns
// each module/provider namespace (issue #555). Organization names are resolved
// via a separate per-org lookup rather than a SQL join because namespace_claims
// (registry connection) and organizations (identity connection) may live on
// different databases.
// GET /api/v1/admin/namespaces
func (h *OrganizationHandlers) ListNamespaceClaimsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.claimRepo == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Namespace claims are not available"})
			return
		}
		// GUARD namespace-claim-list-scope (issue #719). namespace_claims is
		// org-owned and NOT NULL (migration 000045), so it sits squarely inside
		// this class — and this route returned every claim to any holder of the
		// flat organizations:read scope union. That is a map of which
		// organization owns which module/provider namespace across the whole
		// estate, which is precisely the input for choosing a namespace to
		// attack via the create/re-parent axes above.
		scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeOrganizationsRead)
		if !ok {
			return
		}

		claims, err := h.claimRepo.ListClaims(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list namespace claims"})
			return
		}

		nameCache := make(map[string]string)
		out := make([]gin.H, 0, len(claims))
		for _, cl := range claims {
			if !scope.Permits(cl.OrganizationID) {
				continue
			}
			orgName, cached := nameCache[cl.OrganizationID]
			if !cached {
				if org, err := h.orgRepo.GetByID(c.Request.Context(), cl.OrganizationID, scope.OrgScope()); err == nil && org != nil {
					orgName = org.Name
				}
				nameCache[cl.OrganizationID] = orgName
			}
			out = append(out, gin.H{
				"namespace":         cl.Namespace,
				"organization_id":   cl.OrganizationID,
				"organization_name": orgName,
				"claimed_by":        cl.ClaimedBy,
				"created_at":        cl.CreatedAt,
			})
		}
		c.JSON(http.StatusOK, gin.H{"namespaces": out})
	}
}

// @Summary      Get namespace ownership
// @Description  Resolve the owning organization of a single namespace exactly as the mutation authorizer does: the claim when present, otherwise the artifact-row fallback. A namespace whose artifacts span multiple organizations without a claim is reported as ambiguous rather than guessed.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        namespace  path  string  true  "Namespace name"
// @Success      200  {object}  admin.NamespaceOwnershipResponse
// @Failure      400  {object}  map[string]interface{}  "namespace is required"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Namespace is unclaimed and has no artifacts"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/namespaces/{namespace} [get]
// GetNamespaceOwnershipHandler resolves the owning organization of a single
// namespace exactly as the mutation authorizer does: the claim when present,
// otherwise the artifact-row fallback (a namespace that predates claims or was
// populated by a system path). A namespace whose artifacts span multiple
// organizations without a claim is reported as ambiguous rather than guessed.
// GET /api/v1/admin/namespaces/:namespace
func (h *OrganizationHandlers) GetNamespaceOwnershipHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.claimRepo == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Namespace claims are not available"})
			return
		}
		namespace := c.Param("namespace")
		if namespace == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "namespace is required"})
			return
		}

		// GUARD namespace-ownership-byid-scope (issue #719): the by-id axis of
		// the claim list above. Scoping only the list would leave the same
		// ownership map readable one namespace at a time, and namespace names
		// are public on the Terraform-protocol surface, so enumeration costs
		// nothing.
		scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeOrganizationsRead)
		if !ok {
			return
		}

		claim, err := h.claimRepo.GetClaim(c.Request.Context(), namespace)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve namespace ownership"})
			return
		}

		var orgID, source string
		if claim != nil {
			orgID = claim.OrganizationID
			source = "claim"
		} else {
			orgIDs, err := h.claimRepo.ArtifactOrganizations(c.Request.Context(), namespace)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve namespace ownership"})
				return
			}
			switch len(orgIDs) {
			case 0:
				c.JSON(http.StatusNotFound, gin.H{"error": "Namespace is unclaimed and has no artifacts"})
				return
			case 1:
				orgID = orgIDs[0]
				source = "artifact"
			default:
				// The ambiguous branch names every owning organization, so it
				// is filtered to the caller's scope rather than answered whole.
				visible := make([]string, 0, len(orgIDs))
				for _, id := range orgIDs {
					if scope.Permits(id) {
						visible = append(visible, id)
					}
				}
				if len(visible) == 0 {
					c.JSON(http.StatusNotFound, gin.H{"error": "Namespace is unclaimed and has no artifacts"})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"namespace":              namespace,
					"source":                 "ambiguous",
					"owner_organization_ids": visible,
				})
				return
			}
		}

		// Out-of-scope namespaces read as absent, matching the audit by-id axis:
		// a 403 here would confirm that the namespace exists and is owned by
		// someone else, which is the same disclosure in one fewer step.
		if !scope.Permits(orgID) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Namespace is unclaimed and has no artifacts"})
			return
		}

		var orgName string
		if org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, scope.OrgScope()); err == nil && org != nil {
			orgName = org.Name
		}
		resp := gin.H{
			"namespace":         namespace,
			"organization_id":   orgID,
			"organization_name": orgName,
			"source":            source,
		}
		if claim != nil {
			resp["claimed_by"] = claim.ClaimedBy
			resp["created_at"] = claim.CreatedAt
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary      List organizations
// @Description  Get a paginated list of all organizations.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        page      query  int  false  "Page number (default 1)"
// @Param        per_page  query  int  false  "Items per page, max 100 (default 20). A larger value is served as 100."
// @Success      200  {object}  admin.ListOrganizationsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations [get]
// ListOrganizationsHandler lists all organizations with pagination
// GET /api/v1/organizations?page=1&per_page=20
func (h *OrganizationHandlers) ListOrganizationsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// GUARD per-page-clamps-to-max (issue #893). This clamp used to reset
		// an over-large per_page to the DEFAULT of 20, so `?per_page=200`
		// returned 20 rows — fewer than `?per_page=50` — against a swagger
		// annotation that said "max 100". The sibling frontend's OIDC group
		// mapping asks for 200 precisely to get every organization and has been
		// silently served 20 ever since.
		page := pagination.ClampPage(queryInt(c, "page"))
		perPage := pagination.ClampPerPage(queryInt(c, "per_page"), orgPerPageDefault, orgPerPageMax)
		offset := pagination.Offset(page, perPage)

		// GUARD organization-list-scope (issue #719). This is the batch's own
		// sibling-asymmetry test failing: every /organizations/:id route carries
		// RequireOrgScopeForPathOrg (GHSA-hc25-j576-cqm2), while the list beside
		// them returned every organization on the platform with pagination as
		// its only constraint — handing out the exact ids those guarded routes
		// are keyed on, plus a tenant census of the deployment.
		scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeOrganizationsRead)
		if !ok {
			return
		}

		// ONE query for both caller kinds. A platform operator keeps the
		// platform-wide view and everyone else sees exactly the organizations
		// they hold organizations:read in — the difference is the OrgScope, not
		// a second branch. Until v0.25.0 the repository's List had no
		// organization predicate to push this down into, so the non-admin half
		// fetched each id by hand and paginated the result in memory; that
		// second implementation ordered its page by membership rather than by
		// created_at, and counted differently, so the two axes of one endpoint
		// disagreed about what a page was. The predicate is in the query now and
		// the hand-rolled half is gone.
		orgScope := scope.OrgScope()
		orgs, err := h.orgRepo.List(c.Request.Context(), perPage, offset, orgScope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list organizations",
			})
			return
		}
		total, err := h.orgRepo.Count(c.Request.Context(), orgScope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to count organizations",
			})
			return
		}
		c.JSON(http.StatusOK, ListOrganizationsResponse{
			Organizations: orgs,
			// countedPage, not a hand-built gin.H: the meta this endpoint
			// already emitted carried `total` and nothing that said whether the
			// page was the end of the list, so every consumer had to re-derive
			// it — and the sibling frontend's pickers did not (issue #893).
			Pagination: countedPage(page, perPage, offset, len(orgs), total),
		})
	}
}

// @Summary      Get organization
// @Description  Retrieve a specific organization by its ID, including member list.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Organization ID"
// @Success      200  {object}  admin.OrganizationWithMembersResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id} [get]
// GetOrganizationHandler retrieves a specific organization by ID
// GET /api/v1/organizations/:id
func (h *OrganizationHandlers) GetOrganizationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		// Get organization members with user details
		members, err := h.orgRepo.ListMembersWithUsers(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization members",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"organization": org,
			"members":      members,
		})
	}
}

// @Summary      List organization members
// @Description  Retrieve all members of a specific organization including user details.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Organization ID"
// @Success      200  {object}  admin.OrganizationMembersResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id}/members [get]
// ListMembersHandler retrieves all members of an organization with user details
// GET /api/v1/organizations/:id/members
func (h *OrganizationHandlers) ListMembersHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		// Check if organization exists
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		// Get members with user details
		members, err := h.orgRepo.ListMembersWithUsers(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization members",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"members": members,
		})
	}
}

// CreateOrganizationRequest represents the request to create a new organization
type CreateOrganizationRequest struct {
	Name        string `json:"name" binding:"required"`
	DisplayName string `json:"display_name" binding:"required"`
}

// @Summary      Create organization
// @Description  Create a new organization in the registry.
// @Tags         Organizations
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateOrganizationRequest  true  "Organization name and display name"
// @Success      201  {object}  admin.OrganizationResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Organization with this name already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations [post]
// CreateOrganizationHandler creates a new organization
// POST /api/v1/organizations
func (h *OrganizationHandlers) CreateOrganizationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateOrganizationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		// Check if organization already exists.
		//
		// This is an existence PROBE: not-found is the SUCCESS case ("the name
		// is free, go ahead and create it"). Written as a plain `err != nil ->
		// 500` it would reject every create of a name that is available, which
		// is every legitimate call. The switch says which outcome is which
		// instead of leaving it to branch order.
		existingOrg, err := h.orgRepo.GetByName(c.Request.Context(), req.Name, repositories.OrgScopeAllOrganizations())
		switch {
		case identityerr.Missing(existingOrg, err):
			// Name is free — fall through and create.
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing organization",
			})
			return
		default:
			c.JSON(http.StatusConflict, gin.H{
				"error": "Organization with this name already exists",
			})
			return
		}

		// Create organization
		org := &models.Organization{
			Name:        req.Name,
			DisplayName: req.DisplayName,
		}

		if err := h.orgRepo.Create(c.Request.Context(), org); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create organization",
			})
			return
		}

		// Auto-add the creating user as an org_owner member (not global admin
		// -- issue #648) so they can immediately manage the org they just
		// created, without being granted platform-wide admin privileges. The
		// error is no longer swallowed: silently succeeding here would leave
		// the creator with no membership at all in their own new org, and
		// would hide a real failure from the caller.
		//
		// BOOTSTRAP INVARIANT B (issue #766). This is the write that makes a
		// new organization able to administer itself, and it needs no
		// pre-existing administrator of its own to do it: org_owner is a fixed
		// literal carrying organizations:write, and the creator is whoever
		// asked. Every later membership change in this organization is then
		// held above zero administrators by the floor.
		//
		// AN ORGANIZATION WITH NO MEMBERS AT ALL IS A LEGITIMATE STATE, and
		// this branch is how one is reached. A request with no attributable
		// principal — an organization-bound API key whose api_keys.user_id is
		// NULL, i.e. an organization SERVICE credential — has no creator to
		// enrol, and there is nobody the registry could honestly name. The
		// empty organization is not stranded: invariant B is vacuous over it
		// (adminfloor.checkOrganizationFloor says why at length), and any
		// platform administrator can add its first member.
		//
		// It is logged rather than silently allowed, because "I created an
		// organization and cannot manage it" is otherwise indistinguishable
		// from a bug.
		creatorID, _ := c.Get("user_id")
		if uid, ok := creatorID.(string); ok && uid != "" {
			if err := h.orgRepo.AddMemberWithParams(c.Request.Context(), org.ID, uid, "org_owner", repositories.OrgScopeOrganizations(org.ID)); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Organization created but failed to add creator as a member",
				})
				return
			}
		} else {
			slog.Warn("organization created with no members: the request carried no attributable principal to enrol as its owner",
				"organization_id", org.ID, "organization", org.Name)
		}

		c.JSON(http.StatusCreated, gin.H{
			"organization": org,
		})
	}
}

// UpdateOrganizationRequest represents the request to update an organization
type UpdateOrganizationRequest struct {
	Name        *string `json:"name"`         // Optional rename; must satisfy registry naming rules
	DisplayName *string `json:"display_name"` // Human-readable display name
	IdpType     *string `json:"idp_type"`     // "oidc", "saml", "ldap", or null to clear
	IdpName     *string `json:"idp_name"`     // IdP name within type, or null to clear
}

// @Summary      Update organization
// @Description  Update an existing organization's name, display name, and optional IdP binding. Supplying a new `name` triggers a cascade rename: the organization row, all module namespace columns, and all provider namespace columns are updated atomically in a single transaction. User memberships reference the organization by UUID and are therefore unaffected. Set idp_type to "oidc", "saml", or "ldap" to restrict login; set to empty string to clear.
// @Tags         Organizations
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Organization ID"
// @Param        body  body  UpdateOrganizationRequest  true  "Fields to update"
// @Success      200  {object}  admin.OrganizationResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request body or name format"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      409  {object}  map[string]interface{}  "Organization name already taken"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id} [put]
// UpdateOrganizationHandler updates an organization
// PUT /api/v1/organizations/:id
func (h *OrganizationHandlers) UpdateOrganizationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		var req UpdateOrganizationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		// Get existing organization
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		// Handle rename — validate format, check uniqueness, then cascade.
		if req.Name != nil && *req.Name != org.Name {
			newName := *req.Name
			if err := validation.ValidateRegistrySegment(newName); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "invalid organization name: " + err.Error(),
				})
				return
			}
			// Availability probe: not-found means the new name is FREE, which is
			// the only case that may proceed to the rename.
			existing, err := h.orgRepo.GetByName(c.Request.Context(), newName, repositories.OrgScopeAllOrganizations())
			switch {
			case identityerr.Missing(existing, err):
				// Name is free — fall through and rename.
			case err != nil:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check name availability",
				})
				return
			default:
				c.JSON(http.StatusConflict, gin.H{
					"error": "Organization name already taken",
				})
				return
			}
			// ErrNotFound here means the organization was deleted between the
			// GetByID above and this write. Answer 404 — the same status that
			// pre-check gives for the same condition — rather than the 200 the
			// old contract produced, which reported a rename that never
			// happened and left the cascade below to run on a dead id.
			if err := h.orgRepo.Rename(c.Request.Context(), orgID, newName, repositories.OrgScopeOrganizations(orgID)); err != nil {
				if identityerr.IsNotFound(err) {
					c.JSON(http.StatusNotFound, gin.H{
						"error": "Organization not found",
					})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to rename organization",
				})
				return
			}
			// Cascade the new name to the registry's denormalized module/provider
			// namespaces on the domain connection (identity rename is done above).
			if err := repositories.CascadeOrganizationRename(c.Request.Context(), h.db, orgID, org.Name, newName); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to rename organization",
				})
				return
			}
			org.Name = newName
		}

		// Update remaining fields
		if req.DisplayName != nil {
			org.DisplayName = *req.DisplayName
		}

		// Update IdP binding — explicit null clears, present value sets
		if req.IdpType != nil {
			if *req.IdpType == "" {
				org.IdpType = nil
				org.IdpName = nil
			} else {
				valid := map[string]bool{"oidc": true, "saml": true, "ldap": true}
				if !valid[*req.IdpType] {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "idp_type must be 'oidc', 'saml', 'ldap', or empty to clear",
					})
					return
				}
				org.IdpType = req.IdpType
				org.IdpName = req.IdpName
			}
		}

		// Update in database
		// Raced against a concurrent delete: report the row's absence (404),
		// matching the pre-check, instead of the false success the pre-v0.24.0
		// contract returned.
		if err := h.orgRepo.Update(c.Request.Context(), org, repositories.OrgScopeOrganizations(orgID)); err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Organization not found",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update organization",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"organization": org,
		})
	}
}

// refuseIfOwnsIntegrations refuses an organization deletion while the
// organization still owns an SCM provider or a mirror configuration, and
// reports whether the caller must stop. It writes its own response when it
// returns true.
//
// REFUSE RATHER THAN SWEEP (issue #899), and the argument is the same for both
// resources even though their hazards differ.
//
// Both columns were ON DELETE CASCADE until migration 000056 (issue #883), so
// restoring the cascade in application code -- delete the rows, then delete the
// organization -- is the obvious port, and it is what DeleteUserHandler does
// for scm_oauth_tokens. It is the wrong shape here:
//
//  1. NOT ATOMIC, AND THE FAILURE DESTROYS DATA. organizations may live in a
//     different SCHEMA or a different DATABASE from these two registry tables
//     -- that is precisely why 000056 could not keep the foreign keys -- so a
//     sweep and the delete cannot share a transaction. Sweeping first and then
//     failing the delete leaves a LIVE organization stripped of its SCM
//     connection and its mirrors, and client_secret_encrypted is not
//     recoverable from the registry once the row is gone. Refusing has no such
//     failure mode: it is a read, and a read that fails 500s without deleting
//     anything.
//  2. THE INVARIANT BECOMES STRUCTURAL. A refusal makes it impossible to reach
//     orgRepo.Delete while either row exists, so this path cannot produce an
//     orphan at all. A best-effort sweep can only promise that it usually does
//     not.
//  3. IT MATCHES THE TWO REFUSALS ABOVE. This handler's established answer to
//     "the organization still owns something substantive" is 409 with an
//     actionable message, not a silent cascade.
//  4. IT IS ACTIONABLE. Both resources have first-class delete endpoints --
//     DELETE /admin/scm/providers/:id and DELETE /admin/mirrors/:id -- so the
//     operator can do exactly what the message asks, and deleting them THERE
//     cascades their dependents (scm_oauth_tokens, scm_provider_tokens,
//     module_scm_repos; mirror_sync_history, mirrored_providers) through
//     foreign keys that still exist because they stay inside the registry's own
//     schema.
//
// Why this differs from the scm_oauth_tokens sweep DeleteUserHandler does: a
// user's OAuth token is a per-user credential whose only meaning is the
// principal being destroyed, it is re-obtainable by re-running the OAuth flow
// at no operator cost, and there is no endpoint an admin could be told to call
// first -- nobody can delete another user's tokens. An SCM provider and a
// mirror configuration are organization-level configuration objects with their
// own CRUD, carrying secrets and schedules an operator should decommission
// deliberately. A 409 is a usable instruction there; it would not have been on
// the user path.
//
// A nil repository means the dependency was not wired (tests, and any caller
// predating this issue), which skips the check rather than refusing -- the same
// convention creds, floor and h.scmTokens follow. The router is held to wiring
// it by org_delete_guard_wiring_test.go.
func (h *OrganizationHandlers) refuseIfOwnsIntegrations(c *gin.Context, orgID string) bool {
	if h.scmProviders == nil && h.mirrors == nil {
		return false
	}

	// Both repositories key on a uuid.UUID. A non-UUID organization id is not
	// reachable through the routes -- the id was just used to load the
	// organization -- but it would silently count zero of everything, so it
	// fails rather than passing.
	oid, err := uuid.Parse(orgID)
	if err != nil {
		slog.Error("cannot check an organization's integrations for a non-UUID organization id",
			"organization_id", orgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check organization integrations",
		})
		return true
	}

	if h.scmProviders != nil {
		n, countErr := h.scmProviders.CountProvidersByOrganization(c.Request.Context(), oid)
		if countErr != nil {
			slog.Error("failed to count an organization's SCM providers; refusing to delete the organization",
				"organization_id", orgID, "error", countErr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check organization SCM providers",
			})
			return true
		}
		if n > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Organization still owns SCM providers; delete them before deleting it",
			})
			return true
		}
	}

	if h.mirrors != nil {
		n, countErr := h.mirrors.CountByOrganization(c.Request.Context(), oid)
		if countErr != nil {
			slog.Error("failed to count an organization's mirror configurations; refusing to delete the organization",
				"organization_id", orgID, "error", countErr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check organization mirror configurations",
			})
			return true
		}
		if n > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Organization still owns mirror configurations; delete them before deleting it",
			})
			return true
		}
	}

	return false
}

// @Summary      Delete organization
// @Description  Remove an organization and its associated records.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Organization ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      409  {object}  map[string]interface{}  "Organization still owns namespace claims, modules/providers, SCM providers or mirror configurations, or deleting it would leave the deployment with no platform administrator"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id} [delete]
// DeleteOrganizationHandler deletes an organization
// DELETE /api/v1/organizations/:id
func (h *OrganizationHandlers) DeleteOrganizationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		// Check if organization exists
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		// Refuse to delete an organization that still owns namespace claims
		// (CWE-639, issue #555). Cascading the delete onto namespace_claims
		// would silently fall the namespace back to resolveOwnerOrg's
		// artifact-row fallback, which — since every write handler stamps
		// organization_id from the default organization regardless of the
		// real caller — reliably re-attributes ownership to the default org
		// rather than leaving it (correctly) unowned.
		//
		// This check is now the ONLY thing holding that invariant. It was
		// written alongside an ON DELETE RESTRICT foreign key on
		// namespace_claims.organization_id, as the half that turns an opaque
		// 500 into a clear 409; migration 000056 dropped the constraint
		// (issue #883) because it could not be expressed once organizations
		// may live in another schema or another database. Nothing below the
		// application refuses this any more -- do not weaken it.
		claimCount, err := h.claimRepo.CountByOrganization(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check namespace ownership",
			})
			return
		}
		if claimCount > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Organization still owns namespace claims; release or reassign its namespaces before deleting it",
			})
			return
		}

		// Also refuse when the organization directly owns module/provider
		// rows with no namespace_claims row at all -- a namespace whose
		// artifacts already span more than one organization is deliberately
		// left unclaimed (ambiguous ownership, admin-only at runtime), so the
		// claim count check above is 0 for it even though this organization
		// still owns rows there. Deleting this organization would leave its
		// rows in the shared namespace unowned, collapsing it from admin-only
		// ambiguous to unchecked sole ownership by whichever organization's
		// rows survive -- the same defect this table exists to close, reached
		// via a shared namespace instead of via a claim.
		//
		// modules/providers.organization_id was ON DELETE CASCADE until
		// migration 000056 (issue #883). While it existed this refusal made
		// the cascade unreachable, so dropping it changed nothing an API
		// caller can observe -- but only for as long as this check stands.
		ownsArtifacts, err := h.claimRepo.OwnsArtifacts(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check organization artifact ownership",
			})
			return
		}
		if ownsArtifacts {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Organization still owns modules or providers; remove or reassign them before deleting it",
			})
			return
		}

		// GUARD org-owns-integrations (issue #899). Third and fourth refusals,
		// for the two constraints migration 000056 dropped that were the sole
		// mechanism holding their invariant. See refuseIfOwnsIntegrations for
		// why these REFUSE rather than sweep.
		if h.refuseIfOwnsIntegrations(c, orgID) {
			return
		}

		// Snapshot the membership before the delete. Deleting an organization
		// cascades organization_members away, so this is an authority
		// reduction for every member -- reached through a verb
		// (DELETE FROM organizations) rather than an explicit member removal,
		// which is precisely why it was missed.
		//
		// The api_keys half is genuinely handled by the schema here:
		// api_keys.organization_id is ON DELETE CASCADE in BOTH the legacy and
		// the identity schema (unlike user_id, see DeleteUserHandler), so the
		// org's keys really do vanish with it. The JWT half does not: a
		// member's session token carries the UNION of their scopes across all
		// their organizations, computed at login, and nothing re-derives it.
		// A member of this org plus one other keeps exercising the deleted
		// org's scopes on every route gated only on RequireScope until their
		// token expires.
		//
		// Best-effort, like every other site: a lookup failure is surfaced via
		// revocation_incomplete rather than blocking an otherwise valid delete.
		var members []*models.OrganizationMember
		sweepIncomplete := false
		if h.creds != nil {
			var listErr error
			members, listErr = h.orgRepo.ListMembers(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
			if listErr != nil {
				slog.Error("failed to list organization members before deletion; their sessions will not be revoked",
					"organization_id", orgID, "error", listErr)
				members = nil
				sweepIncomplete = true
			}
		}

		// Delete organization (cascading deletes will handle related records)
		// Already gone (a concurrent delete won the race): 404, the same answer
		// a second DELETE gets from the existence pre-check above, so the two
		// paths to "this organization does not exist" agree.
		//
		// GUARD admin-floor (issue #766). The cascade above is also the ONLY
		// way to take a deployment's last platform administrator away without
		// naming a principal at all: if the organization being deleted is the
		// one holding the admin-bearing membership, `DELETE FROM organizations`
		// removes it with no membership statement for anything to notice.
		// Invariant B needs no check here — a deleted organization cannot be
		// stranded — which is why the Change names organizations and no user.
		err = h.floor.Protect(c.Request.Context(), adminfloor.Change{
			OrganizationIDs:      []string{orgID},
			DeletesOrganizations: true,
		}, func(ctx context.Context) error {
			return h.orgRepo.Delete(ctx, orgID, repositories.OrgScopeOrganizations(orgID))
		})
		if respondAdminFloor(c, err) {
			return
		}
		if err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Organization not found",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete organization",
			})
			return
		}

		// retained is nil: the organization is gone, so no member derives
		// anything from it any more. The key half is a no-op in practice
		// (the FK cascade already removed the rows); the watermark is what
		// actually retires the stale scope union.
		for _, m := range members {
			if !h.revokeOrgCredentials(c, m.UserID, orgID, nil, "organization deleted") {
				sweepIncomplete = true
			}
		}

		response := gin.H{"message": "Organization deleted successfully"}
		if sweepIncomplete {
			response["revocation_incomplete"] = true
		}
		c.JSON(http.StatusOK, response)
	}
}

// AddMemberRequest represents the request to add a member to an organization
type AddMemberRequest struct {
	UserID         string  `json:"user_id" binding:"required"`
	RoleTemplateID *string `json:"role_template_id"` // Optional, UUID of role template
}

// @Summary      Add organization member
// @Description  Add a user as a member to an organization, optionally assigning a role template.
// @Tags         Organizations
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string          true  "Organization ID"
// @Param        body  body  AddMemberRequest  true  "Member user_id and optional role_template_id"
// @Success      201  {object}  admin.MemberResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      409  {object}  map[string]interface{}  "User is already a member"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id}/members [post]
// AddMemberHandler adds a member to an organization
// POST /api/v1/organizations/:id/members
func (h *OrganizationHandlers) AddMemberHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		var req AddMemberRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		if chk := h.checkRoleAssignment(c, req.RoleTemplateID); !chk.allowed {
			msg := chk.message
			if msg == "" {
				msg = "role assignment not permitted"
			}
			c.JSON(chk.status, gin.H{"error": msg})
			return
		}

		// Check if organization exists
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(org, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		// Check if user is already a member.
		//
		// Another existence probe with an inverted happy path: NOT being a
		// member is the precondition for adding one. Left as `err != nil ->
		// 500` this would fail every legitimate add.
		existingMember, err := h.orgRepo.GetMember(c.Request.Context(), orgID, req.UserID, repositories.OrgScopeOrganizations(orgID))
		switch {
		case identityerr.Missing(existingMember, err):
			// Not a member yet — fall through and add.
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing membership",
			})
			return
		default:
			c.JSON(http.StatusConflict, gin.H{
				"error": "User is already a member of this organization",
			})
			return
		}

		// Add member with role template.
		//
		// The struct is still built for the response body below, but the write
		// takes the three columns it actually sets: AddMemberWithRoleTemplate
		// stamps created_at from the server clock rather than from the caller,
		// so a struct that forgot to set it can no longer insert a privilege
		// grant dated 0001-01-01.
		member := &models.OrganizationMember{
			OrganizationID: orgID,
			UserID:         req.UserID,
			RoleTemplateID: req.RoleTemplateID,
			CreatedAt:      time.Now(),
		}

		if err := h.orgRepo.AddMemberWithRoleTemplate(c.Request.Context(), orgID, req.UserID, req.RoleTemplateID,
			repositories.OrgScopeOrganizations(orgID)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to add member to organization",
			})
			return
		}

		// Get member with role template info for response
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, req.UserID, repositories.OrgScopeOrganizations(orgID))
		if err != nil {
			// Return basic member info if we can't get role details
			c.JSON(http.StatusCreated, gin.H{
				"member": member,
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"member": memberWithRole,
		})
	}
}

// UpdateMemberRequest represents the request to update a member's role template
type UpdateMemberRequest struct {
	RoleTemplateID *string `json:"role_template_id"` // UUID of role template, or null to clear
}

// @Summary      Update organization member
// @Description  Update a member's role template within an organization. A reassignment revokes the member's sessions and any org-bound API key that over-asks under the new template; if that sweep does not fully land the 200 body carries an extra `revocation_incomplete: true` field.
// @Tags         Organizations
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id       path  string               true  "Organization ID"
// @Param        user_id  path  string               true  "User ID"
// @Param        body     body  UpdateMemberRequest  true  "role_template_id (UUID or null to clear)"
// @Success      200  {object}  admin.MemberResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Member not found in organization"
// @Failure      409  {object}  map[string]interface{}  "Would leave no administrator"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id}/members/{user_id} [put]
// UpdateMemberHandler updates a member's role template in an organization
// PUT /api/v1/organizations/:id/members/:user_id
func (h *OrganizationHandlers) UpdateMemberHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")
		userID := c.Param("user_id")

		var req UpdateMemberRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request: " + err.Error(),
			})
			return
		}

		if chk := h.checkRoleAssignment(c, req.RoleTemplateID); !chk.allowed {
			msg := chk.message
			if msg == "" {
				msg = "role assignment not permitted"
			}
			c.JSON(chk.status, gin.H{"error": msg})
			return
		}

		// Get existing member
		member, err := h.orgRepo.GetMember(c.Request.Context(), orgID, userID, repositories.OrgScopeOrganizations(orgID))
		if identityerr.Missing(member, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Member not found in organization",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve member",
			})
			return
		}

		// Capture the pre-update role template so we know whether this actually
		// changes the member's effective scopes (nil-to-nil or same ID is a no-op).
		oldRoleTemplateID := member.RoleTemplateID

		// Update role template
		member.RoleTemplateID = req.RoleTemplateID
		// The membership vanished between the GetMember above and this write.
		// 404 matches the pre-check; the old contract reported a role change
		// that never landed, and the audit log recorded it as though it had.
		//
		// GUARD admin-floor (issue #766). A re-role is a DOWNGRADE whenever the
		// new template carries less than the old one, and `role_template_id:
		// null` is the widest downgrade there is. Either can take away the
		// deployment's last platform-admin template or an organization's last
		// administrator, so the write runs inside the floor's lock with the
		// replacement template named — a move onto another admin-bearing
		// template is not a reduction and is not refused.
		err = h.floor.Protect(c.Request.Context(), adminfloor.Change{
			UserID:              userID,
			OrganizationIDs:     []string{orgID},
			KeepsRoleTemplateID: req.RoleTemplateID,
		}, func(ctx context.Context) error {
			return h.orgRepo.UpdateMemberRoleTemplate(ctx, orgID, userID, member.RoleTemplateID,
				repositories.OrgScopeOrganizations(orgID))
		})
		if respondAdminFloor(c, err) {
			return
		}
		if err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Member not found in organization",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update member role",
			})
			return
		}

		// A role-template reassignment changes the scopes a fresh JWT would embed
		// for this user, and equally invalidates the scope snapshot frozen on
		// their org-bound API keys at creation time; sweep both so the change
		// takes effect immediately rather than waiting out the JWT TTL (issue
		// #559 finding [9]) or, for the keys, forever (issue #732).
		//
		// The new template's scopes are the retention filter: a promotion
		// (publisher -> owner) leaves every existing key within the new
		// authority, so nothing is deleted, while a demotion deletes exactly
		// the keys that now over-ask.
		//
		// A failed sweep is surfaced as revocation_incomplete, matching
		// RemoveMemberHandler: a clean 200 on a demotion whose credentials are
		// still live is the silent failure this whole change is about.
		revocationIncomplete := false
		if !stringPtrEqual(oldRoleTemplateID, req.RoleTemplateID) {
			revocationIncomplete = !h.revokeOrgCredentials(c, userID, orgID,
				h.retainedOrgScopes(c, orgID, userID),
				"organization member role template changed")
		}

		// Get member with role template info for response
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID, repositories.OrgScopeOrganizations(orgID))
		response := gin.H{"member": memberWithRole}
		if err != nil {
			// Return basic member info if we can't get role details
			response = gin.H{"member": member}
		}
		if revocationIncomplete {
			response["revocation_incomplete"] = true
		}
		c.JSON(http.StatusOK, response)
	}
}

// @Summary      Remove organization member
// @Description  Remove a user from an organization's membership. Refused with 409 when it would leave the organization with members but no administrator, or the deployment with no platform administrator (issue #766).
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id       path  string  true  "Organization ID"
// @Param        user_id  path  string  true  "User ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Would leave no administrator"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id}/members/{user_id} [delete]
// RemoveMemberHandler removes a member from an organization
// DELETE /api/v1/organizations/:id/members/:user_id
func (h *OrganizationHandlers) RemoveMemberHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")
		userID := c.Param("user_id")

		// RemoveMember is a plain DELETE with no rows-affected/not-found
		// signal, so when revocation is wired up, check membership first:
		// without this, calling the endpoint against a user who was never a
		// member of this org (a typo, a stale UI, or a probe by an org admin
		// with no relationship to the target) would still revoke that user's
		// tokens org-wide below -- letting any org admin log out an arbitrary
		// user by targeting a removal that never actually changes anything.
		// Skipped entirely when userRevocations is nil (as in most tests and
		// any deployment that hasn't wired it up): the lookup's only purpose
		// is deciding whether to call revokeUserTokens, which itself no-ops
		// in that case, so running it unconditionally would add a hard
		// dependency on an unrelated read query for no behavioral benefit.
		//
		// A lookup failure is logged and treated as "membership unconfirmed"
		// rather than blocking the removal: this query only feeds the
		// revocation decision below, not RemoveMember itself, so a transient
		// read error must not prevent an admin from removing a member.
		// Treating "unconfirmed" the same as "wasn't a member" is the safe
		// direction -- it costs a skipped revocation sweep (surfaced to the
		// caller below), never an unwarranted one.
		var wasMember *models.OrganizationMemberWithUser
		revocationCheckFailed := false
		if h.creds != nil {
			var err error
			wasMember, err = h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID, repositories.OrgScopeOrganizations(orgID))
			// "Not a member" is a CONFIRMED answer, not an unconfirmed one: it
			// is precisely the typo/stale-UI/probe case this lookup exists to
			// detect, and it correctly skips the revocation sweep. Only a real
			// lookup failure leaves membership unconfirmed and therefore sets
			// revocationCheckFailed — folding the miss in with it would flag
			// `revocation_incomplete` on every no-op removal and train callers
			// to ignore the field that matters.
			switch {
			case identityerr.Missing(wasMember, err):
				wasMember = nil
			case err != nil:
				slog.Error("failed to check organization membership before removal; token revocation will be skipped",
					"user_id", userID, "organization_id", orgID, "error", err)
				wasMember = nil
				revocationCheckFailed = true
			}
		}

		// A removal that matches no row now reports store.ErrNotFound where it
		// used to report success. This endpoint stays IDEMPOTENT: removing a
		// user who is already not a member has achieved the caller's intent,
		// and the handler's own doc comment above is built on that call being
		// safe to make against a non-member. Turning the second DELETE into a
		// 500 would break every retry and every concurrent deprovision.
		//
		// GUARD admin-floor (issue #766). Under the floor's lock, so two
		// administrators removing each other concurrently serialise: the second
		// one's check runs after the first one's DELETE, sees the smaller set,
		// and refuses. IDEMPOTENCE IS PRESERVED — a removal that matches no row
		// is not a reduction, so the floor's own reads find this principal
		// carrying nothing and let it through to the same 200 as before.
		err := h.floor.Protect(c.Request.Context(), adminfloor.Change{
			UserID:            userID,
			OrganizationIDs:   []string{orgID},
			RemovesMembership: true,
		}, func(ctx context.Context) error {
			return h.orgRepo.RemoveMember(ctx, orgID, userID, repositories.OrgScopeOrganizations(orgID))
		})
		if respondAdminFloor(c, err) {
			return
		}
		if err != nil && !identityerr.IsNotFound(err) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove member from organization",
			})
			return
		}

		// The removed member's outstanding JWTs still carry the org-derived
		// scopes they had at login, and their API keys still carry BOTH those
		// scopes and this organization's ID -- and authorizeOrgAccess treats a
		// key's org binding as authoritative. Removal that swept only the JWTs
		// left a working publish credential into this org's namespaces with no
		// expiry at all (issue #732). Sweep both, but only when membership
		// actually existed and was removed.
		// retained is nil: a removed member derives nothing from this
		// organization any more, so every org-bound key they hold over-asks.
		if wasMember != nil {
			if !h.revokeOrgCredentials(c, userID, orgID, nil, "removed from organization") {
				revocationCheckFailed = true
			}
		}

		response := gin.H{"message": "Member removed successfully"}
		if revocationCheckFailed {
			// The removal itself succeeded, but either we couldn't determine
			// whether to sweep the user's credentials, or the sweep itself
			// partially failed -- surface that so the caller doesn't assume
			// the incident is fully closed.
			response["revocation_incomplete"] = true
		}
		c.JSON(http.StatusOK, response)
	}
}

// stringPtrEqual reports whether two optional strings (role template IDs) are
// equal, treating nil as distinct from any non-nil value including "".
func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// @Summary      Search organizations
// @Description  Search organizations by name or display name with pagination.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        q         query  string  true   "Search query"
// @Param        page      query  int     false  "Page number (default 1)"
// @Param        per_page  query  int     false  "Items per page, max 100 (default 20). A larger value is served as 100."
// @Success      200  {object}  admin.ListOrganizationsResponse
// @Failure      400  {object}  map[string]interface{}  "Search query is required"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/search [get]
// SearchOrganizationsHandler searches organizations by name
// GET /api/v1/organizations/search?q=query&page=1&per_page=20
func (h *OrganizationHandlers) SearchOrganizationsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Search query is required",
			})
			return
		}

		// GUARD per-page-clamps-to-max (issue #893), the list axis's sibling:
		// the same clamp, verbatim, with the same "asking for more gets you
		// less" behaviour.
		page := pagination.ClampPage(queryInt(c, "page"))
		perPage := pagination.ClampPerPage(queryInt(c, "per_page"), orgPerPageDefault, orgPerPageMax)
		offset := pagination.Offset(page, perPage)

		// GUARD organization-search-scope (issue #719): the same asymmetry as
		// the list axis, and strictly worse — search turns the census into a
		// lookup, so an attacker who knows a target organization's name can
		// confirm it exists and recover its id without enumerating anything.
		scope, ok := resolveTenantScope(c, h.orgRepo, auth.ScopeOrganizationsRead)
		if !ok {
			return
		}

		// One query, as on the list axis. Search applies the scope predicate as
		// its own conjunct AFTER the parenthesised name/display_name
		// alternation, so no search term can OR its way outside the tenancy —
		// which is what the second, in-memory matcher that used to live here was
		// guarding against by hand, against the same two fields, with its own
		// case-folding rules.
		//
		// pagination.Probe asks for ONE row more than the caller wants. The
		// identity store has no search-counting query, so this axis emitted
		// `{page, per_page}` and nothing else — a consumer could not tell a
		// last page from a truncated one at all (issue #893). The probe row is
		// trimmed off below and never served; its presence is has_more.
		orgs, err := h.orgRepo.Search(c.Request.Context(), query, pagination.Probe(perPage), offset, scope.OrgScope())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search organizations",
			})
			return
		}
		orgs, hasMore := pagination.Trim(orgs, perPage)
		c.JSON(http.StatusOK, ListOrganizationsResponse{
			Organizations: orgs,
			Pagination:    probedPage(page, perPage, hasMore),
		})
	}
}

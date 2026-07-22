// organizations.go implements handlers for organization CRUD operations and membership management.
package admin

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// OrganizationHandlers handles organization management endpoints
type OrganizationHandlers struct {
	cfg       *config.Config
	db        *sql.DB
	orgRepo   *repositories.OrganizationRepository
	claimRepo *repositories.NamespaceClaimRepository
	// userRevocations moves the affected user's revoke-all watermark when a
	// membership's role template changes or a member is removed, so outstanding
	// JWTs (which embed scopes at login) stop validating immediately instead of
	// carrying the old privileges until expiry (issue #559 finding [9]).
	// May be nil in tests; revocation is skipped when unset.
	userRevocations *repositories.UserTokenRevocationRepository
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
	return &OrganizationHandlers{
		cfg:             cfg,
		db:              db,
		orgRepo:         repositories.NewOrganizationRepository(db),
		claimRepo:       claimRepo,
		userRevocations: userRevocations,
	}
}

// revokeUserTokens moves a user's revoke-all watermark after a privilege
// change. Best-effort by design: the privilege change itself has already been
// committed, so a failed revocation is logged loudly rather than turned into a
// misleading error response (retrying the admin action re-runs the revocation).
func (h *OrganizationHandlers) revokeUserTokens(c *gin.Context, userID, reason string) {
	if h.userRevocations == nil {
		return
	}
	if err := h.userRevocations.RevokeAllUserTokens(c.Request.Context(), userID); err != nil {
		slog.Error("failed to revoke user tokens after privilege change",
			"user_id", userID, "reason", reason, "error", err)
	}
}

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
		claims, err := h.claimRepo.ListClaims(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list namespace claims"})
			return
		}

		nameCache := make(map[string]string)
		out := make([]gin.H, 0, len(claims))
		for _, cl := range claims {
			orgName, cached := nameCache[cl.OrganizationID]
			if !cached {
				if org, err := h.orgRepo.GetByID(c.Request.Context(), cl.OrganizationID); err == nil && org != nil {
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
				c.JSON(http.StatusOK, gin.H{
					"namespace":              namespace,
					"source":                 "ambiguous",
					"owner_organization_ids": orgIDs,
				})
				return
			}
		}

		var orgName string
		if org, err := h.orgRepo.GetByID(c.Request.Context(), orgID); err == nil && org != nil {
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
// @Param        per_page  query  int  false  "Items per page, max 100 (default 20)"
// @Success      200  {object}  admin.ListOrganizationsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations [get]
// ListOrganizationsHandler lists all organizations with pagination
// GET /api/v1/organizations?page=1&per_page=20
func (h *OrganizationHandlers) ListOrganizationsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))

		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 100 {
			perPage = 20
		}

		offset := (page - 1) * perPage

		// Get organizations from repository
		orgs, err := h.orgRepo.List(c.Request.Context(), perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list organizations",
			})
			return
		}

		// Get total count
		total, err := h.orgRepo.Count(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to count organizations",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"organizations": orgs,
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
				"total":    total,
			},
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

		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}

		// Get organization members with user details
		members, err := h.orgRepo.ListMembersWithUsers(c.Request.Context(), orgID)
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
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}

		// Get members with user details
		members, err := h.orgRepo.ListMembersWithUsers(c.Request.Context(), orgID)
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

		// Check if organization already exists
		existingOrg, err := h.orgRepo.GetByName(c.Request.Context(), req.Name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing organization",
			})
			return
		}

		if existingOrg != nil {
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

		// Auto-add the creating user as an admin member so they can immediately access the org
		if rawUID, exists := c.Get("user_id"); exists {
			if uid, ok := rawUID.(string); ok && uid != "" {
				_ = h.orgRepo.AddMemberWithParams(c.Request.Context(), org.ID, uid, "admin")
			}
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
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
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
			existing, err := h.orgRepo.GetByName(c.Request.Context(), newName)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check name availability",
				})
				return
			}
			if existing != nil {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Organization name already taken",
				})
				return
			}
			if err := h.orgRepo.Rename(c.Request.Context(), orgID, newName); err != nil {
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
		if err := h.orgRepo.Update(c.Request.Context(), org); err != nil {
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

// @Summary      Delete organization
// @Description  Remove an organization and its associated records.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Organization ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
// @Failure      409  {object}  map[string]interface{}  "Organization still owns namespace claims"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id} [delete]
// DeleteOrganizationHandler deletes an organization
// DELETE /api/v1/organizations/:id
func (h *OrganizationHandlers) DeleteOrganizationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")

		// Check if organization exists
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}

		// Refuse to delete an organization that still owns namespace claims
		// (CWE-639, issue #555). Cascading the delete onto namespace_claims
		// would silently fall the namespace back to resolveOwnerOrg's
		// artifact-row fallback, which — since every write handler stamps
		// organization_id from the default organization regardless of the
		// real caller — reliably re-attributes ownership to the default org
		// rather than leaving it (correctly) unowned. The namespace_claims FK
		// is ON DELETE RESTRICT as a fail-closed backstop; this check exists
		// to surface the reason with a clear 409 instead of an opaque 500.
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
		// still owns rows there. modules/providers' organization_id FK is
		// still ON DELETE CASCADE (unrelated to the namespace_claims RESTRICT
		// above); deleting this organization would silently remove its rows
		// from the shared namespace, collapsing it from admin-only ambiguous
		// to unchecked sole ownership by whichever organization's rows
		// survive -- the same defect this table exists to close, reached via
		// a shared namespace instead of via a claim.
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

		// Delete organization (cascading deletes will handle related records)
		if err := h.orgRepo.Delete(c.Request.Context(), orgID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete organization",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Organization deleted successfully",
		})
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
			c.JSON(chk.status, gin.H{"error": "role assignment not permitted"})
			return
		}

		// Check if organization exists
		org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve organization",
			})
			return
		}

		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Organization not found",
			})
			return
		}

		// Check if user is already a member
		existingMember, err := h.orgRepo.GetMember(c.Request.Context(), orgID, req.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing membership",
			})
			return
		}

		if existingMember != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": "User is already a member of this organization",
			})
			return
		}

		// Add member with role template
		member := &models.OrganizationMember{
			OrganizationID: orgID,
			UserID:         req.UserID,
			RoleTemplateID: req.RoleTemplateID,
			CreatedAt:      time.Now(),
		}

		if err := h.orgRepo.AddMember(c.Request.Context(), member); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to add member to organization",
			})
			return
		}

		// Get member with role template info for response
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, req.UserID)
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
// @Description  Update a member's role template within an organization.
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
			c.JSON(chk.status, gin.H{"error": "role assignment not permitted"})
			return
		}

		// Get existing member
		member, err := h.orgRepo.GetMember(c.Request.Context(), orgID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve member",
			})
			return
		}

		if member == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Member not found in organization",
			})
			return
		}

		// Capture the pre-update role template so we know whether this actually
		// changes the member's effective scopes (nil-to-nil or same ID is a no-op).
		oldRoleTemplateID := member.RoleTemplateID

		// Update role template
		member.RoleTemplateID = req.RoleTemplateID
		if err := h.orgRepo.UpdateMember(c.Request.Context(), member); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update member role",
			})
			return
		}

		// A role-template reassignment changes the scopes a fresh JWT would embed
		// for this user; revoke their outstanding tokens so the change takes
		// effect immediately rather than waiting out the JWT TTL (issue #559
		// finding [9]).
		if !stringPtrEqual(oldRoleTemplateID, req.RoleTemplateID) {
			h.revokeUserTokens(c, userID, "organization member role template changed")
		}

		// Get member with role template info for response
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID)
		if err != nil {
			// Return basic member info if we can't get role details
			c.JSON(http.StatusOK, gin.H{
				"member": member,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"member": memberWithRole,
		})
	}
}

// @Summary      Remove organization member
// @Description  Remove a user from an organization's membership.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        id       path  string  true  "Organization ID"
// @Param        user_id  path  string  true  "User ID"
// @Success      200  {object}  admin.MessageResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
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
		if h.userRevocations != nil {
			var err error
			wasMember, err = h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID)
			if err != nil {
				slog.Error("failed to check organization membership before removal; token revocation will be skipped",
					"user_id", userID, "organization_id", orgID, "error", err)
				wasMember = nil
				revocationCheckFailed = true
			}
		}

		if err := h.orgRepo.RemoveMember(c.Request.Context(), orgID, userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove member from organization",
			})
			return
		}

		// The removed member's outstanding JWTs still carry the org-derived
		// scopes they had at login; revoke them so removal takes effect
		// immediately instead of waiting out the JWT TTL (issue #559 finding
		// [9]) -- but only when membership actually existed and was removed.
		if wasMember != nil {
			h.revokeUserTokens(c, userID, "removed from organization")
		}

		response := gin.H{"message": "Member removed successfully"}
		if revocationCheckFailed {
			// The removal itself succeeded, but we couldn't determine
			// whether to revoke the user's tokens -- surface that so the
			// caller doesn't assume the incident is fully closed.
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
// @Param        per_page  query  int     false  "Items per page, max 100 (default 20)"
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

		// Parse pagination
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))

		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 100 {
			perPage = 20
		}

		offset := (page - 1) * perPage

		// Search organizations
		orgs, err := h.orgRepo.Search(c.Request.Context(), query, perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search organizations",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"organizations": orgs,
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
			},
		})
	}
}

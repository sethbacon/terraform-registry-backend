// organizations.go implements handlers for organization CRUD operations and membership management.
package admin

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// OrganizationHandlers handles organization management endpoints
type OrganizationHandlers struct {
	cfg     *config.Config
	db      *sql.DB
	orgRepo *repositories.OrganizationRepository
}

// NewOrganizationHandlers creates a new OrganizationHandlers instance
func NewOrganizationHandlers(cfg *config.Config, db *sql.DB) *OrganizationHandlers {
	return &OrganizationHandlers{
		cfg:     cfg,
		db:      db,
		orgRepo: repositories.NewOrganizationRepository(db),
	}
}

// @Summary      List organizations
// @Description  Get a paginated list of all organizations.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        page      query  int  false  "Page number (default 1)"
// @Param        per_page  query  int  false  "Items per page, max 100 (default 20)"
// @Success      200  {object}  map[string]interface{}  "organizations: []models.Organization, pagination: {page, per_page, total}"
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
// @Success      200  {object}  map[string]interface{}  "organization: models.Organization, members: []models.Member"
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
// @Success      200  {object}  map[string]interface{}  "members: []models.OrganizationMember"
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
// @Success      201  {object}  map[string]interface{}  "organization: models.Organization"
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

		c.JSON(http.StatusCreated, gin.H{
			"organization": org,
		})
	}
}

// UpdateOrganizationRequest represents the request to update an organization
type UpdateOrganizationRequest struct {
	DisplayName *string `json:"display_name"`
}

// @Summary      Update organization
// @Description  Update an existing organization's display name.
// @Tags         Organizations
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Organization ID"
// @Param        body  body  UpdateOrganizationRequest  true  "Fields to update"
// @Success      200  {object}  map[string]interface{}  "organization: models.Organization"
// @Failure      400  {object}  map[string]interface{}  "Invalid request body"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
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

		// Update fields
		if req.DisplayName != nil {
			org.DisplayName = *req.DisplayName
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
// @Success      200  {object}  map[string]interface{}  "message: Organization deleted successfully"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Organization not found"
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
// @Success      201  {object}  map[string]interface{}  "member: models.OrganizationMember with role info"
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
// @Success      200  {object}  map[string]interface{}  "member: models.OrganizationMember with role info"
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

		// Update role template
		member.RoleTemplateID = req.RoleTemplateID
		if err := h.orgRepo.UpdateMember(c.Request.Context(), member); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update member role",
			})
			return
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
// @Success      200  {object}  map[string]interface{}  "message: Member removed successfully"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/organizations/{id}/members/{user_id} [delete]
// RemoveMemberHandler removes a member from an organization
// DELETE /api/v1/organizations/:id/members/:user_id
func (h *OrganizationHandlers) RemoveMemberHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.Param("id")
		userID := c.Param("user_id")

		// Remove member
		if err := h.orgRepo.RemoveMember(c.Request.Context(), orgID, userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove member from organization",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Member removed successfully",
		})
	}
}

// @Summary      Search organizations
// @Description  Search organizations by name or display name with pagination.
// @Tags         Organizations
// @Security     Bearer
// @Produce      json
// @Param        q         query  string  true   "Search query"
// @Param        page      query  int     false  "Page number (default 1)"
// @Param        per_page  query  int     false  "Items per page, max 100 (default 20)"
// @Success      200  {object}  map[string]interface{}  "organizations: []models.Organization, pagination: map"
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

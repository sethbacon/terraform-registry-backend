// users.go implements handlers for user account CRUD operations including listing, creating, updating, and deleting users.
package admin

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// UserHandlers handles user management endpoints
type UserHandlers struct {
	cfg      *config.Config
	db       *sql.DB
	userRepo *repositories.UserRepository
	orgRepo  *repositories.OrganizationRepository
}

// NewUserHandlers creates a new UserHandlers instance
func NewUserHandlers(cfg *config.Config, db *sql.DB) *UserHandlers {
	return &UserHandlers{
		cfg:      cfg,
		db:       db,
		userRepo: repositories.NewUserRepository(db),
		orgRepo:  repositories.NewOrganizationRepository(db),
	}
}

// @Summary      List users
// @Description  Get a paginated list of all users with their organization role templates. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        page      query  int  false  "Page number (default 1)"
// @Param        per_page  query  int  false  "Items per page, max 100 (default 20)"
// @Success      200  {object}  map[string]interface{}  "users: []models.User, pagination: map"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users [get]
// ListUsersHandler lists all users with pagination
// GET /api/v1/users?page=1&per_page=20
func (h *UserHandlers) ListUsersHandler() gin.HandlerFunc {
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

		// Get users with role template information
		users, total, err := h.userRepo.ListUsersWithRoles(c.Request.Context(), perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list users",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
				"total":    total,
			},
		})
	}
}

// @Summary      Get user
// @Description  Get a user by ID with their organization memberships. Requires users:read scope.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  map[string]interface{}  "user: models.User, organizations: []models.Organization"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id} [get]
// GetUserHandler retrieves a specific user by ID
// GET /api/v1/users/:id
func (h *UserHandlers) GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Get user's organizations
		orgs, err := h.orgRepo.ListUserOrganizations(c.Request.Context(), userID)
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
// @Success      201  {object}  map[string]interface{}  "user: models.User"
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

		// Check if user already exists
		existingUser, err := h.userRepo.GetUserByEmail(c.Request.Context(), req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check existing user",
			})
			return
		}

		if existingUser != nil {
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

		if err := h.userRepo.Create(c.Request.Context(), user); err != nil {
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
// @Success      200  {object}  map[string]interface{}  "user: models.User"
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

		// Get existing user
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Update fields
		if req.Name != nil {
			user.Name = *req.Name
		}

		if req.Email != nil {
			// Check if email is already taken
			existingUser, err := h.userRepo.GetUserByEmail(c.Request.Context(), *req.Email)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check email availability",
				})
				return
			}

			if existingUser != nil && existingUser.ID != userID {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Email already in use by another user",
				})
				return
			}

			user.Email = *req.Email
		}

		// Update in database
		if err := h.userRepo.Update(c.Request.Context(), user); err != nil {
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
// @Success      200  {object}  map[string]interface{}  "message: User deleted successfully"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "User not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/users/{id} [delete]
// DeleteUserHandler deletes a user
// DELETE /api/v1/users/:id
func (h *UserHandlers) DeleteUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		// Check if user exists
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Delete user (cascading deletes will handle related records)
		if err := h.userRepo.Delete(c.Request.Context(), userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete user",
			})
			return
		}

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
// @Param        per_page  query  int     false  "Items per page, max 100 (default 20)"
// @Success      200  {object}  map[string]interface{}  "users: []models.User, pagination: map"
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

		// Search users
		users, err := h.userRepo.Search(c.Request.Context(), query, perPage, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to search users",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
			},
		})
	}
}

// @Summary      Get current user memberships
// @Description  Get the organization memberships for the currently authenticated user. No special scopes required.
// @Tags         Users
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "memberships: []models.OrganizationMembership"
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
// @Success      200  {object}  map[string]interface{}  "memberships: []models.OrganizationMembership"
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

		// Check if user exists
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
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

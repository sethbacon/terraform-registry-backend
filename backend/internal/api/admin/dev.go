// dev.go implements development-only handlers for bypassing authentication and switching active users in dev mode.
package admin

import (
	"database/sql"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// DevHandlers handles development-only endpoints
type DevHandlers struct {
	cfg      *config.Config
	db       *sql.DB
	userRepo *repositories.UserRepository
}

// NewDevHandlers creates a new DevHandlers instance
func NewDevHandlers(cfg *config.Config, db *sql.DB) *DevHandlers {
	return &DevHandlers{
		cfg:      cfg,
		db:       db,
		userRepo: repositories.NewUserRepository(db),
	}
}

// IsDevMode checks if the application is running in development mode.
// Requires explicit opt-in via DEV_MODE=true or DEV_MODE=1 environment variable.
func IsDevMode() bool {
	devMode := os.Getenv("DEV_MODE")
	return devMode == "true" || devMode == "1"
}

// DevModeMiddleware blocks access to dev endpoints in production
func DevModeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !IsDevMode() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Development endpoints are disabled in production",
			})
			return
		}
		c.Next()
	}
}

// ImpersonateUserHandler allows an admin to get a token as another user
// POST /api/v1/dev/impersonate/:user_id
// This is for development/testing only
func (h *DevHandlers) ImpersonateUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		targetUserID := c.Param("user_id")

		// Get current user's scopes to verify they're an admin
		scopesVal, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "No scopes found - must be authenticated",
			})
			return
		}

		scopes, ok := scopesVal.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid scopes format",
			})
			return
		}

		// Only admins can impersonate
		if !auth.HasScope(scopes, auth.ScopeAdmin) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Only administrators can impersonate users",
			})
			return
		}

		// Get the target user
		targetUser, err := h.userRepo.GetUserByID(c.Request.Context(), targetUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve user",
			})
			return
		}

		if targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Generate a new JWT for the target user
		token, err := auth.GenerateJWT(targetUser.ID, targetUser.Email, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token": token,
			"user":  targetUser,
			"message": "You are now impersonating " + targetUser.Email,
		})
	}
}

// ListUsersForImpersonationHandler returns a simplified list of users for the impersonation dropdown
// GET /api/v1/dev/users
func (h *DevHandlers) ListUsersForImpersonationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get current user's scopes to verify they're an admin
		scopesVal, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "No scopes found - must be authenticated",
			})
			return
		}

		scopes, ok := scopesVal.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid scopes format",
			})
			return
		}

		// Only admins can see impersonation list
		if !auth.HasScope(scopes, auth.ScopeAdmin) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Only administrators can access this endpoint",
			})
			return
		}

		// Get all users with their roles
		users, _, err := h.userRepo.ListUsers(c.Request.Context(), 100, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list users",
			})
			return
		}

		// Build simplified response with role info
		result := make([]gin.H, 0, len(users))
		for _, u := range users {
			userWithRoles, err := h.userRepo.GetUserWithOrgRoles(c.Request.Context(), u.ID)
			if err != nil {
				continue
			}

			// Get primary role name for display
			primaryRole := "No role"
			if userWithRoles != nil && len(userWithRoles.Memberships) > 0 {
				if userWithRoles.Memberships[0].RoleTemplateName != nil {
					primaryRole = *userWithRoles.Memberships[0].RoleTemplateDisplayName
				}
			}

			result = append(result, gin.H{
				"id":           u.ID,
				"email":        u.Email,
				"name":         u.Name,
				"primary_role": primaryRole,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"users":    result,
			"dev_mode": true,
		})
	}
}

// DevLoginHandler authenticates as the dev admin user and returns a JWT.
// This eliminates the need for a hardcoded API key in the frontend.
// POST /api/v1/dev/login
// Protected by DevModeMiddleware - returns 403 in production.
func (h *DevHandlers) DevLoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := h.userRepo.GetUserByEmail(c.Request.Context(), "admin@dev.local")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to look up dev admin user",
			})
			return
		}

		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Dev admin user (admin@dev.local) not found. Run the seed script: psql -f backend/scripts/create-dev-admin-user.sql",
			})
			return
		}

		token, err := auth.GenerateJWT(user.ID, user.Email, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"user":       user,
			"expires_in": 86400,
		})
	}
}

// DevStatusHandler returns dev mode status
// GET /api/v1/dev/status
func (h *DevHandlers) DevStatusHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"dev_mode": IsDevMode(),
			"message":  "Development mode is enabled",
		})
	}
}

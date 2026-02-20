// Package admin implements the administrative HTTP handlers for the Terraform Registry.
// These handlers require authentication and appropriate RBAC scopes (see internal/middleware/rbac.go)
// — unlike the Terraform protocol handlers in sibling packages (modules, providers, mirror) which
// are intentionally unauthenticated to match the HashiCorp protocol specification.
package admin

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// APIKeyHandlers handles API key management endpoints
type APIKeyHandlers struct {
	cfg        *config.Config
	db         *sql.DB
	apiKeyRepo *repositories.APIKeyRepository
	orgRepo    *repositories.OrganizationRepository
	userRepo   *repositories.UserRepository
}

// NewAPIKeyHandlers creates a new APIKeyHandlers instance
func NewAPIKeyHandlers(cfg *config.Config, db *sql.DB) *APIKeyHandlers {
	return &APIKeyHandlers{
		cfg:        cfg,
		db:         db,
		apiKeyRepo: repositories.NewAPIKeyRepository(db),
		orgRepo:    repositories.NewOrganizationRepository(db),
		userRepo:   repositories.NewUserRepository(db),
	}
}

// CreateAPIKeyRequest represents the request to create a new API key
type CreateAPIKeyRequest struct {
	Name           string   `json:"name" binding:"required"`
	OrganizationID string   `json:"organization_id" binding:"required"`
	Description    *string  `json:"description"`
	Scopes         []string `json:"scopes" binding:"required"`
	ExpiresAt      *string  `json:"expires_at"` // RFC3339 format
}

// CreateAPIKeyResponse represents the response when creating an API key
type CreateAPIKeyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Key         string     `json:"key"` // Only returned once during creation
	KeyPrefix   string     `json:"key_prefix"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// @Summary      List API keys
// @Description  List API keys with optional filtering by organization. Users with api_keys:manage scope can view all keys in an organization, otherwise only their own keys are visible.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        organization_id  query  string  false  "Filter by organization ID (optional)"
// @Success      200  {object}  map[string]interface{}  "List of API keys"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys [get]
// ListAPIKeysHandler lists API keys for the authenticated user
// GET /api/v1/apikeys
// If organization_id is provided:
//   - Users with api_keys:manage scope see all keys in that org
//   - Otherwise, users only see their own keys in that org
//
// If no organization_id: returns only the user's own keys across all orgs
func (h *APIKeyHandlers) ListAPIKeysHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context
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

		// Get organization filter if provided
		orgID := c.Query("organization_id")

		// Check if user has api_keys:manage scope (allows viewing all keys in org)
		scopesVal, _ := c.Get("scopes")
		scopes, _ := scopesVal.([]string)
		canManageAll := auth.HasScope(scopes, auth.ScopeAPIKeysManage) || auth.HasScope(scopes, auth.ScopeAdmin)

		var keys []*models.APIKey
		var err error

		if orgID != "" {
			if canManageAll {
				// Users with api_keys:manage can see all keys in the organization
				keys, err = h.apiKeyRepo.ListByOrganization(c.Request.Context(), orgID)
			} else {
				// Regular users only see their own keys in the organization
				keys, err = h.apiKeyRepo.ListByUserAndOrganization(c.Request.Context(), userID, orgID)
			}
		} else if canManageAll {
			// Admins can see all keys across all organizations
			keys, err = h.apiKeyRepo.ListAll(c.Request.Context())
		} else {
			// Regular users only see their own keys across all organizations
			keys, err = h.apiKeyRepo.ListByUser(c.Request.Context(), userID)
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list API keys",
			})
			return
		}

		// Map keys to a JSON-friendly shape (snake_case) and avoid exposing sensitive data
		resp := make([]gin.H, 0, len(keys))
		for _, k := range keys {
			var expiresAt interface{}
			var lastUsed interface{}

			if k.ExpiresAt != nil {
				expiresAt = k.ExpiresAt.Format(time.RFC3339)
			} else {
				expiresAt = nil
			}

			if k.LastUsedAt != nil {
				lastUsed = k.LastUsedAt.Format(time.RFC3339)
			} else {
				lastUsed = nil
			}

			desc := ""
			if k.Description != nil {
				desc = *k.Description
			}

			resp = append(resp, gin.H{
				"id":           k.ID,
				"user_id":      k.UserID,
				"user_name":    k.UserName,
				"name":         k.Name,
				"description":  desc,
				"key_prefix":   k.KeyPrefix,
				"scopes":       k.Scopes,
				"expires_at":   expiresAt,
				"last_used_at": lastUsed,
				"created_at":   k.CreatedAt.Format(time.RFC3339),
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"keys": resp,
		})
	}
}

// @Summary      Create API key
// @Description  Create a new API key with specified scopes. The full API key is only returned once during creation.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  CreateAPIKeyRequest  true  "API key creation request"
// @Success      201  {object}  CreateAPIKeyResponse  "API key created successfully (full key returned once)"
// @Failure      400  {object}  map[string]interface{}  "Invalid request or scopes"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - no role or scopes exceed permissions"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys [post]
// CreateAPIKeyHandler creates a new API key
// POST /api/v1/apikeys
func (h *APIKeyHandlers) CreateAPIKeyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateAPIKeyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		// Get user ID from context
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

		// Validate scopes are valid scope strings
		if err := auth.ValidateScopes(req.Scopes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid scopes: " + err.Error(),
			})
			return
		}

		// Resolve organization ID - if 'default', get the actual default org ID
		orgID := req.OrganizationID
		if orgID == "default" || orgID == "" {
			defaultOrg, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get default organization",
				})
				return
			}
			if defaultOrg == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Default organization not found",
				})
				return
			}
			orgID = defaultOrg.ID
		}

		// Get user's role template for this organization to validate scope permissions
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get user role information",
			})
			return
		}

		if memberWithRole == nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "You are not a member of this organization",
			})
			return
		}

		// Check if user has a role template assigned for this org
		if memberWithRole.RoleTemplateID == nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "No role template assigned for this organization. Contact an administrator to assign a role.",
			})
			return
		}

		// Validate requested scopes are within user's allowed scopes for this org
		// Admin scope grants all permissions
		userHasAdmin := false
		for _, scope := range memberWithRole.RoleTemplateScopes {
			if scope == "admin" {
				userHasAdmin = true
				break
			}
		}

		if !userHasAdmin {
			// Check each requested scope is in user's allowed scopes
			allowedScopeSet := make(map[string]bool)
			for _, s := range memberWithRole.RoleTemplateScopes {
				allowedScopeSet[s] = true
			}

			for _, requestedScope := range req.Scopes {
				if !allowedScopeSet[requestedScope] {
					c.JSON(http.StatusForbidden, gin.H{
						"error":          "Scope '" + requestedScope + "' exceeds your role permissions for this organization",
						"allowed_scopes": memberWithRole.RoleTemplateScopes,
						"role_template":  *memberWithRole.RoleTemplateName,
					})
					return
				}
			}
		}

		// Parse expiration if provided
		var expiresAt *time.Time
		if req.ExpiresAt != nil {
			parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid expires_at format. Use RFC3339",
				})
				return
			}
			expiresAt = &parsed
		}

		// Generate API key
		keyPrefix := "tfr" // Terraform Registry
		fullKey, keyHash, displayPrefix, err := auth.GenerateAPIKey(keyPrefix)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate API key",
			})
			return
		}

		// Create API key in database
		apiKey := &models.APIKey{
			UserID:         &userID,
			OrganizationID: orgID,
			Name:           req.Name,
			Description:    req.Description,
			KeyHash:        keyHash,
			KeyPrefix:      displayPrefix,
			Scopes:         req.Scopes,
			ExpiresAt:      expiresAt,
			CreatedAt:      time.Now(),
		}

		if err := h.apiKeyRepo.Create(c.Request.Context(), apiKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create API key",
			})
			return
		}

		// Return full key (only time it's visible)
		c.JSON(http.StatusCreated, CreateAPIKeyResponse{
			ID:        apiKey.ID,
			Name:      apiKey.Name,
			Key:       fullKey, // IMPORTANT: Only returned once
			KeyPrefix: displayPrefix,
			Scopes:    apiKey.Scopes,
			ExpiresAt: apiKey.ExpiresAt,
			CreatedAt: apiKey.CreatedAt,
		})
	}
}

// @Summary      Get API key
// @Description  Retrieve a specific API key by ID. Users can only access their own keys unless they have admin scope.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id  path  string  true  "API key ID"
// @Success      200  {object}  map[string]interface{}  "API key details"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - access denied to this key"
// @Failure      404  {object}  map[string]interface{}  "API key not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys/{id} [get]
// GetAPIKeyHandler retrieves a specific API key
// GET /api/v1/apikeys/:id
func (h *APIKeyHandlers) GetAPIKeyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")

		// Get API key
		apiKey, err := h.apiKeyRepo.GetByID(c.Request.Context(), keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
			})
			return
		}

		if apiKey == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}

		// Check authorization (user can only access their own keys)
		userIDVal, _ := c.Get("user_id")
		userID, _ := userIDVal.(string)

		if apiKey.UserID == nil || *apiKey.UserID != userID {
			// Check if user has admin scope
			scopesVal, _ := c.Get("scopes")
			scopes, _ := scopesVal.([]string)
			if !auth.HasScope(scopes, auth.ScopeAdmin) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"key": apiKey,
		})
	}
}

// @Summary      Delete API key
// @Description  Delete a specific API key by ID. Users can only delete their own keys unless they have admin scope.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id  path  string  true  "API key ID"
// @Success      200  {object}  map[string]interface{}  "Deletion confirmation"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - access denied to this key"
// @Failure      404  {object}  map[string]interface{}  "API key not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys/{id} [delete]
// DeleteAPIKeyHandler deletes an API key
// DELETE /api/v1/apikeys/:id
func (h *APIKeyHandlers) DeleteAPIKeyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")

		// Get API key first to check authorization
		apiKey, err := h.apiKeyRepo.GetByID(c.Request.Context(), keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
			})
			return
		}

		if apiKey == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}

		// Check authorization
		userIDVal, _ := c.Get("user_id")
		userID, _ := userIDVal.(string)

		if apiKey.UserID == nil || *apiKey.UserID != userID {
			// Check if user has admin scope
			scopesVal, _ := c.Get("scopes")
			scopes, _ := scopesVal.([]string)
			if !auth.HasScope(scopes, auth.ScopeAdmin) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
				})
				return
			}
		}

		// Delete API key
		if err := h.apiKeyRepo.Delete(c.Request.Context(), keyID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete API key",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "API key deleted successfully",
		})
	}
}

// @Summary      Update API key
// @Description  Update an API key's name, scopes, or expiration. Users can only update their own keys unless they have admin scope.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string      true  "API key ID"
// @Param        body  body  object      true  "Update request with optional name, scopes, and expires_at fields"
// @Success      200  {object}  map[string]interface{}  "Updated API key details"
// @Failure      400  {object}  map[string]interface{}  "Invalid request or scopes"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - access denied or scopes exceed permissions"
// @Failure      404  {object}  map[string]interface{}  "API key not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys/{id} [put]
// UpdateAPIKeyHandler updates an API key (name, scopes, expiration)
// PUT /api/v1/apikeys/:id
func (h *APIKeyHandlers) UpdateAPIKeyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")

		var req struct {
			Name      *string  `json:"name"`
			Scopes    []string `json:"scopes"`
			ExpiresAt *string  `json:"expires_at"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		// Get API key
		apiKey, err := h.apiKeyRepo.GetByID(c.Request.Context(), keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
			})
			return
		}

		if apiKey == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}

		// Check authorization
		userIDVal, _ := c.Get("user_id")
		userID, _ := userIDVal.(string)

		if apiKey.UserID == nil || *apiKey.UserID != userID {
			scopesVal, _ := c.Get("scopes")
			scopes, _ := scopesVal.([]string)
			if !auth.HasScope(scopes, auth.ScopeAdmin) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
				})
				return
			}
		}

		// Update fields
		if req.Name != nil {
			apiKey.Name = *req.Name
		}

		if req.Scopes != nil {
			if err := auth.ValidateScopes(req.Scopes); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid scopes: " + err.Error(),
				})
				return
			}

			// Get user's role template for this org to validate scope permissions
			memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), apiKey.OrganizationID, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get user role information",
				})
				return
			}

			if memberWithRole != nil && memberWithRole.RoleTemplateID != nil {
				// Validate requested scopes are within user's allowed scopes for this org
				userHasAdmin := false
				for _, scope := range memberWithRole.RoleTemplateScopes {
					if scope == "admin" {
						userHasAdmin = true
						break
					}
				}

				if !userHasAdmin {
					allowedScopeSet := make(map[string]bool)
					for _, s := range memberWithRole.RoleTemplateScopes {
						allowedScopeSet[s] = true
					}

					for _, requestedScope := range req.Scopes {
						if !allowedScopeSet[requestedScope] {
							c.JSON(http.StatusForbidden, gin.H{
								"error":          "Scope '" + requestedScope + "' exceeds your role permissions for this organization",
								"allowed_scopes": memberWithRole.RoleTemplateScopes,
								"role_template":  *memberWithRole.RoleTemplateName,
							})
							return
						}
					}
				}
			}

			apiKey.Scopes = req.Scopes
		}

		if req.ExpiresAt != nil {
			parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid expires_at format. Use RFC3339",
				})
				return
			}
			apiKey.ExpiresAt = &parsed
		}

		// Update in database
		if err := h.apiKeyRepo.Update(c.Request.Context(), apiKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update API key",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"key": apiKey,
		})
	}
}

// RotateAPIKeyRequest represents the request to rotate an API key
type RotateAPIKeyRequest struct {
	// GracePeriodHours is how long the old key should remain valid (0 = immediate revocation)
	GracePeriodHours int `json:"grace_period_hours"`
}

// RotateAPIKeyResponse represents the response when rotating an API key
type RotateAPIKeyResponse struct {
	NewKey       CreateAPIKeyResponse `json:"new_key"`
	OldKeyStatus string               `json:"old_key_status"` // "revoked" or "expires_at"
	OldExpiresAt *time.Time           `json:"old_expires_at,omitempty"`
}

// @Summary      Rotate API key
// @Description  Rotate an API key by creating a new key and optionally scheduling the old key's expiration. Users can only rotate their own keys unless they have admin scope.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                  true  "API key ID"
// @Param        body  body  RotateAPIKeyRequest     true  "Rotation request with optional grace period (0-72 hours)"
// @Success      200  {object}  RotateAPIKeyResponse  "New API key and old key status"
// @Failure      400  {object}  map[string]interface{}  "Invalid grace period (must be 0-72 hours)"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - access denied to this key"
// @Failure      404  {object}  map[string]interface{}  "API key not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys/{id}/rotate [post]
// RotateAPIKeyHandler rotates an API key - creates a new key and optionally schedules old key expiration
// POST /api/v1/apikeys/:id/rotate
func (h *APIKeyHandlers) RotateAPIKeyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")

		var req RotateAPIKeyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			// Default to immediate revocation if no body provided
			req.GracePeriodHours = 0
		}

		// Validate grace period (max 72 hours)
		if req.GracePeriodHours < 0 || req.GracePeriodHours > 72 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "grace_period_hours must be between 0 and 72",
			})
			return
		}

		// Get the existing API key
		oldKey, err := h.apiKeyRepo.GetByID(c.Request.Context(), keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
			})
			return
		}

		if oldKey == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}

		// Check authorization - user can only rotate their own keys
		userIDVal, _ := c.Get("user_id")
		userID, _ := userIDVal.(string)

		if oldKey.UserID == nil || *oldKey.UserID != userID {
			// Check if user has admin scope
			scopesVal, _ := c.Get("scopes")
			scopes, _ := scopesVal.([]string)
			if !auth.HasScope(scopes, auth.ScopeAdmin) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
				})
				return
			}
		}

		// Generate new API key
		keyPrefix := "tfr"
		fullKey, keyHash, displayPrefix, err := auth.GenerateAPIKey(keyPrefix)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate new API key",
			})
			return
		}

		// Create new API key with same properties as old one
		newKey := &models.APIKey{
			UserID:         oldKey.UserID,
			OrganizationID: oldKey.OrganizationID,
			Name:           oldKey.Name + " (rotated)",
			Description:    oldKey.Description,
			KeyHash:        keyHash,
			KeyPrefix:      displayPrefix,
			Scopes:         oldKey.Scopes,
			ExpiresAt:      oldKey.ExpiresAt, // Keep same expiration policy
			CreatedAt:      time.Now(),
		}

		if err := h.apiKeyRepo.Create(c.Request.Context(), newKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create new API key",
			})
			return
		}

		// Handle old key based on grace period
		var oldKeyStatus string
		var oldExpiresAt *time.Time

		if req.GracePeriodHours == 0 {
			// Immediate revocation - delete the old key
			if err := h.apiKeyRepo.Delete(c.Request.Context(), oldKey.ID); err != nil {
				// Log error but don't fail - new key is already created
				// The user might need to manually delete the old key
				oldKeyStatus = "revocation_failed"
			} else {
				oldKeyStatus = "revoked"
			}
		} else {
			// Schedule expiration of old key
			gracePeriodEnd := time.Now().Add(time.Duration(req.GracePeriodHours) * time.Hour)
			oldKey.ExpiresAt = &gracePeriodEnd
			if err := h.apiKeyRepo.Update(c.Request.Context(), oldKey); err != nil {
				oldKeyStatus = "grace_period_update_failed"
			} else {
				oldKeyStatus = "expires_at"
				oldExpiresAt = &gracePeriodEnd
			}
		}

		c.JSON(http.StatusOK, RotateAPIKeyResponse{
			NewKey: CreateAPIKeyResponse{
				ID:        newKey.ID,
				Name:      newKey.Name,
				Key:       fullKey, // IMPORTANT: Only returned once
				KeyPrefix: displayPrefix,
				Scopes:    newKey.Scopes,
				ExpiresAt: newKey.ExpiresAt,
				CreatedAt: newKey.CreatedAt,
			},
			OldKeyStatus: oldKeyStatus,
			OldExpiresAt: oldExpiresAt,
		})
	}
}

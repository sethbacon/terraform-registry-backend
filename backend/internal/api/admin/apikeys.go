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
	"github.com/terraform-registry/terraform-registry/internal/credscope"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
)

// TENANCY OF THE BY-ID API-KEY ROUTES.
//
// GET/PUT/DELETE/rotate on /apikeys/:id read the row with
// OrgScopeAllOrganizations() and then authorize it in memory: the caller must
// OWN the key, or hold the platform-wide admin wildcard. That check is not an
// organization scope and cannot be expressed as one — a plain user with no
// api_keys:manage anywhere must still reach their own key, in whichever
// organization it is bound to — so narrowing the read would 404 every ordinary
// owner. The in-memory check is strictly stronger than any OrgScope these
// callers could resolve, and it is what decides the 403.
//
// The WRITES that follow are scoped to the organization of the row just read
// (OrgScopeOrganizations(key.OrganizationID)), so the statement that mutates a
// credential carries the tenant predicate the read deliberately did not: a key
// that moved organizations between the read and the write is refused rather
// than rewritten from a stale snapshot.

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
// @Success      200  {object}  admin.ListAPIKeysResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/apikeys [get]
// ListAPIKeysHandler lists API keys for the authenticated user
// GET /api/v1/apikeys
// If organization_id is provided:
//   - Platform admins, and callers holding api_keys:manage IN THAT ORG, see all keys in the org
//   - Otherwise, callers only see their own keys in that org
//
// If no organization_id:
//   - Platform admins see all keys across all orgs
//   - Otherwise, callers see only their own keys across all orgs
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

		// Platform admins (holders of the platform-wide "admin" wildcard) may view
		// every key. For everyone else the "see all keys" decision must be derived
		// from the caller's scopes IN THE TARGET ORGANIZATION, never from their
		// login-time cross-org scope union (c.Get("scopes")). api_keys:manage is a
		// per-org role-template scope, so trusting the global union would let a
		// user_manager in org A enumerate every key's metadata (id, name,
		// description, key_prefix, scopes, owner, expiry) in an unrelated org B --
		// the same global-union-as-ceiling defect fixed for role assignment
		// (role_ceiling.go) and key updates (UpdateAPIKeyHandler) in this batch
		// (issue #648 class, CWE-266). Likewise, only platform admins may list keys
		// across every org (ListAll); a per-org api_keys:manage holder must not.
		scopesVal, _ := c.Get("scopes")
		scopes, _ := scopesVal.([]string)
		isPlatformAdmin := auth.HasScope(scopes, auth.ScopeAdmin)
		// The global union is a superset of every per-org scope set, so a caller
		// who lacks api_keys:manage here cannot hold it in ANY org -- skip the
		// per-org lookup for them. A caller who DOES hold it globally might hold it
		// only in a *different* org, so their management right is re-confirmed
		// against the specific target org below before all keys are disclosed.
		hasGlobalManage := isPlatformAdmin || auth.HasScope(scopes, auth.ScopeAPIKeysManage)

		var keys []*models.APIKey
		var err error

		switch {
		case orgID != "":
			// Re-derive per-org whether the caller may manage all keys in THIS org.
			canManageOrg := isPlatformAdmin
			if !canManageOrg && hasGlobalManage {
				orgScopes, scErr := h.orgRepo.GetUserScopesForOrg(c.Request.Context(), userID, orgID)
				if scErr != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"error": "Failed to list API keys",
					})
					return
				}
				canManageOrg = auth.HasScope(orgScopes, auth.ScopeAPIKeysManage)
			}
			if canManageOrg {
				// Caller manages keys in this org: see all keys in the org.
				keys, err = h.apiKeyRepo.ListAPIKeysByOrganization(c.Request.Context(), orgID,
					repositories.OrgScopeOrganizations(orgID))
			} else {
				// Otherwise only the caller's own keys in the org.
				keys, err = h.apiKeyRepo.ListByUserAndOrganization(c.Request.Context(), userID, orgID,
					repositories.OrgScopeOrganizations(orgID))
			}
		case isPlatformAdmin:
			// Only platform admins may enumerate keys across all organizations.
			keys, err = h.apiKeyRepo.ListAPIKeys(c.Request.Context(), repositories.OrgScopeAllOrganizations())
		default:
			// Regular users only see their own keys across all organizations.
			keys, err = h.apiKeyRepo.ListAPIKeysByUser(c.Request.Context(), userID, repositories.OrgScopeAllOrganizations())
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
			var expiryNotifSentAt interface{}

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

			if k.ExpiryNotificationSentAt != nil {
				expiryNotifSentAt = k.ExpiryNotificationSentAt.Format(time.RFC3339)
			} else {
				expiryNotifSentAt = nil
			}

			desc := ""
			if k.Description != nil {
				desc = *k.Description
			}

			resp = append(resp, gin.H{
				"id":                          k.ID,
				"user_id":                     k.UserID,
				"user_name":                   k.UserName,
				"name":                        k.Name,
				"description":                 desc,
				"key_prefix":                  k.KeyPrefix,
				"scopes":                      k.Scopes,
				"expires_at":                  expiresAt,
				"last_used_at":                lastUsed,
				"expiry_notification_sent_at": expiryNotifSentAt,
				"created_at":                  k.CreatedAt.Format(time.RFC3339),
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"keys": resp,
		})
	}
}

// @Summary      Create API key
// @Description  Create a new API key with specified scopes. The full API key is only returned once during creation. Requested scopes must be within the caller's role template for the organization AND within the scopes of the credential making the request, so an API key can never mint a key broader than itself.
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
			// A deployment with no default organization is a misconfiguration,
			// not a client error, so BOTH branches stay 500 — only the message
			// differs, and the miss now gets the message that actually names
			// the problem instead of the generic lookup failure.
			defaultOrg, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
			if identityerr.Missing(defaultOrg, err) {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Default organization not found",
				})
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get default organization",
				})
				return
			}
			orgID = defaultOrg.ID
		}

		// Get user's role template for this organization to validate scope permissions
		memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), orgID, userID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(memberWithRole, err) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "You are not a member of this organization",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get user role information",
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

		// Validate requested scopes are within the ceiling this REQUEST may
		// grant. Admin scope grants all permissions.
		//
		// GUARD credential-scope-binding (issue #733). The ceiling is the
		// caller's role template in this organization, intersected with the
		// scopes of the credential that made the request. Deriving it from the
		// role template alone answered "what may this USER grant" when the
		// question is "what may this CREDENTIAL grant": /apikeys carries no
		// RequireScope (self-service key management is deliberately open to any
		// authenticated caller) and CSRFMiddleware exempts API-key callers, so a
		// key deliberately narrowed to modules:read could POST
		// {"scopes":["admin"]} and receive a platform-wide key whenever its
		// owner held the admin role template. Narrowing a machine credential
		// must contain it; credscope.Bound is a no-op for the interactive
		// sessions the UI uses.
		allowedScopes := credscope.Bound(c, memberWithRole.RoleTemplateScopes)

		callerHasAdmin := false
		for _, scope := range allowedScopes {
			if scope == "admin" {
				callerHasAdmin = true
				break
			}
		}

		if !callerHasAdmin {
			// Check each requested scope is within the ceiling
			allowedScopeSet := make(map[string]bool)
			for _, s := range allowedScopes {
				allowedScopeSet[s] = true
			}

			for _, requestedScope := range req.Scopes {
				if !allowedScopeSet[requestedScope] {
					c.JSON(http.StatusForbidden, gin.H{
						"error":          "Scope '" + requestedScope + "' exceeds the permissions available to this request",
						"allowed_scopes": allowedScopes,
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

		if err := h.apiKeyRepo.CreateAPIKey(c.Request.Context(), apiKey, repositories.OrgScopeOrganizations(orgID)); err != nil {
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
// @Success      200  {object}  admin.APIKeyResponse
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
		apiKey, err := h.apiKeyRepo.GetAPIKeyByID(c.Request.Context(), keyID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(apiKey, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
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
// @Success      200  {object}  admin.MessageResponse
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
		apiKey, err := h.apiKeyRepo.GetAPIKeyByID(c.Request.Context(), keyID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(apiKey, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
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

		// Delete API key. A miss means the key went away between the GetByID
		// above and this write; report 404, the same answer the pre-check gives
		// a second DELETE, rather than the "deleted successfully" the old
		// contract returned for a deletion that did nothing.
		if err := h.apiKeyRepo.RevokeAPIKey(c.Request.Context(), keyID, repositories.OrgScopeOrganizations(apiKey.OrganizationID)); err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "API key not found",
				})
				return
			}
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
// @Description  Update an API key's name, scopes, or expiration. Users can only update their own keys unless they have admin scope. New scopes are bounded the same way as on creation: by the caller's role template in the key's organization AND by the scopes of the credential making the request.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string      true  "API key ID"
// @Param        body  body  object      true  "Update request with optional name, scopes, and expires_at fields"
// @Success      200  {object}  admin.APIKeyResponse
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
		apiKey, err := h.apiKeyRepo.GetAPIKeyByID(c.Request.Context(), keyID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(apiKey, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
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
			memberWithRole, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), apiKey.OrganizationID, userID, repositories.OrgScopeAllOrganizations())

			// Fail closed exactly like CreateAPIKeyHandler: changing a key's scopes
			// requires a current role in the key's organization. The previous code
			// only enforced the ceiling when membership+role were present and
			// otherwise applied req.Scopes verbatim, so a key owner who had been
			// removed from the org (or had their role template cleared) could widen
			// an org-bound key to "admin". The key survives removal — RemoveMember
			// does not delete keys, and API-key auth sets scopes from the stored key
			// without consulting the revocation watermark — so the owner could
			// re-authenticate with the key and self-escalate to a platform-wide
			// admin wildcard (issue #650, CWE-269). A null role template grants zero
			// scopes and must be treated as such.
			//
			// The non-membership denial is tested BEFORE the lookup-failure
			// branch. Ordered the other way, identity v0.24.0's store.ErrNotFound
			// would be consumed by `err != nil` and a removed member's
			// scope-widening attempt would return 500 instead of 403 — still
			// refused, but for the wrong reason and with a retryable status on
			// a privilege-escalation path.
			if identityerr.Missing(memberWithRole, err) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "You are not a member of this organization",
				})
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get user role information",
				})
				return
			}
			if memberWithRole.RoleTemplateID == nil {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "No role template assigned for this organization. Contact an administrator to assign a role.",
				})
				return
			}

			// Validate requested scopes are within the ceiling this REQUEST may
			// grant.
			//
			// GUARD credential-scope-binding (issue #733): the same ceiling
			// CreateAPIKeyHandler applies, for the same reason. Widening an
			// existing key is minting authority by another name, so a narrowed
			// credential must not be able to do it either — including on the
			// key it is itself presenting.
			allowedScopes := credscope.Bound(c, memberWithRole.RoleTemplateScopes)

			callerHasAdmin := false
			for _, scope := range allowedScopes {
				if scope == "admin" {
					callerHasAdmin = true
					break
				}
			}

			if !callerHasAdmin {
				allowedScopeSet := make(map[string]bool)
				for _, s := range allowedScopes {
					allowedScopeSet[s] = true
				}

				for _, requestedScope := range req.Scopes {
					if !allowedScopeSet[requestedScope] {
						c.JSON(http.StatusForbidden, gin.H{
							"error":          "Scope '" + requestedScope + "' exceeds the permissions available to this request",
							"allowed_scopes": allowedScopes,
							"role_template":  *memberWithRole.RoleTemplateName,
						})
						return
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

		// Update in database. Raced against a delete: 404, matching the
		// existence pre-check above.
		if err := h.apiKeyRepo.Update(c.Request.Context(), apiKey, repositories.OrgScopeOrganizations(apiKey.OrganizationID)); err != nil {
			if identityerr.IsNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "API key not found",
				})
				return
			}
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
// @Description  Rotate an API key by creating a new key and optionally scheduling the old key's expiration. Users can only rotate their own keys unless they have admin scope. The new key's scopes are re-derived from the key owner's current role template rather than copied from the old key, and are additionally bounded by the scopes of the credential making the request, so a rotation cannot re-mint authority the owner no longer holds.
// @Tags         API Keys
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                  true  "API key ID"
// @Param        body  body  RotateAPIKeyRequest     true  "Rotation request with optional grace period (0-72 hours)"
// @Success      200  {object}  RotateAPIKeyResponse  "New API key and old key status"
// @Failure      400  {object}  map[string]interface{}  "Invalid grace period (must be 0-72 hours)"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized - user not authenticated"
// @Failure      403  {object}  map[string]interface{}  "Forbidden - access denied to this key, or the key's scopes exceed the authority available to this request"
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
		oldKey, err := h.apiKeyRepo.GetAPIKeyByID(c.Request.Context(), keyID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(oldKey, err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "API key not found",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve API key",
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

		// GUARD credential-scope-binding (issue #733). Rotation MINTS a key, so
		// the scopes it writes need the same ceiling as creation — re-derived,
		// not inherited. Copying oldKey.Scopes and authorizing on ownership
		// alone made rotation a scope-laundering primitive: it was the one
		// minting path with no ceiling at all, so a narrowed credential could
		// rotate a broader sibling key of its owner's and receive that key's
		// full scopes, and a key whose owner had since been demoted could
		// re-mint the authority the demotion removed.
		//
		// The user half of the ceiling is the KEY OWNER's current role
		// template, not the caller's: rotation re-issues the owner's
		// credential, and reading the caller's membership would 403 a platform
		// admin rotating a key in an organization they do not belong to. The
		// credential half is still the caller's, so a narrow key cannot launder
		// scopes through a rotation it is not entitled to perform.
		if oldKey.UserID == nil || *oldKey.UserID == "" {
			// Matches middleware.verifyKeyOwnerAuthority: a userless key is a
			// row whose owner was deleted (identity.api_keys.user_id is
			// ON DELETE SET NULL), not an organization service credential, and
			// there is no authority left to re-derive for it.
			c.JSON(http.StatusForbidden, gin.H{
				"error": "API key has no owning user; re-issue it through the API key endpoints",
			})
			return
		}
		owner, err := h.orgRepo.GetMemberWithRole(c.Request.Context(), oldKey.OrganizationID, *oldKey.UserID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(owner, err) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "API key owner is no longer a member of the key's organization",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get user role information",
			})
			return
		}

		rotateScopes := credscope.Bound(c, owner.RoleTemplateScopes)
		ownerHasAdmin := false
		for _, scope := range rotateScopes {
			if scope == "admin" {
				ownerHasAdmin = true
				break
			}
		}
		if !ownerHasAdmin {
			allowedScopeSet := make(map[string]bool)
			for _, s := range rotateScopes {
				allowedScopeSet[s] = true
			}
			for _, existingScope := range oldKey.Scopes {
				if !allowedScopeSet[existingScope] {
					c.JSON(http.StatusForbidden, gin.H{
						"error":          "Scope '" + existingScope + "' exceeds the permissions available to this request; update the key's scopes before rotating it",
						"allowed_scopes": rotateScopes,
					})
					return
				}
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

		if err := h.apiKeyRepo.CreateAPIKey(c.Request.Context(), newKey, repositories.OrgScopeOrganizations(newKey.OrganizationID)); err != nil {
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
			// An already-absent old key IS revoked — that is the desired end
			// state, so it reports "revoked" rather than "revocation_failed".
			// Calling it a failure would send an operator hunting for a key
			// that no longer exists.
			if err := h.apiKeyRepo.RevokeAPIKey(c.Request.Context(), oldKey.ID, repositories.OrgScopeOrganizations(oldKey.OrganizationID)); err != nil &&
				!identityerr.IsNotFound(err) {
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
			// Unlike the immediate-revocation branch above, a missing old key
			// cannot be reported as a successful grace-period extension: there
			// is no row left to expire, so the caller is told the update did
			// not land.
			if err := h.apiKeyRepo.Update(c.Request.Context(), oldKey, repositories.OrgScopeOrganizations(oldKey.OrganizationID)); err != nil {
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

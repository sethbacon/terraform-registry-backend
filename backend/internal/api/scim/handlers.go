// Package scim implements SCIM 2.0 provisioning endpoints (RFC 7644)
// for user and group management by external identity providers.
package scim

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// SCIM Schema URIs
const (
	SchemaUser     = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResp = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError    = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// Handlers provides SCIM 2.0 REST endpoints.
type Handlers struct {
	cfg      *config.Config
	db       *sql.DB
	userRepo *repositories.UserRepository
	orgRepo  *repositories.OrganizationRepository
}

// NewHandlers creates a SCIM handler set.
func NewHandlers(cfg *config.Config, db *sql.DB) *Handlers {
	return &Handlers{
		cfg:      cfg,
		db:       db,
		userRepo: repositories.NewUserRepository(db),
		orgRepo:  repositories.NewOrganizationRepository(db),
	}
}

// --- SCIM Resource types ---

// SCIMUser is a SCIM 2.0 User resource representation.
type SCIMUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       SCIMMeta    `json:"meta"`
}

// SCIMName is the SCIM name sub-object.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// SCIMEmail is the SCIM email sub-object.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}

// SCIMMeta is the SCIM metadata sub-object.
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location,omitempty"`
}

// SCIMListResponse is the SCIM 2.0 ListResponse.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	ItemsPerPage int         `json:"itemsPerPage"`
	StartIndex   int         `json:"startIndex"`
	Resources    interface{} `json:"Resources"`
}

// SCIMError is the SCIM 2.0 error response.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMPatchOp represents a SCIM PATCH request.
type SCIMPatchOp struct {
	Schemas    []string        `json:"schemas"`
	Operations []SCIMOperation `json:"Operations"`
}

// SCIMOperation is a single SCIM PATCH operation.
type SCIMOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// --- User endpoints ---

// @Summary      List SCIM users
// @Description  Returns a paginated list of users in SCIM 2.0 format. Supports optional filter parameter (e.g., userName eq "alice@example.com").
// @Tags         SCIM
// @Security     Bearer
// @Produce      json
// @Param        startIndex  query  int     false  "1-based start index"  default(1)
// @Param        count       query  int     false  "Page size (max 200)"  default(100)
// @Param        filter      query  string  false  "SCIM filter expression"
// @Success      200  {object}  scim.SCIMListResponse  "SCIM list response"
// @Failure      401  {object}  scim.SCIMError  "Unauthorized"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Users [get]
// ListUsers handles GET /scim/v2/Users
func (h *Handlers) ListUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "1"))
		count, _ := strconv.Atoi(c.DefaultQuery("count", "100"))
		if startIndex < 1 {
			startIndex = 1
		}
		if count < 1 || count > 200 {
			count = 100
		}
		filter := c.Query("filter")
		offset := startIndex - 1
		ctx := c.Request.Context()

		var users []*models.User
		var total int
		var err error

		if filter != "" {
			value := extractFilterValue(filter)
			if value != "" {
				users, err = h.userRepo.Search(ctx, value, count, offset)
				total = len(users)
			} else {
				users, total, err = h.userRepo.ListUsers(ctx, count, offset)
			}
		} else {
			users, total, err = h.userRepo.ListUsers(ctx, count, offset)
		}

		if err != nil {
			slog.Error("scim: list users failed", "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to list users")
			return
		}

		base := h.baseURL(c)
		resources := make([]SCIMUser, 0, len(users))
		for _, u := range users {
			resources = append(resources, userToSCIM(u, base))
		}

		c.JSON(http.StatusOK, SCIMListResponse{
			Schemas:      []string{SchemaListResp},
			TotalResults: total,
			ItemsPerPage: count,
			StartIndex:   startIndex,
			Resources:    resources,
		})
	}
}

// @Summary      Get SCIM user
// @Description  Returns a single user in SCIM 2.0 format by ID.
// @Tags         SCIM
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "User ID"
// @Success      200  {object}  scim.SCIMUser  "SCIM user resource"
// @Failure      404  {object}  scim.SCIMError  "User not found"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Users/{id} [get]
// GetUser handles GET /scim/v2/Users/:id
func (h *Handlers) GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			slog.Error("scim: get user failed", "id", userID, "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to get user")
			return
		}
		if user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}
		c.JSON(http.StatusOK, userToSCIM(user, h.baseURL(c)))
	}
}

// @Summary      Create SCIM user
// @Description  Provisions a new user via SCIM 2.0. Requires userName or emails[0].value. Uses externalId as the identity link.
// @Tags         SCIM
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  scim.SCIMUser  true  "SCIM user resource"
// @Success      201  {object}  scim.SCIMUser  "Created SCIM user"
// @Failure      400  {object}  scim.SCIMError  "Invalid payload"
// @Failure      409  {object}  scim.SCIMError  "User already exists"
// @Router       /scim/v2/Users [post]
// CreateUser handles POST /scim/v2/Users
func (h *Handlers) CreateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SCIMUser
		if err := c.ShouldBindJSON(&req); err != nil {
			scimError(c, http.StatusBadRequest, "Invalid SCIM user payload")
			return
		}

		email := req.UserName
		if email == "" && len(req.Emails) > 0 {
			email = req.Emails[0].Value
		}
		if email == "" {
			scimError(c, http.StatusBadRequest, "userName or emails[0].value is required")
			return
		}

		displayName := ""
		if req.Name != nil {
			displayName = req.Name.Formatted
			if displayName == "" {
				parts := []string{req.Name.GivenName, req.Name.FamilyName}
				displayName = strings.TrimSpace(strings.Join(parts, " "))
			}
		}

		// Use externalId as the OIDC sub for SCIM-provisioned users
		oidcSub := req.ExternalID
		if oidcSub == "" {
			oidcSub = "scim:" + uuid.New().String()
		} else {
			oidcSub = "scim:" + oidcSub
		}

		ctx := c.Request.Context()
		user, err := h.userRepo.GetOrCreateUserByOIDC(ctx, oidcSub, email, displayName)
		if err != nil {
			slog.Error("scim: create user failed", "email", email, "error", err)
			scimError(c, http.StatusConflict, "User already exists or creation failed")
			return
		}

		c.JSON(http.StatusCreated, userToSCIM(user, h.baseURL(c)))
	}
}

// @Summary      Patch SCIM user
// @Description  Partially updates a user via SCIM 2.0 PATCH operations. Supports 'replace' op for active, userName, name.formatted, and displayName.
// @Tags         SCIM
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string          true  "User ID"
// @Param        body  body  scim.SCIMPatchOp  true  "SCIM PATCH request"
// @Success      200  {object}  scim.SCIMUser  "Updated SCIM user"
// @Failure      400  {object}  scim.SCIMError  "Invalid PATCH payload"
// @Failure      404  {object}  scim.SCIMError  "User not found"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Users/{id} [patch]
// PatchUser handles PATCH /scim/v2/Users/:id
func (h *Handlers) PatchUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		ctx := c.Request.Context()

		var patchReq SCIMPatchOp
		if err := c.ShouldBindJSON(&patchReq); err != nil {
			scimError(c, http.StatusBadRequest, "Invalid SCIM PATCH payload")
			return
		}

		user, err := h.userRepo.GetUserByID(ctx, userID)
		if err != nil || user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}

		for _, op := range patchReq.Operations {
			switch strings.ToLower(op.Op) {
			case "replace":
				h.applyReplaceOp(ctx, user, op)
			default:
				// Ignore unsupported ops per SCIM spec
			}
		}

		if err := h.userRepo.UpdateUser(ctx, user); err != nil {
			slog.Error("scim: update user failed", "id", userID, "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to update user")
			return
		}

		c.JSON(http.StatusOK, userToSCIM(user, h.baseURL(c)))
	}
}

// @Summary      Replace SCIM user
// @Description  Full replacement of a user resource via SCIM 2.0 PUT. Setting active=false deactivates the user and removes all organization memberships.
// @Tags         SCIM
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string        true  "User ID"
// @Param        body  body  scim.SCIMUser  true  "Full SCIM user resource"
// @Success      200  {object}  scim.SCIMUser  "Updated SCIM user"
// @Failure      400  {object}  scim.SCIMError  "Invalid payload"
// @Failure      404  {object}  scim.SCIMError  "User not found"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Users/{id} [put]
// PutUser handles PUT /scim/v2/Users/:id (full replacement)
func (h *Handlers) PutUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		ctx := c.Request.Context()

		var req SCIMUser
		if err := c.ShouldBindJSON(&req); err != nil {
			scimError(c, http.StatusBadRequest, "Invalid SCIM user payload")
			return
		}

		user, err := h.userRepo.GetUserByID(ctx, userID)
		if err != nil || user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}

		if req.UserName != "" {
			user.Email = req.UserName
		}
		if req.Name != nil {
			displayName := req.Name.Formatted
			if displayName == "" {
				parts := []string{req.Name.GivenName, req.Name.FamilyName}
				displayName = strings.TrimSpace(strings.Join(parts, " "))
			}
			if displayName != "" {
				user.Name = displayName
			}
		}

		if !req.Active {
			_ = h.orgRepo.RemoveAllMembershipsForUser(ctx, userID)
			slog.Info("scim: user deactivated via PUT", "id", userID)
		}

		if err := h.userRepo.UpdateUser(ctx, user); err != nil {
			slog.Error("scim: put user failed", "id", userID, "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to update user")
			return
		}

		c.JSON(http.StatusOK, userToSCIM(user, h.baseURL(c)))
	}
}

// @Summary      Delete SCIM user
// @Description  Soft-deletes (deactivates) a user by removing all organization memberships. The user record is preserved.
// @Tags         SCIM
// @Security     Bearer
// @Param        id  path  string  true  "User ID"
// @Success      204  "User deactivated"
// @Failure      404  {object}  scim.SCIMError  "User not found"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Users/{id} [delete]
// DeleteUser handles DELETE /scim/v2/Users/:id
// Per the roadmap, this soft-deletes (deactivates) rather than hard-deletes.
func (h *Handlers) DeleteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")
		ctx := c.Request.Context()

		user, err := h.userRepo.GetUserByID(ctx, userID)
		if err != nil || user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}

		if err := h.orgRepo.RemoveAllMembershipsForUser(ctx, userID); err != nil {
			slog.Error("scim: deactivate user failed", "id", userID, "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to deactivate user")
			return
		}

		slog.Info("scim: user deactivated", "id", userID, "email", user.Email)
		c.Status(http.StatusNoContent)
	}
}

// --- Group endpoints (map organizations to SCIM groups) ---

// @Summary      List SCIM groups
// @Description  Returns all organizations as SCIM 2.0 Group resources (up to 200).
// @Tags         SCIM
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  scim.SCIMListResponse  "SCIM list response"
// @Failure      500  {object}  scim.SCIMError  "Internal server error"
// @Router       /scim/v2/Groups [get]
// ListGroups handles GET /scim/v2/Groups
func (h *Handlers) ListGroups() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgs, err := h.orgRepo.List(c.Request.Context(), 200, 0)
		if err != nil {
			scimError(c, http.StatusInternalServerError, "Failed to list groups")
			return
		}

		base := h.baseURL(c)
		resources := make([]gin.H, 0, len(orgs))
		for _, org := range orgs {
			resources = append(resources, orgToSCIMGroup(org, base))
		}

		c.JSON(http.StatusOK, SCIMListResponse{
			Schemas:      []string{SchemaListResp},
			TotalResults: len(resources),
			ItemsPerPage: int(math.Min(float64(len(resources)), 200)),
			StartIndex:   1,
			Resources:    resources,
		})
	}
}

// @Summary      Get SCIM group
// @Description  Returns a single organization as a SCIM 2.0 Group resource by ID.
// @Tags         SCIM
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Group (organization) ID"
// @Success      200  {object}  map[string]interface{}  "SCIM group resource"
// @Failure      404  {object}  scim.SCIMError  "Group not found"
// @Router       /scim/v2/Groups/{id} [get]
// GetGroup handles GET /scim/v2/Groups/:id
func (h *Handlers) GetGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		groupID := c.Param("id")
		org, err := h.orgRepo.GetByID(c.Request.Context(), groupID)
		if err != nil || org == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("Group %q not found", groupID))
			return
		}
		c.JSON(http.StatusOK, orgToSCIMGroup(org, h.baseURL(c)))
	}
}

// --- Helpers ---

func (h *Handlers) applyReplaceOp(ctx context.Context, user *models.User, op SCIMOperation) {
	path := strings.ToLower(op.Path)

	switch path {
	case "active":
		active := true
		switch v := op.Value.(type) {
		case bool:
			active = v
		case string:
			active = strings.EqualFold(v, "true")
		}
		if !active {
			_ = h.orgRepo.RemoveAllMembershipsForUser(ctx, user.ID)
			slog.Info("scim: user deactivated via PATCH", "id", user.ID)
		}
	case "username", "emails[type eq \"work\"].value":
		if v, ok := op.Value.(string); ok && v != "" {
			user.Email = v
		}
	case "name.formatted", "displayname":
		if v, ok := op.Value.(string); ok && v != "" {
			user.Name = v
		}
	case "":
		// No path — value is a map of attributes
		if m, ok := op.Value.(map[string]interface{}); ok {
			if v, ok := m["active"].(bool); ok && !v {
				_ = h.orgRepo.RemoveAllMembershipsForUser(ctx, user.ID)
			}
			if v, ok := m["userName"].(string); ok && v != "" {
				user.Email = v
			}
			if nameMap, ok := m["name"].(map[string]interface{}); ok {
				if formatted, ok := nameMap["formatted"].(string); ok && formatted != "" {
					user.Name = formatted
				}
			}
		}
	}
}

func (h *Handlers) baseURL(c *gin.Context) string {
	if h.cfg.Server.PublicURL != "" {
		return strings.TrimRight(h.cfg.Server.PublicURL, "/")
	}
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}

func userToSCIM(u *models.User, baseURL string) SCIMUser {
	externalID := ""
	if u.OIDCSub != nil {
		externalID = strings.TrimPrefix(*u.OIDCSub, "scim:")
	}

	emails := []SCIMEmail{}
	if u.Email != "" {
		emails = append(emails, SCIMEmail{Value: u.Email, Type: "work", Primary: true})
	}

	return SCIMUser{
		Schemas:    []string{SchemaUser},
		ID:         u.ID,
		ExternalID: externalID,
		UserName:   u.Email,
		Name:       &SCIMName{Formatted: u.Name},
		Emails:     emails,
		Active:     true, // Active is always true for existing users; deactivated users have no memberships
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt.Format(time.RFC3339),
			LastModified: u.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/Users/%s", baseURL, u.ID),
		},
	}
}

func orgToSCIMGroup(org *models.Organization, baseURL string) gin.H {
	return gin.H{
		"schemas":     []string{SchemaGroup},
		"id":          org.ID,
		"displayName": org.Name,
		"meta": SCIMMeta{
			ResourceType: "Group",
			Created:      org.CreatedAt.Format(time.RFC3339),
			LastModified: org.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/Groups/%s", baseURL, org.ID),
		},
	}
}

func extractFilterValue(filter string) string {
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) != 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, "\"")
	return val
}

func scimError(c *gin.Context, status int, detail string) {
	c.JSON(status, SCIMError{
		Schemas: []string{SchemaError},
		Detail:  detail,
		Status:  strconv.Itoa(status),
	})
}

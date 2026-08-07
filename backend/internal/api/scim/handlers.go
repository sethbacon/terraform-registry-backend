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
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
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
	// creds invalidates the credentials of a user this IdP feed deprovisions.
	//
	// SCIM is the primary IdP-driven offboarding channel: it is what fires when
	// HR disables an account. Every deactivation path here used to strip
	// organization memberships and nothing else (issue #736) -- the deactivated
	// user kept a fully working session for the remainder of the 24h JWT
	// lifetime and kept their API keys permanently, because both families
	// snapshot their authority at issue time. That is directly inconsistent
	// with the admin path, which goes out of its way to sweep on the analogous
	// membership removal.
	//
	// May be nil (no sweep) so the handler set stays constructible without the
	// revocation subsystem.
	creds *credlifecycle.Sweeper
}

// Option configures optional Handlers construction behaviour.
type Option func(*Handlers)

// WithCredentialSweeper wires the credential sweep used by the deprovisioning
// paths (DELETE /Users/{id}, and active=false via PUT or PATCH).
func WithCredentialSweeper(s *credlifecycle.Sweeper) Option {
	return func(h *Handlers) { h.creds = s }
}

// NewHandlers creates a SCIM handler set.
func NewHandlers(cfg *config.Config, db *sql.DB, opts ...Option) *Handlers {
	h := &Handlers{
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

// deprovision invalidates every credential family belonging to a user this
// SCIM feed has just deactivated or deleted: their JWT sessions and every API
// key they hold in the organizations `removed` names. Best-effort and non-fatal
// — the membership strip has already committed, and SCIM clients retry
// aggressively on 5xx, so a sweep failure is logged rather than turned into an
// error the IdP would replay.
//
// removed must be the scope RemoveAllMembershipsForUser reported, not the
// caller's own scope: it is the set of organizations whose membership was
// actually withdrawn, so the sweep reaches exactly the keys whose backing
// authority just went away and no others.
//
// Reached only through deprovisionUser (tenant_scope.go), which pairs it
// structurally with the membership removal so no deactivation path can take
// one half without the other (issues #719/#736).
func (h *Handlers) deprovision(ctx context.Context, userID string, removed repositories.OrgScope, reason string) {
	if h.creds == nil {
		return
	}
	out := h.creds.UserDeprovisioned(ctx, userID, removed, reason)
	slog.Info("scim: credentials revoked for deprovisioned user",
		"id", userID, "reason", reason,
		"tokens_revoked", out.TokensRevoked, "api_keys_revoked", out.KeysRevoked,
		"incomplete", out.Incomplete)
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
	// Active is a POINTER so an omitted "active" is distinguishable from an
	// explicit "active": false.
	//
	// As a plain bool it zero-valued to false on every PUT that did not
	// mention the attribute, and PutUser reads false as "deprovision" -- which
	// since #736 means removing every organization membership AND irreversibly
	// deleting every API key the user holds in every organization. A partial
	// PUT from an IdP (or any client updating only a display name) would
	// silently destroy the user's credentials fleet-wide. Deprovisioning must
	// require the IdP to actually say active=false.
	Active *bool    `json:"active,omitempty"`
	Meta   SCIMMeta `json:"meta"`
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
				users, err = h.userRepo.Search(ctx, value, count, offset, repositories.OrgScopeAllOrganizations())
				total = len(users)
			} else {
				users, total, err = h.userRepo.ListUsers(ctx, count, offset, repositories.OrgScopeAllOrganizations())
			}
		} else {
			users, total, err = h.userRepo.ListUsers(ctx, count, offset, repositories.OrgScopeAllOrganizations())
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
		user, err := h.userRepo.GetUserByID(c.Request.Context(), userID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(user, err) {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}
		if err != nil {
			slog.Error("scim: get user failed", "id", userID, "error", err)
			scimError(c, http.StatusInternalServerError, "Failed to get user")
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

		// SCIM provisioning is a trusted, scim:provision-scoped administrative
		// feed, so the provided email is treated as verified here, matching
		// this flow's pre-v0.17.0 behavior (no verification gate existed
		// before this parameter was added).
		ctx := c.Request.Context()
		user, err := h.userRepo.GetOrCreateUserFromOIDC(ctx, oidcSub, email, displayName, true)
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

		user, err := h.userRepo.GetUserByID(ctx, userID, repositories.OrgScopeAllOrganizations())
		if err != nil || user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}

		for _, op := range patchReq.Operations {
			switch strings.ToLower(op.Op) {
			case "replace":
				h.applyReplaceOp(c, user, op)
			default:
				// Ignore unsupported ops per SCIM spec
			}
		}

		// The user was deleted between the read above and this write. SCIM
		// callers reconcile against 404, so report the resource's absence
		// rather than a server fault they would retry forever.
		if err := h.userRepo.UpdateUser(ctx, user, repositories.OrgScopeAllOrganizations()); err != nil {
			if identityerr.IsNotFound(err) {
				scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
				return
			}
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

		user, err := h.userRepo.GetUserByID(ctx, userID, repositories.OrgScopeAllOrganizations())
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

		// Only an EXPLICIT active=false deprovisions. An omitted attribute
		// leaves the user's authority (and credentials) untouched.
		if req.Active != nil && !*req.Active {
			// GUARD scim-deprovision-tenant-scope (issue #719): see
			// tenant_scope.go. Memberships are removed only where the caller
			// may act, not in every organization on the platform, and the
			// helper also sweeps the user's JWT sessions and API keys, which
			// carry a snapshot of the removed authority (issue #736).
			if err := h.deprovisionUser(c, userID, "scim: user deactivated via PUT"); err != nil {
				slog.Error("scim: deactivate user failed", "id", userID, "error", err)
				scimError(c, http.StatusInternalServerError, "Failed to deactivate user")
				return
			}
			slog.Info("scim: user deactivated via PUT", "id", userID)
		}

		// Same race as the PATCH path above: absent resource is a 404.
		if err := h.userRepo.UpdateUser(ctx, user, repositories.OrgScopeAllOrganizations()); err != nil {
			if identityerr.IsNotFound(err) {
				scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
				return
			}
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

		user, err := h.userRepo.GetUserByID(ctx, userID, repositories.OrgScopeAllOrganizations())
		if err != nil || user == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("User %q not found", userID))
			return
		}

		// GUARD scim-deprovision-tenant-scope (issue #719): see tenant_scope.go.
		// The helper also sweeps the user's credentials (issue #736). That
		// matters here because this is a SOFT delete: the users row survives,
		// so nothing cascades to api_keys and nothing makes AuthMiddleware's
		// user lookup fail — without the sweep the "deleted" user would keep a
		// live session and permanently valid API keys.
		if err := h.deprovisionUser(c, userID, "scim: user deleted"); err != nil {
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
		orgs, err := h.orgRepo.List(c.Request.Context(), 200, 0, repositories.OrgScopeAllOrganizations())
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
		org, err := h.orgRepo.GetByID(c.Request.Context(), groupID, repositories.OrgScopeAllOrganizations())
		if err != nil || org == nil {
			scimError(c, http.StatusNotFound, fmt.Sprintf("Group %q not found", groupID))
			return
		}
		c.JSON(http.StatusOK, orgToSCIMGroup(org, h.baseURL(c)))
	}
}

// --- Helpers ---

// applyReplaceOp takes the gin context rather than a bare context.Context
// because the deactivation branches must know WHO is asking: the tenant scope
// of a SCIM deprovision is a property of the caller, not of the request
// deadline (issue #719).
func (h *Handlers) applyReplaceOp(c *gin.Context, user *models.User, op SCIMOperation) {
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
			// GUARD scim-deprovision-tenant-scope (issue #719): see tenant_scope.go.
			// Same deprovisioning event as PUT active=false, reached through
			// the PATCH "replace active" op; the helper sweeps the same
			// credential families (issue #736).
			if err := h.deprovisionUser(c, user.ID, "scim: user deactivated via PATCH"); err != nil {
				slog.Error("scim: deactivate user failed", "id", user.ID, "error", err)
				return
			}
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
				// GUARD scim-deprovision-tenant-scope (issue #719): the pathless
				// PATCH form is the fourth deactivation path over this table and
				// was as unscoped as the other three. It is the same
				// deprovisioning event as the "active" path above and sweeps
				// identically (issue #736) through the shared helper.
				if err := h.deprovisionUser(c, user.ID, "scim: user deactivated via pathless PATCH"); err != nil {
					slog.Error("scim: deactivate user failed", "id", user.ID, "error", err)
					return
				}
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

	// Always rendered explicitly on the way out: existing users are active
	// (deactivated users have no memberships). Only the INBOUND direction
	// needs to distinguish omitted from false.
	active := true

	return SCIMUser{
		Schemas:    []string{SchemaUser},
		ID:         u.ID,
		ExternalID: externalID,
		UserName:   u.Email,
		Name:       &SCIMName{Formatted: u.Name},
		Emails:     emails,
		Active:     &active,
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

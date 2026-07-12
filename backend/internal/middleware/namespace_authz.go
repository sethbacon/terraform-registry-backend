// Package middleware (namespace_authz.go) enforces object-level authorization
// on module and provider mutations (issue #555, CWE-639).
//
// Global scopes (modules:write, providers:write) only say WHAT a principal may
// do; this file decides WHERE they may do it. Every namespace is bound to an
// owning organization via the namespace_claims table (bound on first publish,
// backfilled from existing artifacts by migration 000045). A mutation of any
// artifact in a namespace is allowed only when:
//
//   - the caller holds the wildcard "admin" scope. Admin deliberately crosses
//     organization boundaries: registry operators must be able to manage
//     content in every namespace; or
//   - the caller authenticated with an API key whose organization binding
//     equals the owning organization (keys are bound to exactly one
//     organization at creation time); or
//   - the caller is a JWT principal whose user is a member of the owning
//     organization with a role template that grants the required write scope.
//
// When no claim exists the ownership falls back to the organization of the
// existing artifact rows (covers system-created content such as mirror-synced
// providers), and a first publish into a fully unclaimed namespace binds it to
// the caller's organization. Requests without a resolvable organization
// context fail closed.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// errAmbiguousOwnership is returned when a namespace has artifacts in multiple
// organizations and no claim row to disambiguate them. This cannot happen
// through the API (claims are created on first publish); it indicates manual
// data edits, so only admins may act on such a namespace.
var errAmbiguousOwnership = errors.New("namespace has artifacts in multiple organizations and no claim")

// NamespaceAuthorizer resolves namespace ownership and checks callers against
// the owning organization. It is wired onto every module/provider mutation
// route in router.go, after AuthMiddleware and RequireScope.
type NamespaceAuthorizer struct {
	orgRepo      *repositories.OrganizationRepository
	claimRepo    *repositories.NamespaceClaimRepository
	moduleRepo   *repositories.ModuleRepository
	providerRepo *repositories.ProviderRepository
}

// NewNamespaceAuthorizer creates a namespace authorizer. orgRepo must be
// backed by the identity connection; the remaining repositories use the
// registry (public schema) connection.
func NewNamespaceAuthorizer(
	orgRepo *repositories.OrganizationRepository,
	claimRepo *repositories.NamespaceClaimRepository,
	moduleRepo *repositories.ModuleRepository,
	providerRepo *repositories.ProviderRepository,
) *NamespaceAuthorizer {
	return &NamespaceAuthorizer{
		orgRepo:      orgRepo,
		claimRepo:    claimRepo,
		moduleRepo:   moduleRepo,
		providerRepo: providerRepo,
	}
}

// RequireNamespaceAccessFromPath authorizes mutations on routes that carry the
// namespace as the :namespace path parameter (delete, deprecate, version
// operations). Unowned namespaces pass through: nothing exists under them, so
// the handler's own not-found response leaks nothing.
func (a *NamespaceAuthorizer) RequireNamespaceAccessFromPath(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		if namespace == "" {
			abortNamespaceAuthz(c, http.StatusForbidden, "Namespace not present in request path")
			return
		}
		if a.authorizeNamespaceMutation(c, namespace, scope, false) {
			c.Next()
		}
	}
}

// RequirePublishAccessFromForm authorizes publish routes that carry the
// namespace as a multipart form field (module and provider uploads). A first
// publish into an unclaimed namespace binds it to the caller's organization.
// maxMemory bounds the in-memory portion of the parsed form and should match
// the handler's own ParseMultipartForm limit.
func (a *NamespaceAuthorizer) RequirePublishAccessFromForm(scope auth.Scope, maxMemory int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.Request.ParseMultipartForm(maxMemory); err != nil {
			abortNamespaceAuthz(c, http.StatusBadRequest, "Failed to parse multipart form")
			return
		}
		// PostFormValue (body-only), NOT FormValue: FormValue prefers the URL
		// query string over the parsed body, but the upload handler reads the
		// namespace via c.PostForm (body-only, Gin's GetPostForm reads
		// req.PostForm). Using FormValue here let a caller authorize against a
		// namespace named in the query string (?namespace=one-they-own) while
		// the multipart body — what the handler actually persists into —
		// named a different, victim namespace, bypassing this check entirely.
		namespace := c.Request.PostFormValue("namespace")
		if namespace == "" {
			// The handler rejects the request as invalid; nothing is targeted.
			c.Next()
			return
		}
		if a.authorizeNamespaceMutation(c, namespace, scope, true) {
			c.Next()
		}
	}
}

// RequirePublishAccessFromJSON authorizes create routes that carry the
// namespace in a JSON body (module/provider record creation). The body is
// buffered and restored so the handler can bind it again. A first publish into
// an unclaimed namespace binds it to the caller's organization. When the body
// carries an organization_id override (provider record creation), a non-admin
// caller must match the namespace's owning organization.
func (a *NamespaceAuthorizer) RequirePublishAccessFromJSON(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortNamespaceAuthz(c, http.StatusBadRequest, "Failed to read request body")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))

		var body struct {
			Namespace      string `json:"namespace"`
			OrganizationID string `json:"organization_id"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.Namespace == "" {
			// Malformed JSON or missing namespace: the handler's binding
			// rejects the request; nothing is targeted.
			c.Next()
			return
		}

		if !a.authorizeNamespaceMutation(c, body.Namespace, scope, true) {
			return
		}

		// A non-admin caller must not plant artifact rows in another
		// organization's row space via an organization_id override.
		if body.OrganizationID != "" && !callerIsAdmin(c) {
			ownerOrgID, err := a.resolveOwnerOrg(c.Request.Context(), body.Namespace)
			if err != nil || ownerOrgID == "" || body.OrganizationID != ownerOrgID {
				abortNamespaceAuthz(c, http.StatusForbidden, "organization_id does not match the namespace's owning organization")
				return
			}
		}

		c.Next()
	}
}

// RequireModuleAccessByID authorizes mutations on routes that address a module
// by its UUID (SCM link operations). Missing modules and malformed IDs pass
// through so the handler keeps its own not-found/bad-request semantics.
func (a *NamespaceAuthorizer) RequireModuleAccessByID(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, _, ok := a.moduleAccessByID(c, scope); ok {
			c.Next()
		}
	}
}

// RequireModuleUpdateAccess authorizes PUT /admin/modules/:id, which may also
// move the module to a different namespace. Moving into a namespace owned by
// another organization is denied for non-admins; moving into an unclaimed
// namespace claims it for the module's owning organization.
func (a *NamespaceAuthorizer) RequireModuleUpdateAccess(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		module, currentOwner, ok := a.moduleAccessByID(c, scope)
		if !ok {
			return
		}
		if module == nil {
			// Missing module or malformed ID: handler responds.
			c.Next()
			return
		}

		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortNamespaceAuthz(c, http.StatusBadRequest, "Failed to read request body")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))

		var body struct {
			Namespace *string `json:"namespace"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.Namespace == nil ||
			*body.Namespace == "" || *body.Namespace == module.Namespace {
			// No namespace change requested (or the handler will reject the
			// body); the current-namespace authorization above suffices.
			c.Next()
			return
		}

		target := *body.Namespace
		targetOwner, err := a.resolveOwnerOrg(c.Request.Context(), target)
		if err != nil {
			if errors.Is(err, errAmbiguousOwnership) {
				if callerIsAdmin(c) {
					c.Next()
					return
				}
				abortNamespaceAuthz(c, http.StatusForbidden, "Namespace ownership is ambiguous; contact an administrator")
				return
			}
			abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to resolve namespace ownership")
			return
		}

		switch {
		case targetOwner == "":
			// Moving into an unclaimed namespace claims it for the module's
			// owning organization.
			if err := validation.ValidateRegistrySegment(target); err != nil {
				abortNamespaceAuthz(c, http.StatusBadRequest, fmt.Sprintf("Invalid namespace: %v", err))
				return
			}
			claim, err := a.claimRepo.ClaimNamespace(c.Request.Context(), target, currentOwner, callerUserID(c))
			if err != nil {
				abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to claim namespace")
				return
			}
			if claim.OrganizationID != currentOwner && !callerIsAdmin(c) {
				abortNamespaceAuthz(c, http.StatusForbidden, "Namespace is owned by another organization")
				return
			}
		case targetOwner != currentOwner:
			if !callerIsAdmin(c) {
				abortNamespaceAuthz(c, http.StatusForbidden, "Namespace is owned by another organization")
				return
			}
		}

		c.Next()
	}
}

// RequireProviderAccessByID authorizes mutations on routes that address a
// provider by its UUID (PUT /admin/providers/:id). Missing providers and
// malformed IDs pass through so the handler keeps its own semantics.
func (a *NamespaceAuthorizer) RequireProviderAccessByID(scope auth.Scope) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if _, err := uuid.Parse(id); err != nil {
			c.Next()
			return
		}

		provider, err := a.providerRepo.GetProviderByID(c.Request.Context(), id)
		if err != nil {
			abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to get provider")
			return
		}
		if provider == nil {
			c.Next()
			return
		}

		ownerOrgID, err := a.ownerOrgForArtifact(c.Request.Context(), provider.Namespace, provider.OrganizationID)
		if err != nil {
			abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to resolve namespace ownership")
			return
		}
		if status, msg := a.authorizeOrgAccess(c, ownerOrgID, scope); status != 0 {
			abortNamespaceAuthz(c, status, msg)
			return
		}

		c.Next()
	}
}

// moduleAccessByID loads the module addressed by the :id path parameter and
// authorizes the caller against its owning organization. It returns
// (module, ownerOrgID, true) on success, (nil, "", true) when the module is
// missing or the ID is malformed (the handler responds), and (nil, "", false)
// after aborting the request.
func (a *NamespaceAuthorizer) moduleAccessByID(c *gin.Context, scope auth.Scope) (*models.Module, string, bool) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		return nil, "", true
	}

	module, err := a.moduleRepo.GetModuleByID(c.Request.Context(), id)
	if err != nil {
		abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to get module")
		return nil, "", false
	}
	if module == nil {
		return nil, "", true
	}

	ownerOrgID, err := a.ownerOrgForArtifact(c.Request.Context(), module.Namespace, module.OrganizationID)
	if err != nil {
		abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to resolve namespace ownership")
		return nil, "", false
	}
	if status, msg := a.authorizeOrgAccess(c, ownerOrgID, scope); status != 0 {
		abortNamespaceAuthz(c, status, msg)
		return nil, "", false
	}

	return module, ownerOrgID, true
}

// authorizeNamespaceMutation resolves the owning organization of a namespace
// and checks the caller against it. allowClaim enables the first-publish path
// that binds an unclaimed namespace to the caller's organization. Returns true
// when the request may proceed; on false the request has been aborted.
func (a *NamespaceAuthorizer) authorizeNamespaceMutation(c *gin.Context, namespace string, scope auth.Scope, allowClaim bool) bool {
	ownerOrgID, err := a.resolveOwnerOrg(c.Request.Context(), namespace)
	if err != nil {
		if errors.Is(err, errAmbiguousOwnership) {
			if callerIsAdmin(c) {
				return true
			}
			abortNamespaceAuthz(c, http.StatusForbidden, "Namespace ownership is ambiguous; contact an administrator")
			return false
		}
		abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to resolve namespace ownership")
		return false
	}

	if ownerOrgID != "" {
		if status, msg := a.authorizeOrgAccess(c, ownerOrgID, scope); status != 0 {
			abortNamespaceAuthz(c, status, msg)
			return false
		}
		return true
	}

	// Unowned namespace.
	if !allowClaim {
		// Nothing exists under this namespace, so the handler can only
		// respond not-found. Passing through preserves 404 semantics without
		// exposing any object.
		return true
	}

	// First publish into this namespace: bind it to the caller's organization.
	if err := validation.ValidateRegistrySegment(namespace); err != nil {
		abortNamespaceAuthz(c, http.StatusBadRequest, fmt.Sprintf("Invalid namespace: %v", err))
		return false
	}

	callerOrgID, status, msg := a.resolveCallerOrg(c)
	if status != 0 {
		abortNamespaceAuthz(c, status, msg)
		return false
	}

	claim, err := a.claimRepo.ClaimNamespace(c.Request.Context(), namespace, callerOrgID, callerUserID(c))
	if err != nil {
		abortNamespaceAuthz(c, http.StatusInternalServerError, "Failed to claim namespace")
		return false
	}
	if claim.OrganizationID != callerOrgID {
		// Lost a concurrent first-publish race to another organization; the
		// caller must now qualify against the winner.
		if status, msg := a.authorizeOrgAccess(c, claim.OrganizationID, scope); status != 0 {
			abortNamespaceAuthz(c, status, msg)
			return false
		}
	}

	return true
}

// authorizeOrgAccess checks the authenticated caller against the owning
// organization. It returns (0, "") when access is allowed, otherwise an HTTP
// status and message. The checks are ordered from cheapest to most expensive
// and every branch fails closed.
func (a *NamespaceAuthorizer) authorizeOrgAccess(c *gin.Context, ownerOrgID string, scope auth.Scope) (int, string) {
	scopesVal, exists := c.Get("scopes")
	if !exists {
		return http.StatusForbidden, "Insufficient permissions"
	}
	userScopes, ok := scopesVal.([]string)
	if !ok {
		return http.StatusForbidden, "Invalid scopes format"
	}

	// The wildcard admin scope deliberately crosses organization boundaries:
	// registry operators must be able to manage content in every namespace.
	if auth.HasScope(userScopes, auth.ScopeAdmin) {
		return 0, ""
	}

	// API keys are bound to exactly one organization at creation time; that
	// binding is authoritative for the key regardless of the owning user's
	// other memberships.
	if keyVal, exists := c.Get("api_key"); exists {
		apiKey, ok := keyVal.(*models.APIKey)
		if !ok {
			return http.StatusForbidden, "Invalid API key context"
		}
		if apiKey.OrganizationID != "" {
			if apiKey.OrganizationID == ownerOrgID {
				return 0, ""
			}
			return http.StatusForbidden, "Namespace is owned by another organization"
		}
		// Keys without an organization binding (legacy rows) fall through to
		// the owning user's membership check below.
	}

	userVal, exists := c.Get("user_id")
	if !exists {
		return http.StatusForbidden, "Organization context required"
	}
	userID, ok := userVal.(string)
	if !ok || userID == "" {
		return http.StatusForbidden, "Invalid user ID format"
	}

	member, err := a.orgRepo.GetMemberWithRole(c.Request.Context(), ownerOrgID, userID)
	if err != nil {
		return http.StatusInternalServerError, "Failed to check organization membership"
	}
	if member == nil {
		return http.StatusForbidden, "Namespace is owned by another organization"
	}
	if !auth.HasScope(member.RoleTemplateScopes, scope) {
		return http.StatusForbidden, "Missing required scope in the owning organization"
	}

	return 0, ""
}

// resolveOwnerOrg returns the organization that owns a namespace: the claim
// when one exists, otherwise the single organization owning artifact rows in
// the namespace (system-created content), otherwise "" for a fully unowned
// namespace. Multiple artifact organizations without a claim yield
// errAmbiguousOwnership.
func (a *NamespaceAuthorizer) resolveOwnerOrg(ctx context.Context, namespace string) (string, error) {
	claim, err := a.claimRepo.GetClaim(ctx, namespace)
	if err != nil {
		return "", err
	}
	if claim != nil {
		return claim.OrganizationID, nil
	}

	orgIDs, err := a.claimRepo.ArtifactOrganizations(ctx, namespace)
	if err != nil {
		return "", err
	}
	switch len(orgIDs) {
	case 0:
		return "", nil
	case 1:
		return orgIDs[0], nil
	default:
		return "", errAmbiguousOwnership
	}
}

// ownerOrgForArtifact resolves ownership for an already-loaded artifact row:
// the namespace claim wins; without one the row's own organization is
// authoritative.
func (a *NamespaceAuthorizer) ownerOrgForArtifact(ctx context.Context, namespace, artifactOrgID string) (string, error) {
	claim, err := a.claimRepo.GetClaim(ctx, namespace)
	if err != nil {
		return "", err
	}
	if claim != nil {
		return claim.OrganizationID, nil
	}
	return artifactOrgID, nil
}

// resolveCallerOrg determines which organization a first publish should bind a
// new namespace to. Returns (orgID, 0, "") on success, otherwise an HTTP
// status and message. Fails closed when no organization can be derived from
// the caller's identity.
func (a *NamespaceAuthorizer) resolveCallerOrg(c *gin.Context) (string, int, string) {
	// Org-scoped API keys carry their organization directly.
	if keyVal, exists := c.Get("api_key"); exists {
		if apiKey, ok := keyVal.(*models.APIKey); ok && apiKey.OrganizationID != "" {
			return apiKey.OrganizationID, 0, ""
		}
	}

	if userID := callerUserID(c); userID != nil {
		memberships, err := a.orgRepo.GetUserMemberships(c.Request.Context(), *userID)
		if err != nil {
			return "", http.StatusInternalServerError, "Failed to resolve organization memberships"
		}
		if len(memberships) == 1 {
			return memberships[0].OrganizationID, 0, ""
		}
		if len(memberships) > 1 && !callerIsAdmin(c) {
			return "", http.StatusForbidden, "Ambiguous organization context: use an organization-scoped API key to publish a new namespace"
		}
	}

	// Admins without an unambiguous organization bind new namespaces to the
	// default organization (registry-operator behavior).
	if callerIsAdmin(c) {
		org, err := a.orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil {
			return "", http.StatusInternalServerError, "Failed to get organization context"
		}
		if org == nil {
			return "", http.StatusInternalServerError, "Default organization not found"
		}
		return org.ID, 0, ""
	}

	return "", http.StatusForbidden, "Organization context required"
}

// callerIsAdmin reports whether the authenticated principal holds the wildcard
// admin scope.
func callerIsAdmin(c *gin.Context) bool {
	scopesVal, exists := c.Get("scopes")
	if !exists {
		return false
	}
	userScopes, ok := scopesVal.([]string)
	if !ok {
		return false
	}
	return auth.HasScope(userScopes, auth.ScopeAdmin)
}

// callerUserID returns the authenticated user ID from context, or nil when
// absent (e.g. service API keys without an owning user).
func callerUserID(c *gin.Context) *string {
	if userVal, exists := c.Get("user_id"); exists {
		if uid, ok := userVal.(string); ok && uid != "" {
			return &uid
		}
	}
	return nil
}

func abortNamespaceAuthz(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}

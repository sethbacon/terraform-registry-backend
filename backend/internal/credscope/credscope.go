// Package credscope binds an authority ceiling to the credential that actually
// made the request.
//
// THE CLASS (issue #733, CWE-269). A handler that decides how much authority a
// request may exercise, or GRANT, by reading the caller's user record — their
// organization membership and its role template — answers a question about the
// PRINCIPAL when the question it needs answered is about the CREDENTIAL. The
// two are not the same thing. A user holding the admin role template may also
// hold a machine credential deliberately narrowed to `modules:read`; deriving
// the ceiling from the user makes that narrowing decorative, because the narrow
// credential can mint, widen or rotate its way to the owner's full authority.
// Containment is the entire reason for issuing a scoped key, so a scoping that
// does not survive the key's own use is not scoping at all.
//
// THE RULE. Every authority ceiling derived from a user record is intersected
// with the scopes the presenting credential itself carries. An interactive
// session (a JWT in the Authorization header or the session cookie) IS the
// user's full authority by construction and keeps the user-derived ceiling
// unchanged; an API key never rises above the scopes stored on its own row.
//
// WHY A PACKAGE. The same decision is needed in internal/api/admin (API key
// create/update/rotate, role assignment) and would be needed by any future
// caller in internal/middleware; a copy per package is precisely the divergence
// tracked in issue #665, where two implementations of one check drift until one
// of them is wrong. middleware.authorizeOrgAccess and tenantscope.Resolve
// already read the API-key principal correctly for the ORGANIZATION axis; this
// package is the same idea on the SCOPE axis, and new call sites should use it
// rather than re-deriving the intersection inline.
package credscope

import (
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// Presented returns the scopes carried by the credential that authenticated
// this request, and whether that credential is an API key.
//
// The scopes come from the request context in preference to the api_keys row:
// AuthMiddleware.currentKeyScopes has already intersected the row's frozen
// scopes with what the owner's CURRENT role template grants (issue #732), so
// the context set is the narrower — and therefore correct — of the two. The
// stored set is the fallback for a context that carries the key but no derived
// scopes.
//
// An api_key context value of an unexpected type yields (nil, true): a
// principal that cannot be interpreted grants nothing, rather than falling
// through to the interactive path and inheriting the whole user-derived
// ceiling.
func Presented(c *gin.Context) ([]string, bool) {
	keyVal, exists := c.Get("api_key")
	if !exists {
		return nil, false
	}
	apiKey, ok := keyVal.(*models.APIKey)
	if !ok {
		return nil, true
	}
	scopes := apiKey.Scopes
	if scopesVal, ok := c.Get("scopes"); ok {
		if ctxScopes, ok := scopesVal.([]string); ok {
			scopes = ctxScopes
		}
	}
	return scopes, true
}

// Interactive reports whether the request was authenticated by an interactive
// session token — a JWT presented in the Authorization header or in the
// tfr_auth_token cookie.
//
// Machine credentials (API keys, mTLS client certificates) are not
// interactive, and neither is a request whose authentication method was never
// recorded: this is a question about the credential, so the absence of one is
// answered "no" rather than waved through.
func Interactive(c *gin.Context) bool {
	switch c.GetString("auth_method") {
	case "jwt", "jwt_cookie":
		return true
	default:
		return false
	}
}

// Bound narrows a ceiling derived from the caller's user record to the scopes
// the presenting credential itself carries, and returns it in the same
// []string form the call site already uses — so it drops straight into
// auth.HasScope, auth.RoleScopesPermittedBy, or a membership set literal.
//
// For an interactive session userDerived is returned unchanged.
//
// The result is materialised by testing every candidate scope against BOTH
// sets with auth.HasScope, rather than by set intersection, because either set
// may contain the "admin" wildcard or a write scope that implies its read
// sibling. A literal intersection of ["admin"] with ["modules:read"] is empty —
// it would deny a request both sides plainly permit, and a ceiling that denies
// everyone is a bug that a denial-only test cannot see.
func Bound(c *gin.Context, userDerived []string) []string {
	presented, isAPIKey := Presented(c)
	if !isAPIKey {
		return userDerived
	}

	seen := make(map[string]bool, len(userDerived)+len(presented))
	out := make([]string, 0, len(userDerived))
	for _, candidates := range [][]string{userDerived, presented} {
		for _, s := range candidates {
			if seen[s] {
				continue
			}
			seen[s] = true
			if auth.HasScope(userDerived, auth.Scope(s)) && auth.HasScope(presented, auth.Scope(s)) {
				out = append(out, s)
			}
		}
	}
	return out
}

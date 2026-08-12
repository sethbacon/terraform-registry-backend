// Package middleware provides Gin HTTP middleware for authentication, authorization,
// rate limiting, security headers, and audit logging.
//
// Middleware ordering matters and is enforced in router.go:
//
//	Security → RateLimit → Auth → RBAC → Audit → Handler
//
// Security headers run first so they appear on all responses including errors.
// Rate limiting runs before auth to block brute-force attacks before any DB work.
// Auth populates the user identity and scopes; RBAC reads from that context.
// Audit logging runs after RBAC so only successfully authorized mutations are
// recorded as successful actions.
package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
	"github.com/terraform-registry/terraform-registry/internal/safego"
)

// AuthMiddleware validates authentication (JWT or API key).
//
// Token resolution order:
//  1. Authorization: Bearer <token> header — tried as JWT first, then API key.
//  2. tfr_auth_token HttpOnly cookie — tried as JWT only. When the token
//     originates from a cookie the auth_method is set to "jwt_cookie" so that
//     downstream middleware (CSRFMiddleware) can distinguish browser-initiated
//     requests from programmatic ones.
func AuthMiddleware(cfg *config.Config, userRepo *repositories.UserRepository, apiKeyRepo *repositories.APIKeyRepository, orgRepo *repositories.OrganizationRepository, tokenRepo *repositories.TokenRepository, userRevocations *repositories.UserTokenRevocationRepository, platformAdmins *repositories.PlatformAdminRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string
		var fromCookie bool

		// Check for Authorization header first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Authorization header must start with 'Bearer '",
				})
				return
			}
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// Fall back to HttpOnly auth cookie if no header token
		if token == "" {
			if cookieVal, err := c.Cookie("tfr_auth_token"); err == nil && cookieVal != "" {
				token = cookieVal
				fromCookie = true
			}
		}

		if token == "" {
			// mTLS-authenticated machine clients carry no bearer token: when
			// security.mtls.enabled, the mtls middleware runs earlier in the
			// chain, reads the identity from the TLS layer's verified chains,
			// and sets auth_method/scopes from the subject mapping (issue #559
			// finding [3]). Let those requests through to the scope checks.
			if c.GetString("auth_method") == "mtls" {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing authorization credentials",
			})
			return
		}

		// Try JWT first
		if claims, err := auth.ValidateJWT(token); err == nil {
			// Check if the token has been revoked
			if claims.JTI != "" && tokenRepo != nil {
				if revoked, rErr := tokenRepo.IsTokenRevoked(c.Request.Context(), claims.JTI); rErr != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": "Auth check failed",
					})
					return
				} else if revoked {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error": "Token has been revoked",
					})
					return
				}
			}

			// Also reject tokens issued before the user's revoke-all watermark.
			// The watermark is moved forward when a member's role template is
			// changed, a member is removed from an organization, or a role
			// template's scopes are edited, so privilege changes take effect
			// without waiting out the JWT TTL (issue #559 finding [9]).
			if claims.IssuedAt != nil && userRevocations != nil {
				if revoked, rErr := userRevocations.TokensRevokedSince(c.Request.Context(), claims.UserID, claims.IssuedAt.Time); rErr != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": "Auth check failed",
					})
					return
				} else if revoked {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error": "Token has been revoked",
					})
					return
				}
			}

			// JWT is valid, load user and set in context.
			//
			// The not-found check comes FIRST. A JWT that outlives its user —
			// the token is still cryptographically valid, the row is gone — is
			// an authentication failure (401), not a server fault (500). Before
			// v0.24.0 the miss arrived as (nil, nil) and the `user == nil`
			// branch below caught it; now it arrives as store.ErrNotFound, so
			// ordering the checks the other way round would turn every
			// deleted-user request into a 500 and hand a caller a retryable
			// status for a condition that will never resolve.
			user, err := userRepo.GetUserByID(c.Request.Context(), claims.UserID, repositories.OrgScopeAllOrganizations())
			if identityerr.Missing(user, err) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "User not found",
				})
				return
			}
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to load user",
				})
				return
			}

			// Set context values
			c.Set("user", user)
			c.Set("user_id", user.ID)
			if fromCookie {
				c.Set("auth_method", "jwt_cookie")
			} else {
				c.Set("auth_method", "jwt")
			}
			c.Set("jwt_claims", claims)

			// Use scopes embedded in JWT claims (avoids DB query per request)
			scopes := claims.Scopes
			if scopes == nil {
				scopes = []string{}
			}

			// GUARD platform-admin-carrier (issue #766). THE insertion point:
			// resolve platform-admin authority once, here, so the twelve
			// existing auth.HasScope(scopes, auth.ScopeAdmin) sites keep asking
			// the same question and start getting the answer from the carrier.
			// A lookup failure aborts, matching how the revocation checks above
			// treat an unresolved auth question on this middleware.
			elevated, status, msg := platformAdminScopes(c.Request.Context(), platformAdmins, user.ID, scopes)
			if status != 0 {
				c.AbortWithStatusJSON(status, gin.H{"error": msg})
				return
			}
			c.Set("scopes", elevated)

			c.Next()
			return
		}

		// JWT validation is attempted first because it is entirely stateless — it
		// requires only a cryptographic check against the JWT secret with no database
		// round-trip. API key validation always requires a DB query (prefix lookup +
		// bcrypt comparison), so JWT is the lower-latency path for browser sessions.

		// If the token came from a cookie, it can only be a JWT (API keys are never
		// stored in cookies). Don't try API key auth for cookie tokens.
		if fromCookie {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication cookie",
			})
			return
		}

		// Try API key.
		// We never store the raw key — only its bcrypt hash. The 10-character prefix
		// is stored plaintext alongside the hash so we can do a fast indexed DB query
		// to narrow the candidate set, then run the expensive bcrypt comparison only
		// on those few rows. Without the prefix, every request would require scanning
		// the entire api_keys table and running bcrypt on each row — O(n) bcrypt calls
		// per request, which is catastrophically slow at scale.
		keyPrefix := token
		if len(token) > 10 {
			keyPrefix = token[:10]
		}
		apiKey, err := authenticateAPIKey(c.Request.Context(), token, keyPrefix, apiKeyRepo)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Authentication failed",
			})
			return
		}

		if apiKey != nil {
			// Check expiration
			if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "API key expired",
				})
				return
			}

			// Update last-used timestamp asynchronously. This is intentionally fire-and-forget:
			// last-used tracking is best-effort — a failed update is not a correctness problem.
			// Making it synchronous would add a DB write to every authenticated request,
			// increasing P99 latency across all endpoints. The 5-second timeout prevents
			// leaked goroutines if the DB is temporarily unreachable.
			safego.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = apiKeyRepo.UpdateLastUsed(ctx, apiKey.ID)
			})

			// Set context values
			c.Set("api_key", apiKey)
			c.Set("api_key_id", apiKey.ID)
			c.Set("auth_method", "api_key")
			c.Set("organization_id", apiKey.OrganizationID)
			c.Set("scopes", apiKey.Scopes)

			// Re-derive the key's authority HERE, where the binding is
			// established, rather than only at the two call sites that happened
			// to have the check (NamespaceAuthorizer.authorizeOrgAccess and
			// resolveCallerOrg).
			//
			// organization_id and scopes are both frozen on the api_keys row at
			// creation, and the two Set calls above copy them into the context
			// for EVERY route. Only module/provider mutations run through the
			// namespace authorizer; everything else -- the admin surface,
			// /apikeys, SCIM, quota and rate-limit bucketing -- consumed the
			// snapshot with no re-derivation at all, so a member who had been
			// removed or downgraded kept the authority their key was minted
			// with on all of those routes.
			//
			// COST, stated rather than implied: one indexed membership read per
			// API-key-authenticated request. It lands on a path that already
			// does a key-prefix query, a bcrypt comparison (which dominates the
			// request's latency by orders of magnitude) and a user load, so it
			// is roughly a 30% increase in query count and a rounding error in
			// latency. Leaving the check only at the namespace authorizer would
			// also have been a cost decision -- just an unstated one, paid in
			// authority instead of milliseconds.
			//
			// A nil orgRepo means the subsystem is not wired (unit tests) and
			// the re-derivation is skipped, matching how the tokenRepo and
			// userRevocations checks on the JWT path above behave. Every
			// production wiring in router_routes.go passes the real repository.
			if orgRepo != nil && apiKey.OrganizationID != "" {
				scopes, status, msg := currentKeyScopes(c.Request.Context(), orgRepo, apiKey)
				if status != 0 {
					c.AbortWithStatusJSON(status, gin.H{"error": msg})
					return
				}
				c.Set("scopes", scopes)
			}

			// Load user if exists
			if apiKey.UserID != nil {
				user, _ := userRepo.GetUserByID(c.Request.Context(), *apiKey.UserID, repositories.OrgScopeAllOrganizations())
				if user != nil {
					c.Set("user", user)
					c.Set("user_id", user.ID)
				}
			}

			c.Next()
			return
		}

		// Neither JWT nor API key worked
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
	}
}

// currentKeyScopes re-derives what an organization-bound API key may currently
// ask for, from its owner's CURRENT membership rather than from the snapshot
// frozen on the api_keys row.
//
// It returns (scopes, 0, "") when the key still stands, otherwise an HTTP
// status and message. Every failure direction is closed:
//
//   - No owning user. Not an "organization service credential": the registry
//     mints keys only through CreateAPIKeyHandler (UserID from the
//     authenticated caller) and RotateAPIKeyHandler (copies it), so a NULL
//     user_id means the owner was deleted and identity.api_keys' ON DELETE SET
//     NULL detached the row. See verifyKeyOwnerAuthority and migration 000050.
//   - Owner no longer a member of the bound organization. The binding is a
//     snapshot, not evidence of current standing (issue #732).
//   - Lookup failure. 500 rather than serving the frozen snapshot.
//
// On success the key's frozen scopes are INTERSECTED with what the owner's
// current role template grants, by scope semantics (auth.HasScope resolves the
// "admin" wildcard and the read/write implications). A key can never ask for
// more than its owner currently holds in the organization it is bound to; the
// lifecycle sweep normally deletes such a key first, which makes this a no-op
// in steady state and a backstop when a sweep did not land.
func currentKeyScopes(ctx context.Context, orgRepo *repositories.OrganizationRepository, apiKey *models.APIKey) ([]string, int, string) {
	if apiKey.UserID == nil || *apiKey.UserID == "" {
		return nil, http.StatusUnauthorized, "API key has no owning user; re-issue it through the API key endpoints"
	}
	// "Not a member" must stay a DENIAL, and it must be tested before the
	// generic failure branch. This is the whole point of the check: the miss is
	// the revoked-authority case (issue #732), and letting it fall through to
	// the 500 below would turn a closed door into a retryable server fault —
	// failing loudly, but in the wrong direction, and hiding a real lookup
	// failure behind the same status.
	//
	// Both spellings of the miss are handled so this reads the same against the
	// released identity version, where it arrives as (nil, nil), and v0.24.0,
	// where it arrives as store.ErrNotFound.
	member, err := orgRepo.GetMemberWithRole(ctx, apiKey.OrganizationID, *apiKey.UserID, repositories.OrgScopeAllOrganizations())
	if identityerr.Missing(member, err) {
		return nil, http.StatusUnauthorized, "API key owner is no longer a member of the bound organization"
	}
	if err != nil {
		return nil, http.StatusInternalServerError, "Failed to verify API key organization membership"
	}
	scopes := make([]string, 0, len(apiKey.Scopes))
	for _, s := range apiKey.Scopes {
		if auth.HasScope(member.RoleTemplateScopes, auth.Scope(s)) {
			scopes = append(scopes, s)
		}
	}
	return scopes, 0, ""
}

// platformAdminScopes returns the effective scopes for a USER SESSION,
// elevated with auth.ScopeAdmin when the principal holds platform-admin
// authority through the carrier (issue #766, migration 000051).
//
// TRANSITION SEMANTICS ARE `OR`, WHICH IS WHAT MAKES PR 1 NON-BREAKING.
// Effective admin is `carrier OR the existing scope union`. The union still
// answers exactly as it did, the carrier can only add, and migration 000051
// backfills the carrier from the union — so day-one behaviour is identical.
// PR 3 removes the union side; nothing here changes when it does.
//
// APPLIED ON THE USER/SESSION PATH ONLY — NEVER TO AN API KEY. Five of the
// twelve admin checks are in apikeys.go, and a long-lived credential silently
// carrying the highest privilege in the product is the exact shape of the
// problem #766 is about. Keys are already org-bound (#732) and their scopes
// are already re-derived per request from the owner's CURRENT membership
// (currentKeyScopes); inheriting the owner's platform-admin status on top of
// that would hand every CI token its owner's wildcard. Neither middleware
// calls this from its API-key branch, and
// TestAuthMiddleware_APIKey_DoesNotInheritOwnersPlatformAdmin holds that shut.
//
// A nil repository means the subsystem is not wired (unit tests), matching how
// tokenRepo/userRevocations/orgRepo nil-checks behave on both middlewares.
//
// Returns (scopes, 0, "") when the answer resolved, otherwise an HTTP status
// and message.
//
// The elevation copies rather than appending to the caller's slice. `scopes`
// is claims.Scopes, which is also published on the context as jwt_claims, so
// appending in place would write through a shared backing array whenever it
// has spare capacity. Stated as an idiom, not as a tested guarantee: the JWT
// decoder happens to produce len == cap today, so a mutation to append-in-place
// is not observable and no test here would catch it.
func platformAdminScopes(ctx context.Context, platformAdmins *repositories.PlatformAdminRepository, userID string, scopes []string) ([]string, int, string) {
	if platformAdmins == nil {
		return scopes, 0, ""
	}
	isAdmin, err := platformAdmins.IsPlatformAdmin(ctx, userID)
	if err != nil {
		// 500, not "not an admin". An authority question that did not resolve
		// must not be served as a completed no: that would silently downgrade a
		// platform administrator to a 403 during exactly the incident in which
		// they need the admin surface, with nothing in the response saying why.
		return nil, http.StatusInternalServerError, "Auth check failed"
	}
	if !isAdmin || auth.HasScope(scopes, auth.ScopeAdmin) {
		return scopes, 0, ""
	}
	elevated := make([]string, len(scopes), len(scopes)+1)
	copy(elevated, scopes)
	return append(elevated, string(auth.ScopeAdmin)), 0, ""
}

// OptionalAuthMiddleware - same as AuthMiddleware but doesn't abort if no auth
func OptionalAuthMiddleware(cfg *config.Config, userRepo *repositories.UserRepository, apiKeyRepo *repositories.APIKeyRepository, orgRepo *repositories.OrganizationRepository, tokenRepo *repositories.TokenRepository, userRevocations *repositories.UserTokenRevocationRepository, platformAdmins *repositories.PlatformAdminRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string
		var fromCookie bool

		// Check for Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// Fall back to HttpOnly auth cookie
		if token == "" {
			if cookieVal, err := c.Cookie("tfr_auth_token"); err == nil && cookieVal != "" {
				token = cookieVal
				fromCookie = true
			}
		}

		if token == "" {
			// No auth provided, continue without setting user context
			c.Next()
			return
		}

		// Try JWT first
		if claims, err := auth.ValidateJWT(token); err == nil {
			// Check revocation — same check as AuthMiddleware, but a revoked
			// token here means "continue as unauthenticated" rather than abort,
			// since this middleware guards optionally-authenticated public
			// registry-protocol endpoints (issue #559 finding [4]).
			revoked := false
			if claims.JTI != "" && tokenRepo != nil {
				revoked, _ = tokenRepo.IsTokenRevoked(c.Request.Context(), claims.JTI)
			}
			// Same revoke-all watermark check as AuthMiddleware (issue #559
			// finding [9]); a match likewise downgrades to unauthenticated.
			if !revoked && claims.IssuedAt != nil && userRevocations != nil {
				revoked, _ = userRevocations.TokensRevokedSince(c.Request.Context(), claims.UserID, claims.IssuedAt.Time)
			}
			if !revoked {
				// JWT is valid, load user and set in context
				user, err := userRepo.GetUserByID(c.Request.Context(), claims.UserID, repositories.OrgScopeAllOrganizations())
				if err == nil && user != nil {
					c.Set("user", user)
					c.Set("user_id", user.ID)
					if fromCookie {
						c.Set("auth_method", "jwt_cookie")
					} else {
						c.Set("auth_method", "jwt")
					}
					// Same context shape as AuthMiddleware: whenever this
					// middleware establishes a JWT identity it also publishes
					// the claims. Handlers that must act on the presented token
					// itself — logout revoking its JTI (issue #764) — can then
					// be mounted under either middleware and behave the same.
					// Without this the claims key is set on required-auth routes
					// only, so any such handler silently no-ops here.
					c.Set("jwt_claims", claims)
					// Use scopes embedded in JWT claims (avoids DB query per request)
					scopes := claims.Scopes
					if scopes == nil {
						scopes = []string{}
					}

					// GUARD platform-admin-carrier (issue #766). Same
					// elevation as AuthMiddleware, for the same reason the
					// jwt_claims Set immediately above exists: the two
					// middlewares must publish the SAME context shape, or a
					// check behaves differently depending on which group a
					// route happens to be mounted under — the divergence
					// tracked as #665 and the bug the jwt_claims comment
					// records. No route under this middleware consults
					// ScopeAdmin today; letting that stay true by accident is
					// not a decision, it is a bet on nobody moving a route.
					//
					// A failed lookup leaves the caller UNELEVATED rather than
					// aborting, matching this middleware's treatment of every
					// other failed auth lookup (the revocation checks above
					// swallow their errors too). Fail-closed by construction:
					// the carrier can only ever add authority.
					if elevated, status, _ := platformAdminScopes(c.Request.Context(), platformAdmins, user.ID, scopes); status == 0 {
						scopes = elevated
					}
					c.Set("scopes", scopes)
				}
			}
			c.Next()
			return
		}

		// Cookie tokens can only be JWTs — skip API key auth for cookies.
		if fromCookie {
			c.Next()
			return
		}

		// Try API key
		keyPrefix := token
		if len(token) > 10 {
			keyPrefix = token[:10]
		}

		apiKey, _ := authenticateAPIKey(c.Request.Context(), token, keyPrefix, apiKeyRepo)
		if apiKey != nil {
			// Check expiration
			if apiKey.ExpiresAt == nil || time.Now().Before(*apiKey.ExpiresAt) {
				// Update last used (async)
				safego.Go(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = apiKeyRepo.UpdateLastUsed(ctx, apiKey.ID)
				})

				// Same point-of-establishment re-derivation as AuthMiddleware
				// (see currentKeyScopes). A key whose owner has left the bound
				// organization is not an error here -- this middleware guards
				// optionally-authenticated public registry endpoints -- so the
				// request simply continues UNAUTHENTICATED, exactly as a
				// revoked JWT does above. That is the fail-closed direction:
				// private artifacts stop resolving for the stale key.
				scopes := apiKey.Scopes
				if orgRepo != nil && apiKey.OrganizationID != "" {
					current, status, _ := currentKeyScopes(c.Request.Context(), orgRepo, apiKey)
					if status != 0 {
						c.Next()
						return
					}
					scopes = current
				}

				// Set context values
				c.Set("api_key", apiKey)
				c.Set("api_key_id", apiKey.ID)
				c.Set("auth_method", "api_key")
				c.Set("organization_id", apiKey.OrganizationID)
				c.Set("scopes", scopes)

				// Load user if exists
				if apiKey.UserID != nil {
					user, _ := userRepo.GetUserByID(c.Request.Context(), *apiKey.UserID, repositories.OrgScopeAllOrganizations())
					if user != nil {
						c.Set("user", user)
						c.Set("user_id", user.ID)
					}
				}
			}
		}

		// Continue regardless of auth status
		c.Next()
	}
}

// authenticateAPIKey attempts to authenticate an API key by prefix lookup and bcrypt validation
func authenticateAPIKey(ctx context.Context, providedKey, keyPrefix string, apiKeyRepo *repositories.APIKeyRepository) (*models.APIKey, error) {
	// Get API keys matching the prefix
	keys, err := apiKeyRepo.GetAPIKeysByPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}

	// Try to validate the provided key against each candidate
	for _, key := range keys {
		if auth.ValidateAPIKey(providedKey, key.KeyHash) {
			return key, nil
		}
	}

	return nil, nil
}

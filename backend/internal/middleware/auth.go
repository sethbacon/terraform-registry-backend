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
)

// AuthMiddleware validates authentication (JWT or API key)
func AuthMiddleware(cfg *config.Config, userRepo *repositories.UserRepository, apiKeyRepo *repositories.APIKeyRepository, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing authorization header",
			})
			return
		}

		// Check if it starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header must start with 'Bearer '",
			})
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token is empty",
			})
			return
		}

		// Try JWT first
		if claims, err := auth.ValidateJWT(token); err == nil {
			// JWT is valid, load user and set in context
			user, err := userRepo.GetUserByID(c.Request.Context(), claims.UserID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to load user",
				})
				return
			}

			if user == nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "User not found",
				})
				return
			}

			// Set context values
			c.Set("user", user)
			c.Set("user_id", user.ID)
			c.Set("auth_method", "jwt")

			// Get user's combined scopes from all organization memberships
			scopes, err := orgRepo.GetUserCombinedScopes(c.Request.Context(), user.ID)
			if err != nil {
				// Log error but don't fail - user just gets empty scopes
				scopes = []string{}
			}
			c.Set("scopes", scopes)

			c.Next()
			return
		}

		// JWT validation is attempted first because it is entirely stateless — it
		// requires only a cryptographic check against the JWT secret with no database
		// round-trip. API key validation always requires a DB query (prefix lookup +
		// bcrypt comparison), so JWT is the lower-latency path for browser sessions.

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
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = apiKeyRepo.UpdateLastUsed(ctx, apiKey.ID)
			}()

			// Set context values
			c.Set("api_key", apiKey)
			c.Set("api_key_id", apiKey.ID)
			c.Set("auth_method", "api_key")
			c.Set("organization_id", apiKey.OrganizationID)
			c.Set("scopes", apiKey.Scopes)

			// Load user if exists
			if apiKey.UserID != nil {
				user, _ := userRepo.GetUserByID(c.Request.Context(), *apiKey.UserID)
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

// OptionalAuthMiddleware - same as AuthMiddleware but doesn't abort if no auth
func OptionalAuthMiddleware(cfg *config.Config, userRepo *repositories.UserRepository, apiKeyRepo *repositories.APIKeyRepository, orgRepo *repositories.OrganizationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth provided, continue without setting user context
			c.Next()
			return
		}

		// Check if it starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			// Invalid format, continue without auth
			c.Next()
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		if token == "" {
			// Empty token, continue without auth
			c.Next()
			return
		}

		// Try JWT first
		if claims, err := auth.ValidateJWT(token); err == nil {
			// JWT is valid, load user and set in context
			user, err := userRepo.GetUserByID(c.Request.Context(), claims.UserID)
			if err == nil && user != nil {
				c.Set("user", user)
				c.Set("user_id", user.ID)
				c.Set("auth_method", "jwt")
				// Get user's combined scopes from all organization memberships
				scopes, _ := orgRepo.GetUserCombinedScopes(c.Request.Context(), user.ID)
				c.Set("scopes", scopes)
			}
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
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = apiKeyRepo.UpdateLastUsed(ctx, apiKey.ID)
				}()

				// Set context values
				c.Set("api_key", apiKey)
				c.Set("api_key_id", apiKey.ID)
				c.Set("auth_method", "api_key")
				c.Set("organization_id", apiKey.OrganizationID)
				c.Set("scopes", apiKey.Scopes)

				// Load user if exists
				if apiKey.UserID != nil {
					user, _ := userRepo.GetUserByID(c.Request.Context(), *apiKey.UserID)
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

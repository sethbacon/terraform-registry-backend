// setup.go provides middleware for authenticating first-run setup wizard requests.
// Setup endpoints use a separate authentication scheme ("Authorization: SetupToken <token>")
// that is independent of the normal JWT/API key auth chain. The setup token is
// generated once at first boot and invalidated after setup completes.
package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"golang.org/x/crypto/bcrypt"
)

// SetupTokenContextKey is the context key set when a request is authenticated via setup token.
const SetupTokenContextKey = "is_setup_request"

// setupRateLimiter tracks per-IP attempt counts to prevent brute-force attacks
// on the setup token. Allows maxAttempts per window per IP.
type setupRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newSetupRateLimiter() *setupRateLimiter {
	return &setupRateLimiter{
		attempts: make(map[string][]time.Time),
	}
}

const (
	setupMaxAttempts = 5
	setupRateWindow  = time.Minute
)

// allow returns true if the IP has not exceeded the rate limit.
func (rl *setupRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-setupRateWindow)

	// Prune old entries
	recent := make([]time.Time, 0, len(rl.attempts[ip]))
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= setupMaxAttempts {
		rl.attempts[ip] = recent
		return false
	}

	rl.attempts[ip] = append(recent, now)
	return true
}

// SetupTokenMiddleware validates setup token authentication. It checks that:
//  1. Setup has not already been completed (returns 403 if it has).
//  2. The Authorization header contains a valid "SetupToken <token>" value.
//  3. The token matches the bcrypt hash stored in system_settings.
//  4. The IP is not rate-limited (max 5 attempts per minute).
//
// On success, sets SetupTokenContextKey=true in the gin context and calls c.Next().
func SetupTokenMiddleware(oidcConfigRepo *repositories.OIDCConfigRepository) gin.HandlerFunc {
	rateLimiter := newSetupRateLimiter()

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 1. Check if setup is already completed — permanently block all setup endpoints
		completed, err := oidcConfigRepo.IsSetupCompleted(ctx)
		if err != nil {
			slog.Error("setup middleware: failed to check setup status", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check setup status",
			})
			return
		}
		if completed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Setup has already been completed. These endpoints are permanently disabled.",
			})
			return
		}

		// 2. Rate limit check before doing any bcrypt work
		clientIP := c.ClientIP()
		if !rateLimiter.allow(clientIP) {
			slog.Warn("setup middleware: rate limit exceeded", "ip", clientIP)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many setup token attempts. Try again in one minute.",
			})
			return
		}

		// 3. Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required. Use: Authorization: SetupToken <token>",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "SetupToken") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization scheme. Use: Authorization: SetupToken <token>",
			})
			return
		}
		rawToken := strings.TrimSpace(parts[1])

		// 4. Retrieve stored hash
		storedHash, err := oidcConfigRepo.GetSetupTokenHash(ctx)
		if err != nil {
			slog.Error("setup middleware: failed to get token hash", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to validate setup token",
			})
			return
		}
		if storedHash == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "No setup token has been generated. Restart the server to generate one.",
			})
			return
		}

		// 5. Verify token against bcrypt hash
		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(rawToken)); err != nil {
			slog.Warn("setup middleware: invalid setup token", "ip", clientIP)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid setup token",
			})
			return
		}

		// Token is valid — set context flag and continue
		c.Set(SetupTokenContextKey, true)
		c.Next()
	}
}

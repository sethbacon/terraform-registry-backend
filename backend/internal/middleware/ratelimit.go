// ratelimit.go provides Gin middleware that enforces per-client token-bucket rate limits,
// returning 429 responses when the configured requests-per-minute threshold is exceeded.
package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	// RequestsPerMinute is the maximum number of requests allowed per minute
	RequestsPerMinute int
	// BurstSize is the maximum burst of requests allowed
	BurstSize int
	// CleanupInterval is how often to clean up expired entries
	CleanupInterval time.Duration
}

// DefaultRateLimitConfig returns sensible defaults
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 200, // Higher limit for authenticated API usage
		BurstSize:         50,  // Allow burst for pages that load multiple resources
		CleanupInterval:   5 * time.Minute,
	}
}

// AuthRateLimitConfig returns stricter limits for auth endpoints
func AuthRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 10, // 10 login attempts per minute
		BurstSize:         5,
		CleanupInterval:   5 * time.Minute,
	}
}

// UploadRateLimitConfig returns limits for upload endpoints
func UploadRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 30, // 30 uploads per minute
		BurstSize:         5,
		CleanupInterval:   5 * time.Minute,
	}
}

// rateLimitEntry tracks request counts for a single client
type rateLimitEntry struct {
	tokens     float64
	lastUpdate time.Time
}

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	config  RateLimitConfig
	entries map[string]*rateLimitEntry
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewRateLimiter creates a new rate limiter with the given config
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:  config,
		entries: make(map[string]*rateLimitEntry),
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// cleanup periodically removes expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, entry := range rl.entries {
				// Remove entries that haven't been accessed in 10 minutes
				if now.Sub(entry.lastUpdate) > 10*time.Minute {
					delete(rl.entries, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// Allow checks if a request from the given key should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[key]

	if !exists {
		// New client, give them full burst
		rl.entries[key] = &rateLimitEntry{
			tokens:     float64(rl.config.BurstSize) - 1,
			lastUpdate: now,
		}
		return true
	}

	// Calculate tokens to add based on time elapsed
	elapsed := now.Sub(entry.lastUpdate)
	tokensPerSecond := float64(rl.config.RequestsPerMinute) / 60.0
	tokensToAdd := elapsed.Seconds() * tokensPerSecond

	// Update tokens (capped at burst size)
	entry.tokens = min(float64(rl.config.BurstSize), entry.tokens+tokensToAdd)
	entry.lastUpdate = now

	// Check if we have tokens available
	if entry.tokens >= 1 {
		entry.tokens--
		return true
	}

	return false
}

// RemainingTokens returns how many tokens are left for a key
func (rl *RateLimiter) RemainingTokens(key string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	entry, exists := rl.entries[key]
	if !exists {
		return rl.config.BurstSize
	}

	// Calculate current tokens
	now := time.Now()
	elapsed := now.Sub(entry.lastUpdate)
	tokensPerSecond := float64(rl.config.RequestsPerMinute) / 60.0
	tokensToAdd := elapsed.Seconds() * tokensPerSecond
	currentTokens := min(float64(rl.config.BurstSize), entry.tokens+tokensToAdd)

	return int(currentTokens)
}

// RateLimitMiddleware creates a Gin middleware that rate limits requests
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Determine the rate limit key
		key := getRateLimitKey(c)

		if !limiter.Allow(key) {
			remaining := limiter.RemainingTokens(key)
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			return
		}

		// Add rate limit headers
		remaining := limiter.RemainingTokens(key)
		c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.config.RequestsPerMinute))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Next()
	}
}

// getRateLimitKey determines the key to use for rate limiting
// Priority: user_id > api_key_id > IP address
func getRateLimitKey(c *gin.Context) string {
	// Check for authenticated user
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok && id != "" {
			return "user:" + id
		}
	}

	// Check for API key
	if apiKeyID, exists := c.Get("api_key_id"); exists {
		if id, ok := apiKeyID.(string); ok && id != "" {
			return "apikey:" + id
		}
	}

	// Fall back to IP address
	ip := c.ClientIP()
	if ip == "" {
		ip = c.Request.RemoteAddr
	}
	return "ip:" + ip
}

// Helper function for min (Go 1.21+ has this built-in, but for compatibility)
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ratelimit.go provides Gin middleware that enforces per-client token-bucket rate limits,
// returning 429 responses when the configured requests-per-minute threshold is exceeded.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
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

// AuthRateLimitConfig returns stricter limits for auth endpoints.
// The burst must be large enough to accommodate a full OIDC login cycle
// (provider probe + redirect + callback + exchange-token = 4 minimum,
// plus headroom for multi-provider probes and retries).
func AuthRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 20, // 20 auth requests per minute
		BurstSize:         15,
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

// RateLimiterBackend is the interface that rate limiter backends must satisfy.
// Implementations include the in-memory token bucket (MemoryRateLimiter) and
// the Redis-backed GCRA limiter (RedisRateLimiter).
type RateLimiterBackend interface {
	// Allow reports whether a request identified by key should be allowed.
	Allow(ctx context.Context, key string) (bool, error)
	// RemainingTokens returns the approximate number of tokens left for key.
	RemainingTokens(ctx context.Context, key string) (int, error)
	// Close releases resources held by the backend (e.g. stop goroutines, close connections).
	Close() error
}

// OrgRateLimiterConfig holds configuration for per-organization rate limiting.
type OrgRateLimiterConfig struct {
	RequestsPerMinute int
	BurstSize         int
}

// rateLimitEntry tracks request counts for a single client
type rateLimitEntry struct {
	tokens     float64
	lastUpdate time.Time
}

// MemoryRateLimiter implements RateLimiterBackend using in-process memory.
// IMPORTANT: This is not suitable for horizontally scaled deployments — each instance
// maintains independent state, allowing clients to exceed limits by rotating across
// instances. For production HA deployments, use the Redis-backed implementation.
type MemoryRateLimiter struct {
	config  RateLimitConfig
	entries map[string]*rateLimitEntry
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// RateLimiter is an alias for MemoryRateLimiter kept for backward compatibility with
// code that references the original concrete type (e.g. BackgroundServices.Shutdown).
type RateLimiter = MemoryRateLimiter

// NewRateLimiter creates a new in-memory rate limiter with the given config
func NewRateLimiter(config RateLimitConfig) *MemoryRateLimiter {
	rl := &MemoryRateLimiter{
		config:  config,
		entries: make(map[string]*rateLimitEntry),
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// cleanup periodically removes expired entries
func (rl *MemoryRateLimiter) cleanup() {
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
func (rl *MemoryRateLimiter) Stop() {
	close(rl.stopCh)
}

// Close implements RateLimiterBackend.
func (rl *MemoryRateLimiter) Close() error {
	rl.Stop()
	return nil
}

// Allow checks if a request from the given key should be allowed.
// The context parameter satisfies the RateLimiterBackend interface; the
// in-memory implementation does not use it.
func (rl *MemoryRateLimiter) Allow(_ context.Context, key string) (bool, error) {
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
		return true, nil
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
		return true, nil
	}

	return false, nil
}

// RemainingTokens returns how many tokens are left for a key.
func (rl *MemoryRateLimiter) RemainingTokens(_ context.Context, key string) (int, error) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	entry, exists := rl.entries[key]
	if !exists {
		return rl.config.BurstSize, nil
	}

	// Calculate current tokens
	now := time.Now()
	elapsed := now.Sub(entry.lastUpdate)
	tokensPerSecond := float64(rl.config.RequestsPerMinute) / 60.0
	tokensToAdd := elapsed.Seconds() * tokensPerSecond
	currentTokens := min(float64(rl.config.BurstSize), entry.tokens+tokensToAdd)

	return int(currentTokens), nil
}

// RateLimitMiddleware creates a Gin middleware that rate limits requests.
// If backend is nil (rate limiting disabled), requests pass through unchanged.
// It supports both the legacy *MemoryRateLimiter pointer and any RateLimiterBackend.
func RateLimitMiddleware(backend RateLimiterBackend) gin.HandlerFunc {
	return func(c *gin.Context) {
		// When rate limiting is disabled, pass through
		if backend == nil {
			c.Next()
			return
		}

		// Determine the rate limit key
		key := getRateLimitKey(c)

		allowed, err := backend.Allow(c.Request.Context(), key)
		if err != nil {
			slog.Warn("rate limiter backend error, allowing request", "error", err, "key", key)
			c.Next()
			return
		}

		if !allowed {
			remaining, _ := backend.RemainingTokens(c.Request.Context(), key)
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Header("Retry-After", "60")
			telemetry.RateLimitRejectionsTotal.WithLabelValues(tierFromKey(key), keyTypeFromKey(key)).Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			return
		}

		// Add rate limit headers
		remaining, _ := backend.RemainingTokens(c.Request.Context(), key)
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Next()
	}
}

// OrgRateLimitMiddleware wraps an existing RateLimiterBackend and additionally
// enforces a per-organization aggregate limit. If the individual check passes
// but the organization aggregate limit is exceeded, the request is rejected.
// If orgBackend is nil or no org ID is present in the context, only the
// individual limit applies.
func OrgRateLimitMiddleware(individual RateLimiterBackend, orgBackend RateLimiterBackend) gin.HandlerFunc {
	return func(c *gin.Context) {
		if individual == nil {
			c.Next()
			return
		}

		key := getRateLimitKey(c)

		// Individual check
		allowed, err := individual.Allow(c.Request.Context(), key)
		if err != nil {
			slog.Warn("rate limiter backend error, allowing request", "error", err, "key", key)
			c.Next()
			return
		}

		if !allowed {
			remaining, _ := individual.RemainingTokens(c.Request.Context(), key)
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Header("Retry-After", "60")
			telemetry.RateLimitRejectionsTotal.WithLabelValues("individual", keyTypeFromKey(key)).Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			return
		}

		// Per-org check (only when orgBackend is configured and org ID is present)
		if orgBackend != nil {
			if orgID, exists := c.Get("organization_id"); exists {
				if id, ok := orgID.(string); ok && id != "" {
					orgKey := "org:" + id

					orgAllowed, orgErr := orgBackend.Allow(c.Request.Context(), orgKey)
					if orgErr != nil {
						slog.Warn("org rate limiter backend error, allowing request", "error", orgErr, "org_key", orgKey)
					} else if !orgAllowed {
						remaining, _ := orgBackend.RemainingTokens(c.Request.Context(), orgKey)
						c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
						c.Header("Retry-After", "60")
						telemetry.RateLimitRejectionsTotal.WithLabelValues("organization", "org").Inc()
						c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
							"error":       "Organization rate limit exceeded",
							"retry_after": 60,
						})
						return
					}
				}
			}
		}

		remaining, _ := individual.RemainingTokens(c.Request.Context(), key)
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Next()
	}
}

// PrincipalOverrideLimiters holds per-principal rate limiter instances for
// keys that have custom overrides configured in the YAML. Keys that do NOT
// appear here use the shared default backend.
type PrincipalOverrideLimiters struct {
	overrides map[string]RateLimiterBackend
}

// NewPrincipalOverrideLimiters builds dedicated in-memory rate limiters for
// each entry in the config overrides map.
func NewPrincipalOverrideLimiters(overrides map[string]config.PrincipalRateLimitOverride) *PrincipalOverrideLimiters {
	m := make(map[string]RateLimiterBackend, len(overrides))
	for key, ov := range overrides {
		cfg := RateLimitConfig{
			RequestsPerMinute: ov.RequestsPerMinute,
			BurstSize:         ov.Burst,
			CleanupInterval:   5 * time.Minute,
		}
		if cfg.BurstSize == 0 {
			cfg.BurstSize = cfg.RequestsPerMinute / 4
			if cfg.BurstSize < 1 {
				cfg.BurstSize = 1
			}
		}
		m[key] = NewRateLimiter(cfg)
	}
	return &PrincipalOverrideLimiters{overrides: m}
}

// Close shuts down all override rate limiters.
func (p *PrincipalOverrideLimiters) Close() error {
	for _, rl := range p.overrides {
		_ = rl.Close()
	}
	return nil
}

// PrincipalRateLimitMiddleware enforces per-principal rate limits with support
// for admin-configured overrides. If a principal has a custom override, its
// dedicated rate limiter is used; otherwise the shared defaultBackend applies.
// If defaultBackend is nil, all requests pass through.
func PrincipalRateLimitMiddleware(defaultBackend RateLimiterBackend, overrides *PrincipalOverrideLimiters) gin.HandlerFunc {
	return func(c *gin.Context) {
		if defaultBackend == nil {
			c.Next()
			return
		}

		key := getRateLimitKey(c)

		// Check for per-principal override
		backend := defaultBackend
		if overrides != nil {
			if ov, ok := overrides.overrides[key]; ok {
				backend = ov
			}
		}

		allowed, err := backend.Allow(c.Request.Context(), key)
		if err != nil {
			slog.Warn("rate limiter backend error, allowing request", "error", err, "key", key)
			c.Next()
			return
		}

		if !allowed {
			remaining, _ := backend.RemainingTokens(c.Request.Context(), key)
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Header("Retry-After", "60")
			telemetry.RateLimitRejectionsTotal.WithLabelValues("principal", keyTypeFromKey(key)).Inc()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			return
		}

		remaining, _ := backend.RemainingTokens(c.Request.Context(), key)
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

// tierFromKey extracts a tier label for metrics from a rate limit key.
func tierFromKey(key string) string {
	if len(key) > 4 && key[:4] == "org:" {
		return "organization"
	}
	return "individual"
}

// keyTypeFromKey extracts a key_type label for metrics from a rate limit key.
func keyTypeFromKey(key string) string {
	for i, ch := range key {
		if ch == ':' {
			return key[:i]
		}
	}
	return "unknown"
}

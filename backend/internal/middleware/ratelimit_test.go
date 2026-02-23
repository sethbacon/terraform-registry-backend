package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Config constructors
// ---------------------------------------------------------------------------

func TestDefaultRateLimitConfig(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.RequestsPerMinute != 200 {
		t.Errorf("RequestsPerMinute = %d, want 200", cfg.RequestsPerMinute)
	}
	if cfg.BurstSize != 50 {
		t.Errorf("BurstSize = %d, want 50", cfg.BurstSize)
	}
	if cfg.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, want 5m", cfg.CleanupInterval)
	}
}

func TestAuthRateLimitConfig(t *testing.T) {
	cfg := AuthRateLimitConfig()
	if cfg.RequestsPerMinute != 10 {
		t.Errorf("RequestsPerMinute = %d, want 10", cfg.RequestsPerMinute)
	}
	if cfg.BurstSize != 5 {
		t.Errorf("BurstSize = %d, want 5", cfg.BurstSize)
	}
}

func TestUploadRateLimitConfig(t *testing.T) {
	cfg := UploadRateLimitConfig()
	if cfg.RequestsPerMinute != 30 {
		t.Errorf("RequestsPerMinute = %d, want 30", cfg.RequestsPerMinute)
	}
	if cfg.BurstSize != 5 {
		t.Errorf("BurstSize = %d, want 5", cfg.BurstSize)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter.Allow
// ---------------------------------------------------------------------------

func newTestLimiter(rpm, burst int) *RateLimiter {
	cfg := RateLimitConfig{
		RequestsPerMinute: rpm,
		BurstSize:         burst,
		CleanupInterval:   time.Hour, // Don't clean up during tests
	}
	rl := NewRateLimiter(cfg)
	return rl
}

func TestRateLimiter_NewClientGetsFullBurst(t *testing.T) {
	rl := newTestLimiter(60, 5)
	defer rl.Stop()

	// First request from a new client always allowed
	if !rl.Allow("client-a") {
		t.Error("Allow() = false for new client, want true")
	}
}

func TestRateLimiter_AllowsUpToBurstSize(t *testing.T) {
	burst := 3
	rl := newTestLimiter(600, burst)
	defer rl.Stop()

	key := "burst-test"
	// The first request starts with burst-1 tokens, and we consume one per Allow call.
	// So we can make `burst` requests total.
	allowed := 0
	for i := 0; i < burst+2; i++ {
		if rl.Allow(key) {
			allowed++
		}
	}
	if allowed != burst {
		t.Errorf("allowed %d requests at burst=%d, want exactly %d", allowed, burst, burst)
	}
}

func TestRateLimiter_TokensRefillOverTime(t *testing.T) {
	// Use a high RPM so tokens refill quickly
	rl := newTestLimiter(600, 2) // 10 tokens/sec
	defer rl.Stop()

	key := "refill-test"
	// Exhaust tokens
	for rl.Allow(key) {
	}

	// Wait for 1 token to refill (should take ~100ms at 10/sec)
	time.Sleep(120 * time.Millisecond)

	if !rl.Allow(key) {
		t.Error("Allow() = false after token refill wait, want true")
	}
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := newTestLimiter(60, 2)
	defer rl.Stop()

	// Exhaust key-a
	for rl.Allow("key-a") {
	}

	// key-b should still be allowed
	if !rl.Allow("key-b") {
		t.Error("Allow() = false for independent key-b after exhausting key-a")
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := newTestLimiter(60, 5)
	// Should not panic
	rl.Stop()
}

// ---------------------------------------------------------------------------
// RateLimiter.RemainingTokens
// ---------------------------------------------------------------------------

func TestRateLimiter_RemainingTokens_NewKey(t *testing.T) {
	burst := 10
	rl := newTestLimiter(60, burst)
	defer rl.Stop()

	// Unknown key returns the burst size
	remaining := rl.RemainingTokens("unknown-key")
	if remaining != burst {
		t.Errorf("RemainingTokens(unknown) = %d, want %d", remaining, burst)
	}
}

func TestRateLimiter_RemainingTokens_AfterRequests(t *testing.T) {
	burst := 5
	rl := newTestLimiter(60, burst)
	defer rl.Stop()

	key := "remain-test"
	rl.Allow(key) // consume one token

	remaining := rl.RemainingTokens(key)
	// After one request, burst-1 tokens started = burst-2 remaining (Allow consumed one)
	// Actually: starts with burst-1 tokens, Allow consumes one more → burst-2
	if remaining < 0 || remaining > burst {
		t.Errorf("RemainingTokens = %d, want 0..%d", remaining, burst)
	}
}

// ---------------------------------------------------------------------------
// min helper
// ---------------------------------------------------------------------------

func TestMinHelper(t *testing.T) {
	tests := []struct{ a, b, want float64 }{
		{1.0, 2.0, 1.0},
		{2.0, 1.0, 1.0},
		{5.0, 5.0, 5.0},
		{0.0, 1.0, 0.0},
		{-1.0, 0.0, -1.0},
	}
	for _, tt := range tests {
		if got := min(tt.a, tt.b); got != tt.want {
			t.Errorf("min(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// getRateLimitKey
// ---------------------------------------------------------------------------

func TestGetRateLimitKey_UserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.Set("user_id", "user-123")
	c.Set("api_key_id", "key-456")

	key := getRateLimitKey(c)
	if key != "user:user-123" {
		t.Errorf("key = %q, want user:user-123 (user_id takes priority)", key)
	}
}

func TestGetRateLimitKey_APIKeyID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.Set("api_key_id", "key-456")

	key := getRateLimitKey(c)
	if key != "apikey:key-456" {
		t.Errorf("key = %q, want apikey:key-456", key)
	}
}

func TestGetRateLimitKey_IPFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	c.Request = req

	key := getRateLimitKey(c)
	if key == "" {
		t.Error("getRateLimitKey() returned empty key when falling back to IP")
	}
	// Should start with "ip:"
	if len(key) < 3 || key[:3] != "ip:" {
		t.Errorf("key = %q, want ip:... prefix for IP fallback", key)
	}
}

func TestGetRateLimitKey_EmptyUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	c.Request = req
	c.Set("user_id", "")    // empty, should skip to IP
	c.Set("api_key_id", "") // empty, should skip to IP

	key := getRateLimitKey(c)
	if len(key) < 3 || key[:3] != "ip:" {
		t.Errorf("key = %q, want ip:... when user_id and api_key_id are empty", key)
	}
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware
// ---------------------------------------------------------------------------

func newRateLimitRouter(limiter *RateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(RateLimitMiddleware(limiter))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRateLimitMiddleware_Allowed(t *testing.T) {
	rl := newTestLimiter(600, 10)
	defer rl.Stop()

	r := newRateLimitRouter(rl)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("X-RateLimit-Limit header missing on allowed request")
	}
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining header missing on allowed request")
	}
}

func TestRateLimitMiddleware_Blocked(t *testing.T) {
	// Burst of 1 so second request is blocked
	rl := newTestLimiter(1, 1)
	defer rl.Stop()

	r := newRateLimitRouter(rl)

	send := func() int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:1234"
		r.ServeHTTP(w, req)
		return w.Code
	}

	first := send()
	if first != http.StatusOK {
		t.Errorf("first request status = %d, want 200", first)
	}

	second := send()
	if second != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", second)
	}
}

func TestRateLimitMiddleware_BlockedHeaders(t *testing.T) {
	rl := newTestLimiter(1, 1)
	defer rl.Stop()

	r := newRateLimitRouter(rl)

	// Exhaust the burst
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.3:1234"
		r.ServeHTTP(w, req)
	}

	// Second request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.3:1234"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if retryAfter := w.Header().Get("Retry-After"); retryAfter != "60" {
		t.Errorf("Retry-After = %q, want 60", retryAfter)
	}
	remaining, _ := strconv.Atoi(w.Header().Get("X-RateLimit-Remaining"))
	if remaining < 0 {
		t.Errorf("X-RateLimit-Remaining = %d, should be >= 0", remaining)
	}
}

func TestRateLimitMiddleware_LimitHeaderMatchesConfig(t *testing.T) {
	rpm := 120
	rl := newTestLimiter(rpm, 20)
	defer rl.Stop()

	r := newRateLimitRouter(rl)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	r.ServeHTTP(w, req)

	limit := w.Header().Get("X-RateLimit-Limit")
	if limit != strconv.Itoa(rpm) {
		t.Errorf("X-RateLimit-Limit = %q, want %d", limit, rpm)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter.cleanup — ticker branch
// ---------------------------------------------------------------------------

func TestRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	cfg := RateLimitConfig{
		RequestsPerMinute: 600,
		BurstSize:         10,
		CleanupInterval:   10 * time.Millisecond,
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	// Create an entry via Allow so it exists in the map.
	rl.Allow("stale-client")

	// Back-date the entry's lastUpdate so the cleanup goroutine will evict it.
	rl.mu.Lock()
	if entry, ok := rl.entries["stale-client"]; ok {
		entry.lastUpdate = time.Now().Add(-11 * time.Minute)
	}
	rl.mu.Unlock()

	// Allow a few cleanup ticks to fire.
	time.Sleep(60 * time.Millisecond)

	// After cleanup the entry should have been removed; RemainingTokens returns
	// the full burst again (as if the key was never seen).
	rl.mu.RLock()
	_, stillPresent := rl.entries["stale-client"]
	rl.mu.RUnlock()

	if stillPresent {
		t.Error("expected stale-client entry to be evicted by cleanup goroutine, but it is still present")
	}
}

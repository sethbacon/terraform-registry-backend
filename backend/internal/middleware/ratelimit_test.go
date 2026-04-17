package middleware

import (
	"context"
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
	if cfg.RequestsPerMinute != 20 {
		t.Errorf("RequestsPerMinute = %d, want 20", cfg.RequestsPerMinute)
	}
	if cfg.BurstSize != 15 {
		t.Errorf("BurstSize = %d, want 15", cfg.BurstSize)
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
// MemoryRateLimiter.Allow (via RateLimiterBackend interface)
// ---------------------------------------------------------------------------

func newTestLimiter(rpm, burst int) *MemoryRateLimiter {
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
	allowed, err := rl.Allow(context.Background(), "client-a")
	if err != nil {
		t.Fatalf("Allow() unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Allow() = false for new client, want true")
	}
}

func TestRateLimiter_AllowsUpToBurstSize(t *testing.T) {
	burst := 3
	rl := newTestLimiter(600, burst)
	defer rl.Stop()

	key := "burst-test"
	ctx := context.Background()
	allowed := 0
	for i := 0; i < burst+2; i++ {
		ok, _ := rl.Allow(ctx, key)
		if ok {
			allowed++
		}
	}
	if allowed != burst {
		t.Errorf("allowed %d requests at burst=%d, want exactly %d", allowed, burst, burst)
	}
}

func TestRateLimiter_TokensRefillOverTime(t *testing.T) {
	rl := newTestLimiter(600, 2) // 10 tokens/sec
	defer rl.Stop()

	key := "refill-test"
	ctx := context.Background()
	for {
		ok, _ := rl.Allow(ctx, key)
		if !ok {
			break
		}
	}

	time.Sleep(120 * time.Millisecond)

	ok, err := rl.Allow(ctx, key)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !ok {
		t.Error("Allow() = false after token refill wait, want true")
	}
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := newTestLimiter(60, 2)
	defer rl.Stop()

	ctx := context.Background()
	for {
		ok, _ := rl.Allow(ctx, "key-a")
		if !ok {
			break
		}
	}

	ok, _ := rl.Allow(ctx, "key-b")
	if !ok {
		t.Error("Allow() = false for independent key-b after exhausting key-a")
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := newTestLimiter(60, 5)
	// Should not panic
	rl.Stop()
}

func TestRateLimiter_Close(t *testing.T) {
	rl := newTestLimiter(60, 5)
	if err := rl.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MemoryRateLimiter.RemainingTokens
// ---------------------------------------------------------------------------

func TestRateLimiter_RemainingTokens_NewKey(t *testing.T) {
	burst := 10
	rl := newTestLimiter(60, burst)
	defer rl.Stop()

	remaining, err := rl.RemainingTokens(context.Background(), "unknown-key")
	if err != nil {
		t.Fatalf("RemainingTokens() error: %v", err)
	}
	if remaining != burst {
		t.Errorf("RemainingTokens(unknown) = %d, want %d", remaining, burst)
	}
}

func TestRateLimiter_RemainingTokens_AfterRequests(t *testing.T) {
	burst := 5
	rl := newTestLimiter(60, burst)
	defer rl.Stop()

	key := "remain-test"
	ctx := context.Background()
	rl.Allow(ctx, key)

	remaining, _ := rl.RemainingTokens(ctx, key)
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
	c.Set("user_id", "")
	c.Set("api_key_id", "")

	key := getRateLimitKey(c)
	if len(key) < 3 || key[:3] != "ip:" {
		t.Errorf("key = %q, want ip:... when user_id and api_key_id are empty", key)
	}
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware (uses RateLimiterBackend interface)
// ---------------------------------------------------------------------------

func newRateLimitRouter(limiter RateLimiterBackend) *gin.Engine {
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
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining header missing on allowed request")
	}
}

func TestRateLimitMiddleware_Blocked(t *testing.T) {
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

	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.3:1234"
		r.ServeHTTP(w, req)
	}

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

func TestRateLimitMiddleware_NilBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimitMiddleware(nil))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("nil backend: status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// OrgRateLimitMiddleware
// ---------------------------------------------------------------------------

func TestOrgRateLimitMiddleware_IndividualOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := newTestLimiter(600, 10)
	defer rl.Stop()

	r := gin.New()
	r.Use(OrgRateLimitMiddleware(rl, nil))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestOrgRateLimitMiddleware_OrgLimitExceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	individual := newTestLimiter(600, 10)
	defer individual.Stop()
	orgLimiter := newTestLimiter(1, 1) // Very strict org limit
	defer orgLimiter.Stop()

	r := gin.New()
	// Simulate auth middleware setting organization_id
	r.Use(func(c *gin.Context) {
		c.Set("organization_id", "org-123")
		c.Next()
	})
	r.Use(OrgRateLimitMiddleware(individual, orgLimiter))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	send := func() int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.6:1234"
		r.ServeHTTP(w, req)
		return w.Code
	}

	// First request should pass
	if code := send(); code != http.StatusOK {
		t.Errorf("first request status = %d, want 200", code)
	}

	// Second request should be org-limited
	if code := send(); code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429 (org limit)", code)
	}
}

func TestOrgRateLimitMiddleware_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	individual := newTestLimiter(600, 10)
	defer individual.Stop()
	orgLimiter := newTestLimiter(1, 1)
	defer orgLimiter.Stop()

	r := gin.New()
	// No organization_id set — org limiter should be skipped
	r.Use(OrgRateLimitMiddleware(individual, orgLimiter))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.7:1234"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d status = %d, want 200 (no org context)", i, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// tierFromKey / keyTypeFromKey helpers
// ---------------------------------------------------------------------------

func TestTierFromKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"org:abc", "organization"},
		{"user:123", "individual"},
		{"apikey:x", "individual"},
		{"ip:1.2.3.4", "individual"},
	}
	for _, tt := range tests {
		if got := tierFromKey(tt.key); got != tt.want {
			t.Errorf("tierFromKey(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestKeyTypeFromKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"user:123", "user"},
		{"apikey:x", "apikey"},
		{"ip:1.2.3.4", "ip"},
		{"org:abc", "org"},
		{"noprefix", "unknown"},
	}
	for _, tt := range tests {
		if got := keyTypeFromKey(tt.key); got != tt.want {
			t.Errorf("keyTypeFromKey(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RateLimiterBackend interface compliance
// ---------------------------------------------------------------------------

func TestMemoryRateLimiter_ImplementsBackendInterface(t *testing.T) {
	var _ RateLimiterBackend = (*MemoryRateLimiter)(nil)
}

// ---------------------------------------------------------------------------
// MemoryRateLimiter.cleanup — ticker branch
// ---------------------------------------------------------------------------

func TestRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	cfg := RateLimitConfig{
		RequestsPerMinute: 600,
		BurstSize:         10,
		CleanupInterval:   10 * time.Millisecond,
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	rl.Allow(context.Background(), "stale-client")

	rl.mu.Lock()
	if entry, ok := rl.entries["stale-client"]; ok {
		entry.lastUpdate = time.Now().Add(-11 * time.Minute)
	}
	rl.mu.Unlock()

	time.Sleep(60 * time.Millisecond)

	rl.mu.RLock()
	_, stillPresent := rl.entries["stale-client"]
	rl.mu.RUnlock()

	if stillPresent {
		t.Error("expected stale-client entry to be evicted by cleanup goroutine, but it is still present")
	}
}

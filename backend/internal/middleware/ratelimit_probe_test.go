// ratelimit_probe_test.go guards how many times a single request is allowed to probe the
// rate-limiter backend.
//
// For the Redis backend the quota probe is the quota spend: redis_rate's GCRA has no
// peek-only operation, so RedisRateLimiter.RemainingTokens is implemented as a second
// Allow() and consumes another unit. When the middleware called Allow() for the decision and
// then RemainingTokens() for the X-RateLimit-Remaining header, every request cost two units
// and operators got half the requests-per-minute they configured. The middleware now takes
// the remaining count from the one Allow() it already made; these tests fail if a second
// probe — of either kind — comes back.
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// countingRateLimiterBackend records every probe made against it and returns a remaining
// count that is distinguishable per call, so a header populated from a second probe cannot
// coincidentally match one populated from the first.
type countingRateLimiterBackend struct {
	mu               sync.Mutex
	allowCalls       int
	remainingCalls   int
	allowedResponses []bool // consumed in order; the last value repeats
}

func (b *countingRateLimiterBackend) Allow(_ context.Context, _ string) (bool, int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowCalls++
	allowed := true
	if len(b.allowedResponses) > 0 {
		idx := b.allowCalls - 1
		if idx >= len(b.allowedResponses) {
			idx = len(b.allowedResponses) - 1
		}
		allowed = b.allowedResponses[idx]
	}
	// Remaining shrinks with each probe, exactly as a GCRA bucket does.
	return allowed, 100 - b.allowCalls, nil
}

func (b *countingRateLimiterBackend) RemainingTokens(_ context.Context, _ string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remainingCalls++
	return 999, nil
}

func (b *countingRateLimiterBackend) Close() error { return nil }

func (b *countingRateLimiterBackend) counts() (allow, remaining int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowCalls, b.remainingCalls
}

// TestRateLimitMiddlewares_ProbeTheBackendExactlyOnce covers every middleware that consults a
// backend, on both the allowed and the rejected path. The rejected path matters as much as
// the allowed one: a second probe there spends quota on a request that was already refused.
func TestRateLimitMiddlewares_ProbeTheBackendExactlyOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middlewares := map[string]func(RateLimiterBackend) gin.HandlerFunc{
		"RateLimitMiddleware": RateLimitMiddleware,
		"OrgRateLimitMiddleware": func(b RateLimiterBackend) gin.HandlerFunc {
			return OrgRateLimitMiddleware(b, nil)
		},
		"PrincipalRateLimitMiddleware": func(b RateLimiterBackend) gin.HandlerFunc {
			return PrincipalRateLimitMiddleware(b, nil)
		},
	}

	decisions := map[string][]bool{
		"allowed":  {true},
		"rejected": {false},
	}

	for mwName, build := range middlewares {
		for decision, responses := range decisions {
			t.Run(mwName+"/"+decision, func(t *testing.T) {
				backend := &countingRateLimiterBackend{allowedResponses: responses}

				r := gin.New()
				r.Use(build(backend))
				r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

				allow, remaining := backend.counts()
				if allow != 1 {
					t.Errorf("Allow called %d times for one request, want exactly 1 — each extra "+
						"probe spends another unit of the operator's configured quota", allow)
				}
				if remaining != 0 {
					t.Errorf("RemainingTokens called %d times, want 0 — on the Redis backend it is a "+
						"second Allow() and consumes quota; use the remaining value Allow already returned",
						remaining)
				}

				// The header must come from that single probe. 99 is what the first Allow
				// returns; 999 is the counting backend's RemainingTokens answer.
				if got := w.Header().Get("X-RateLimit-Remaining"); got != strconv.Itoa(99) {
					t.Errorf("X-RateLimit-Remaining = %q, want %q (the value the single Allow probe returned)",
						got, strconv.Itoa(99))
				}
			})
		}
	}
}

// TestOrgRateLimitMiddleware_ProbesEachBucketOnce extends the rule to the two-bucket path:
// the individual and per-organization limiters are distinct buckets, so one probe each is
// correct — but neither may be probed twice.
func TestOrgRateLimitMiddleware_ProbesEachBucketOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	individual := &countingRateLimiterBackend{}
	org := &countingRateLimiterBackend{}

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("organization_id", "org-1"); c.Next() })
	r.Use(OrgRateLimitMiddleware(individual, org))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	for name, backend := range map[string]*countingRateLimiterBackend{"individual": individual, "org": org} {
		allow, remaining := backend.counts()
		if allow != 1 {
			t.Errorf("%s bucket: Allow called %d times, want exactly 1", name, allow)
		}
		if remaining != 0 {
			t.Errorf("%s bucket: RemainingTokens called %d times, want 0", name, remaining)
		}
	}
}

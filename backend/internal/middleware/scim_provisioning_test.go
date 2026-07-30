package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestSCIMProvisioning_AuditAndRateLimit_Composition documents, in isolation,
// that PrincipalRateLimitMiddleware + OrgRateLimitMiddleware + AuditMiddleware
// compose correctly with each other (audit fires on a legit mutation; a
// burst past the limit gets 429). It builds its own stand-in gin.Engine and
// does NOT exercise the real scimGroup registration in
// internal/api/router_routes.go, so it would pass unchanged even if that
// wiring regressed — it is not, by itself, the regression guard for issue
// #666/its ordering follow-up.
//
// TestRegisterSCIMRoutes_RateLimitRunsAheadOfScopeCheck (internal/api package)
// is the regression test that exercises the real registerSCIMRoutes wiring
// and fails if RequireScope is ever registered ahead of the rate-limit/audit
// middleware again.
func TestSCIMProvisioning_AuditAndRateLimit_Composition(t *testing.T) {
	// Positive path: a legitimate provisioning mutation is both audited and
	// allowed through while under the rate limit.
	t.Run("legit mutation is audited", func(t *testing.T) {
		cs := newCaptureShipper(1)
		limiter := NewRateLimiter(RateLimitConfig{RequestsPerMinute: 200, BurstSize: 50, CleanupInterval: time.Minute})
		defer limiter.Stop()

		r := gin.New()
		scimGroup := r.Group("/scim/v2")
		scimGroup.Use(PrincipalRateLimitMiddleware(limiter, nil))
		scimGroup.Use(OrgRateLimitMiddleware(limiter, nil))
		scimGroup.Use(AuditMiddlewareWithShipper(nil, cs, nil))
		scimGroup.POST("/Users", func(c *gin.Context) { c.Status(http.StatusCreated) })

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		r.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", w.Code)
		}
		entry := cs.waitForEntry(t, 500*time.Millisecond)
		if entry.ResourceType != "scim_provisioning" {
			t.Errorf("audit entry ResourceType = %q, want %q", entry.ResourceType, "scim_provisioning")
		}
	})

	// Negative path: a burst of provisioning requests past the configured
	// limit is rejected with 429, same as every other authenticated mutating
	// route — proving rate limiting now actually applies to SCIM.
	t.Run("burst beyond limit is rejected", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimitConfig{RequestsPerMinute: 60, BurstSize: 2, CleanupInterval: time.Minute})
		defer limiter.Stop()

		r := gin.New()
		scimGroup := r.Group("/scim/v2")
		scimGroup.Use(PrincipalRateLimitMiddleware(limiter, nil))
		scimGroup.Use(OrgRateLimitMiddleware(limiter, nil))
		scimGroup.POST("/Users", func(c *gin.Context) { c.Status(http.StatusCreated) })

		var lastCode int
		for i := 0; i < 4; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
			req.RemoteAddr = "10.0.0.6:1234"
			r.ServeHTTP(w, req)
			lastCode = w.Code
		}

		if lastCode != http.StatusTooManyRequests {
			t.Errorf("status of request past burst size = %d, want 429", lastCode)
		}
	})
}

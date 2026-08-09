package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Issue #743 — registerPublicRoutes had no rate limiting anywhere.
//
// Every route family under registerAPIV1Routes is wrapped in one of the
// configured limiters. registerPublicRoutes — the anonymous,
// internet-reachable Terraform-protocol/OCI/mirror table — was wrapped in
// none, so the highest-volume handlers in the service, the ones doing DB
// lookups, presigned-URL round trips to S3/Azure/GCS, pull-through fetches
// with DB writes on a cache miss, and full archive streams through io.Copy,
// had no request-volume defence at the application layer at all.
//
// This test is written against the ROUTE TABLE, not a list of paths I typed
// out: it enumerates whatever registerPublicRoutes actually mounted and
// requires each route to be limited or to be a named exemption. A new public
// route lands unlimited exactly once, and this fails.

// rateLimitExemptPublicRoutes are the routes that must NOT be rate limited,
// each with the reason. Asserted in both directions: an exempt route that
// starts returning 429 fails, and a route dropped from the real table while
// still listed here fails too, so the list cannot rot into an unread allowlist.
var rateLimitExemptPublicRoutes = map[string]string{
	"GET /health": "liveness probe: kubelet probes for every pod on a node share " +
		"that node's source address, and rate-limiting liveness restarts healthy pods",
	"GET /ready": "readiness probe: a 429 here pulls a healthy pod out of service — " +
		"the limiter causing the outage it exists to prevent",
}

// publicRouteRouter mounts the real public route table with a limiter tight
// enough that a short burst crosses it.
func publicRouteRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 60, BurstSize: 2, CleanupInterval: time.Minute,
	})
	t.Cleanup(limiter.Stop)

	r := gin.New()
	// Handlers reached with sparse dependencies may panic; the limiter runs
	// ahead of the handler, so a recovered 500 does not affect what is asserted.
	r.Use(gin.Recovery())
	registerPublicRoutes(r, &publicRouteDeps{
		cfg:                 &config.Config{},
		db:                  db,
		userRepo:            repositories.NewUserRepository(db),
		orgRepo:             repositories.NewOrganizationRepository(db),
		protocolRateLimiter: limiter,
	})
	return r
}

// concretePath turns a gin route pattern into a requestable path.
func concretePath(pattern string) string {
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		switch {
		case strings.HasPrefix(p, "*"):
			parts[i] = "x"
		case strings.HasPrefix(p, ":"):
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

func TestPublicRoutes_EveryRouteIsRateLimitedOrNamedExempt(t *testing.T) {
	for _, ri := range publicRouteRouter(t).Routes() {
		key := ri.Method + " " + ri.Path
		reason, exempt := rateLimitExemptPublicRoutes[key]

		t.Run(key, func(t *testing.T) {
			// A fresh router per route: the limiter keys on client address, so
			// a shared engine would let one route drain the bucket and make
			// every later route look limited whether it is or not.
			r := publicRouteRouter(t)
			path := concretePath(ri.Path)

			// Burst 2, so by the 6th request a limited route must have answered
			// 429 at least once.
			var got429 bool
			for i := 0; i < 6; i++ {
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(ri.Method, path, nil))
				if w.Code == http.StatusTooManyRequests {
					got429 = true
				}
			}

			if exempt && got429 {
				t.Errorf("%s is rate limited but listed exempt (%s); "+
					"remove the exemption or the middleware", key, reason)
			}
			if !exempt && !got429 {
				t.Errorf("%s is NOT rate limited. Add protocolLimit to its group "+
					"or route in registerPublicRoutes, or add it to "+
					"rateLimitExemptPublicRoutes with a reason.", key)
			}
		})
	}
}

func TestRateLimitExemptions_AreAllStillRealRoutes(t *testing.T) {
	// The other direction. Without this, a route removed or renamed leaves a
	// dead exemption behind, and the next route to take that path inherits an
	// exemption nobody chose for it.
	mounted := map[string]bool{}
	for _, ri := range publicRouteRouter(t).Routes() {
		mounted[ri.Method+" "+ri.Path] = true
	}
	for key := range rateLimitExemptPublicRoutes {
		if !mounted[key] {
			t.Errorf("rateLimitExemptPublicRoutes lists %q, which registerPublicRoutes "+
				"no longer mounts — drop the entry", key)
		}
	}
}

func TestPublicRoutes_TableIsNotEmpty(t *testing.T) {
	// The failure mode the two tests above cannot see: if registerPublicRoutes
	// mounted nothing (a sparse-deps panic swallowed by a future refactor, a
	// renamed helper), both would iterate an empty set and report green while
	// checking nothing.
	routes := publicRouteRouter(t).Routes()
	if len(routes) < len(rateLimitExemptPublicRoutes)+8 {
		t.Fatalf("registerPublicRoutes mounted only %d routes — the table is not "+
			"being enumerated, so the rate-limit coverage assertions are vacuous",
			len(routes))
	}
}

// TestProtocolRateLimit_IsNotTheGeneralBudget pins the reason for a separate
// limiter. If these ever converge, one `terraform init` from a CI fleet behind
// a shared egress address can exhaust the same bucket the UI and API use.
func TestProtocolRateLimit_IsNotTheGeneralBudget(t *testing.T) {
	protocol := middleware.ProtocolRateLimitConfig()
	general := middleware.DefaultRateLimitConfig()

	if protocol.RequestsPerMinute <= general.RequestsPerMinute {
		t.Errorf("protocol rpm (%d) must exceed the general API rpm (%d): a single "+
			"terraform init fans out across discovery, version listing, download and "+
			"file fetch for every module and provider",
			protocol.RequestsPerMinute, general.RequestsPerMinute)
	}
	if protocol.BurstSize <= general.BurstSize {
		t.Errorf("protocol burst (%d) must exceed the general burst (%d)",
			protocol.BurstSize, general.BurstSize)
	}
}

// TestPublicRoutes_NilLimiterPassesThrough covers the rate-limiting-disabled
// deployment: the middleware must not become a hard block when no backend is
// configured.
func TestPublicRoutes_NilLimiterPassesThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.Use(gin.Recovery())
	registerPublicRoutes(r, &publicRouteDeps{
		cfg:                 &config.Config{},
		db:                  db,
		userRepo:            repositories.NewUserRepository(db),
		orgRepo:             repositories.NewOrganizationRepository(db),
		protocolRateLimiter: nil, // rate limiting disabled
	})

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/version", nil))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d got 429 with rate limiting disabled", i+1)
		}
	}
}

// TestProtocolRateLimit_KeyIsNotHeaderSpoofable is what separates a real limit
// from a cosmetic one on these routes.
//
// The protocol routes are anonymous, so getRateLimitPrincipal falls back to
// c.ClientIP(). Gin's default engine trusts every proxy, and under that default
// ClientIP() returns whatever X-Forwarded-For says -- a client could send a
// fresh address per request and never share a bucket with itself, leaving the
// limiter applied and useless. NewRouter calls SetTrustedProxies with
// cfg.Server.TrustedProxies, which defaults to empty (trust nothing).
//
// This asserts the resulting behaviour rather than the config value: rotating
// X-Forwarded-For must not buy extra requests.
func TestProtocolRateLimit_KeyIsNotHeaderSpoofable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 60, BurstSize: 2, CleanupInterval: time.Minute,
	})
	defer limiter.Stop()

	r := gin.New()
	r.Use(gin.Recovery())
	// The production default: empty list, i.e. trust no proxy.
	if err := r.SetTrustedProxies([]string{}); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	registerPublicRoutes(r, &publicRouteDeps{
		cfg:                 &config.Config{},
		db:                  db,
		userRepo:            repositories.NewUserRepository(db),
		orgRepo:             repositories.NewOrganizationRepository(db),
		protocolRateLimiter: limiter,
	})

	var got429 bool
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest("GET", "/version", nil)
		// A different claimed client address every time.
		req.Header.Set("X-Forwarded-For", "203.0.113."+string(rune('1'+i)))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Error("rotating X-Forwarded-For evaded the rate limit — the limiter is " +
			"keyed on a client-controlled header. Check SetTrustedProxies / " +
			"server.trusted_proxies; it must not trust arbitrary proxies.")
	}
}

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// loopbackGuard allow-lists the loopback addresses httptest.NewServer binds to
// (127.0.0.1 / ::1) so the positive-path tests below can exercise a real
// outbound round trip through the httpsafe-guarded client (issue #653)
// without the strict default policy rejecting the test server itself as an
// internal target.
var loopbackGuard = httpsafe.MustGuard("127.0.0.1", "::1")

// mountConsumers mounts the proxy for a PLATFORM ADMIN caller.
//
// That scope crosses organization boundaries here as it does everywhere else,
// so it is the caller for which this proxy's behaviour is unchanged by #439 --
// which is what keeps every pre-existing test below meaningful. Callers with a
// narrower scope are covered by the #439 tests at the end of this file.
func mountConsumers(cfg *config.Config, dc *suite.DiscoveryClient, guard *httpsafe.Guard) *gin.Engine {
	return mountConsumersAsCaller(cfg, dc, guard, func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
	})
}

// mountConsumersAsCaller mounts the proxy behind a middleware that establishes
// whatever principal a test needs, standing in for the authenticated group the
// route really sits in.
func mountConsumersAsCaller(cfg *config.Config, dc *suite.DiscoveryClient, guard *httpsafe.Guard, principal gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.GET("/api/v1/suite/modules/:namespace/:name/:system/consumers",
		principal,
		moduleConsumersHandler(func() *suite.DiscoveryClient { return dc }, cfg, guard, nil))
	return r
}

func getConsumers(r *gin.Engine) (int, map[string]any) {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/suite/modules/acme/vpc/aws/consumers", nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// identityLoopbackGuard is the egress policy the SHARED module's clients run
// under here — the identity/httpsafe twin of loopbackGuard above. httptest serves on
// 127.0.0.1, which identity/httpsafe's default policy DENIES since v0.25.0, so
// a discovery client built with a nil guard would never reach the sibling —
// exactly the deployment failure the allow-list exists to fix, and exactly what
// TFR_SECURITY_EGRESS_ALLOWLIST names in the dev stack.
func identityLoopbackGuard(t *testing.T) *identityhttpsafe.Guard {
	t.Helper()
	g, err := identityhttpsafe.NewGuard([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

// activeClient builds a DiscoveryClient polling url and waits for it to go active.
// url is an httptest.Server address (plaintext HTTP), so this uses
// NewInsecureDiscoveryClient — the library's explicit opt-out of the
// HTTPS-only requirement NewDiscoveryClient enforces for real sibling URLs —
// rather than the production constructor.
func activeClient(t *testing.T, url string) *suite.DiscoveryClient {
	t.Helper()
	self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry"}
	dc := suite.NewInsecureDiscoveryClient(url, self, time.Minute, identityLoopbackGuard(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	go dc.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := dc.Snapshot(); st == suite.StateActive {
			return dc
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("discovery client did not become active")
	return nil
}

func TestModuleConsumers_StandaloneReturnsEmpty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "tok"
	code, out := getConsumers(mountConsumers(cfg, nil, nil)) // no sibling
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if c, _ := out["consumers"].([]any); len(c) != 0 || out["total"].(float64) != 0 {
		t.Errorf("standalone must be empty: %v", out)
	}
}

func TestModuleConsumers_NoTokenReturnsEmpty(t *testing.T) {
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com" // SiblingToken empty → inert
	_, out := getConsumers(mountConsumers(cfg, dc, loopbackGuard))
	if c, _ := out["consumers"].([]any); len(c) != 0 {
		t.Errorf("no sibling token must yield empty: %v", out)
	}
}

func TestModuleConsumers_ProxiesActiveSibling(t *testing.T) {
	var gotToken, gotHost, gotModule string
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			gotToken = r.Header.Get("X-Suite-Service-Token")
			gotHost = r.URL.Query().Get("host")
			gotModule = r.URL.Query().Get("module")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"consumers": []map[string]any{{"source_id": "s1", "source_name": "prod", "state_key": "app.tfstate"}},
				"total":     1,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(manifest) // discovery poll
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "s3cr3t"
	code, out := getConsumers(mountConsumers(cfg, dc, loopbackGuard))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if out["total"].(float64) != 1 {
		t.Errorf("total = %v, want 1", out["total"])
	}
	if c, _ := out["consumers"].([]any); len(c) != 1 {
		t.Errorf("consumers = %v, want 1 row", out["consumers"])
	}
	if gotToken != "s3cr3t" {
		t.Errorf("service token not forwarded to sibling: %q", gotToken)
	}
	if gotModule != "acme/vpc/aws" {
		t.Errorf("module param = %q, want acme/vpc/aws", gotModule)
	}
	if gotHost != "registry.example.com" {
		t.Errorf("host param = %q, want registry.example.com (the registry's own host)", gotHost)
	}
}

// TestModuleConsumers_EmitsHostAliasSet proves the registry forwards its full
// canonical host-identity set (public host + base host + operator aliases,
// de-duped) as repeated &host= params so a vanity-CNAME / split-horizon
// deployment still joins.
func TestModuleConsumers_EmitsHostAliasSet(t *testing.T) {
	var gotHosts []string
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			gotHosts = r.URL.Query()["host"]
			_ = json.NewEncoder(w).Encode(map[string]any{"consumers": []map[string]any{}, "total": 0})
			return
		}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Server.BaseURL = "http://registry.internal:8080"
	cfg.Server.HostAliases = []string{"tf.example.com", "REGISTRY.example.com"} // alias + dup-of-public
	cfg.Suite.SiblingToken = "s3cr3t"
	if code, _ := getConsumers(mountConsumers(cfg, dc, loopbackGuard)); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	want := map[string]bool{"registry.example.com": true, "registry.internal:8080": true, "tf.example.com": true}
	if len(gotHosts) != len(want) {
		t.Fatalf("emitted hosts = %v, want the 3-host deduped set %v", gotHosts, want)
	}
	for _, h := range gotHosts {
		if !want[h] {
			t.Errorf("unexpected emitted host %q (set %v)", h, gotHosts)
		}
	}
}

func TestModuleConsumers_SiblingErrorReturnsEmpty(t *testing.T) {
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			w.WriteHeader(http.StatusUnauthorized) // e.g. wrong/absent token at the sibling
			return
		}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "s3cr3t"
	_, out := getConsumers(mountConsumers(cfg, dc, loopbackGuard))
	if c, _ := out["consumers"].([]any); len(c) != 0 {
		t.Errorf("sibling error must yield empty (graceful): %v", out)
	}
}

// TestModuleConsumers_OversizedResponseIsCappedAndFails is the regression test
// for issue #662: the sibling response is decoded through an io.LimitReader
// capped at maxConsumersResponseBytes (1 MB), so a well-formed JSON document
// whose encoded size exceeds that cap is truncated mid-document and fails to
// decode, falling back to the graceful empty result -- it is never fully
// buffered or forwarded. Without the io.LimitReader wrap (i.e. reverting
// suite.go's decode to a bare resp.Body), this same oversized document would
// decode successfully with all its rows and this test would fail.
func TestModuleConsumers_OversizedResponseIsCappedAndFails(t *testing.T) {
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			w.Header().Set("Content-Type", "application/json")
			// A single well-formed JSON document whose encoded size exceeds
			// maxConsumersResponseBytes: the padding pushes total size past the
			// cap, so io.LimitReader truncates mid-string before the closing
			// quote/braces are ever read.
			_, _ = io.WriteString(w, `{"consumers":[{"source_id":"s1","pad":"`)
			_, _ = io.WriteString(w, strings.Repeat("x", maxConsumersResponseBytes+1024))
			_, _ = io.WriteString(w, `"}],"total":1}`)
			return
		}
		_ = json.NewEncoder(w).Encode(manifest) // discovery poll
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "s3cr3t"
	code, out := getConsumers(mountConsumers(cfg, dc, loopbackGuard))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if c, _ := out["consumers"].([]any); len(c) != 0 {
		t.Errorf("oversized (cap-truncated) response must decode-fail to empty, got %d consumers", len(c))
	}
}

// TestModuleConsumers_BlocksNonAllowlistedSiblingURL is the negative test for
// issue #653: moduleConsumersHandler must not reach a sibling whose
// self-advertised PublicURL (m.PublicURL, taken from the discovery manifest —
// not the operator-pinned SiblingURL) is outside the operator's egress
// allow-list, even though discovery itself already succeeded. A nil egress
// guard is the strict default policy (no allow-list), so the loopback address
// every httptest.Server in this file binds to stands in for the internal/
// metadata host a compromised sibling or a MITM'd discovery response could
// try to steer this credential-bearing request at.
//
// Since identity v0.25.0 the sibling-asserted URL is a distinct type
// (suite.UntrustedURL) with exactly two ways out — Resolve, which checks, and
// Display, which is for rendering — so the handler cannot build a request from
// it without passing the policy. What this test pins is unchanged and is the
// part that matters: whatever the discovery client was willing to poll, a
// target outside THIS deployment's allow-list is never reached.
func TestModuleConsumers_BlocksNonAllowlistedSiblingURL(t *testing.T) {
	var consumersHit bool
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			consumersHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"consumers": []map[string]any{{"source_id": "s1"}},
				"total":     1,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(manifest) // discovery poll
	}))
	defer srv.Close()
	manifest.PublicURL = suite.UntrustedURL(srv.URL)
	dc := activeClient(t, srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "s3cr3t"
	code, out := getConsumers(mountConsumers(cfg, dc, nil)) // nil guard == strict default, no allow-list
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if c, _ := out["consumers"].([]any); len(c) != 0 {
		t.Errorf("non-allowlisted sibling target must yield empty: %v", out)
	}
	if consumersHit {
		t.Error("the sibling's /consumers endpoint must never be reached when its advertised PublicURL is not egress-allowlisted")
	}
}

// ---------------------------------------------------------------------------
// #439 — the sibling's /consumers has no principal, so this proxy must name the
// caller's organizations on its behalf.
//
// The sibling is authenticated only by a shared suite service token and cannot
// work out who is asking, so today it answers fleet-wide and a registry user in
// one organization sees another's source names and state keys through here.
// Sending the scope is what lets the sibling begin enforcing it.
// ---------------------------------------------------------------------------

// consumersSibling starts a sibling that records the /consumers query it was
// asked, answers it, and serves discovery polls. onConsumers reports whether
// the endpoint was reached at all.
func consumersSibling(t *testing.T, body string, seen *url.Values, reached *bool) (*config.Config, *suite.DiscoveryClient) {
	t.Helper()
	manifest := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-state-manager"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/consumers") {
			if reached != nil {
				*reached = true
			}
			if seen != nil {
				*seen = r.URL.Query()
			}
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	t.Cleanup(srv.Close)
	manifest.PublicURL = suite.UntrustedURL(srv.URL)

	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Suite.SiblingToken = "s3cr3t"
	return cfg, activeClient(t, srv.URL)
}

// capturedQuery runs one request through the proxy and returns the query the
// sibling was asked.
func capturedQuery(t *testing.T, principal gin.HandlerFunc) url.Values {
	t.Helper()
	var got url.Values
	cfg, dc := consumersSibling(t, `{"consumers":[],"total":0}`, &got, nil)
	code, _ := getConsumers(mountConsumersAsCaller(cfg, dc, loopbackGuard, principal))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	return got
}

func TestModuleConsumers_NamesTheCallersOrganizations(t *testing.T) {
	q := capturedQuery(t, func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeModulesRead)})
		c.Set("api_key", &models.APIKey{OrganizationID: "org-acme"})
	})

	orgs := q["organization"]
	if len(orgs) != 1 || orgs[0] != "org-acme" {
		t.Errorf("organization = %v, want [org-acme]", orgs)
	}
	// The pre-existing parameters must survive unchanged.
	if q.Get("module") != "acme/vpc/aws" {
		t.Errorf("module = %q, want acme/vpc/aws", q.Get("module"))
	}
	if len(q["host"]) == 0 {
		t.Error("host set must still be sent")
	}
}

// A platform admin deliberately sends NO organization parameter: that scope
// crosses organization boundaries here exactly as it does elsewhere, and its
// absence is what the sibling will read as fleet-wide, gated on its own
// operator opt-in. Pinning this stops a later change from quietly narrowing an
// admin's view, or from inventing a magic wildcard value.
func TestModuleConsumers_PlatformAdminSendsNoOrganization(t *testing.T) {
	q := capturedQuery(t, func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
	})
	// Assert the sibling was ACTUALLY queried first. Without this, "sent no
	// organization" and "never asked at all" are the same observation, and a
	// short-circuit that wrongly caught platform admins would pass here.
	if q.Get("module") != "acme/vpc/aws" {
		t.Fatalf("the sibling was not queried for a platform admin (module=%q)", q.Get("module"))
	}
	if orgs := q["organization"]; len(orgs) != 0 {
		t.Errorf("organization = %v, want none for a platform admin", orgs)
	}
}

// A caller who holds no organizations can legitimately see no consumers, and
// this is answered WITHOUT asking the sibling -- which closes this half of the
// disclosure now rather than waiting for the sibling to enforce the parameter.
//
// The sibling here fails the test if it is contacted at all: that is the
// assertion, not the empty body, because an un-enforcing sibling would answer
// fleet-wide and the body alone could not tell the two apart.
func TestModuleConsumers_CallerWithNoOrganizationsNeverReachesTheSibling(t *testing.T) {
	var reached bool
	cfg, dc := consumersSibling(t,
		`{"consumers":[{"state_key":"other-org/prod"}],"total":1}`, nil, &reached)

	r := mountConsumersAsCaller(cfg, dc, loopbackGuard, func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeModulesRead)})
		// authenticated, but belongs to no organization
	})
	code, body := getConsumers(r)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if reached {
		t.Error("the sibling was queried for a caller with no organizations; it answers fleet-wide, so this leaks another organization's state keys")
	}
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("total = %v, want 0", total)
	}
}

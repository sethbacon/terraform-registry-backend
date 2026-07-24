package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// loopbackGuard allow-lists the loopback addresses httptest.NewServer binds to
// (127.0.0.1 / ::1) so the positive-path tests below can exercise a real
// outbound round trip through the httpsafe-guarded client (issue #653)
// without the strict default policy rejecting the test server itself as an
// internal target.
var loopbackGuard = httpsafe.MustGuard("127.0.0.1", "::1")

func mountConsumers(cfg *config.Config, dc *suite.DiscoveryClient, guard *httpsafe.Guard) *gin.Engine {
	r := gin.New()
	r.GET("/api/v1/suite/modules/:namespace/:name/:system/consumers",
		moduleConsumersHandler(func() *suite.DiscoveryClient { return dc }, cfg, guard))
	return r
}

func getConsumers(r *gin.Engine) (int, map[string]any) {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/suite/modules/acme/vpc/aws/consumers", nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// activeClient builds a DiscoveryClient polling url and waits for it to go active.
// url is an httptest.Server address (plaintext HTTP), so this uses
// NewInsecureDiscoveryClient — the library's explicit opt-out of the
// HTTPS-only requirement NewDiscoveryClient enforces for real sibling URLs —
// rather than the production constructor.
func activeClient(t *testing.T, url string) *suite.DiscoveryClient {
	t.Helper()
	self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry"}
	dc := suite.NewInsecureDiscoveryClient(url, self, time.Minute)
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
	manifest.PublicURL = srv.URL
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
	manifest.PublicURL = srv.URL
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
	manifest.PublicURL = srv.URL
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
	manifest.PublicURL = srv.URL
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
	manifest.PublicURL = srv.URL
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
	manifest.PublicURL = srv.URL
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

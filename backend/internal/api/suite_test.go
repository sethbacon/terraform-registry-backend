package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

func init() { gin.SetMode(gin.TestMode) }

func TestSuiteManifestHandler(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.BaseURL = "https://registry.example.com"

	r := gin.New()
	r.GET("/api/v1/suite/manifest", suiteManifestHandler(cfg))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/suite/manifest", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var m suite.Manifest
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.App != "terraform-registry" {
		t.Errorf("app = %q, want terraform-registry", m.App)
	}
	if m.SchemaVersion != suite.SchemaVersionV1 {
		t.Errorf("schemaVersion = %q, want %q", m.SchemaVersion, suite.SchemaVersionV1)
	}
	if m.PublicURL != "https://registry.example.com" {
		t.Errorf("publicUrl = %q, want https://registry.example.com", m.PublicURL)
	}
	if len(m.Capabilities) == 0 {
		t.Error("capabilities should not be empty")
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=30" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestSuiteManifestHandler_PublicURLFallsBackToBaseURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.BaseURL = "http://localhost:8080"
	cfg.Server.PublicURL = "https://public.example.com"

	r := gin.New()
	r.GET("/api/v1/suite/manifest", suiteManifestHandler(cfg))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/suite/manifest", nil))

	var m suite.Manifest
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.PublicURL != "https://public.example.com" {
		t.Errorf("publicUrl = %q, want https://public.example.com", m.PublicURL)
	}
}

func TestUIConfigHandler_NoSibling(t *testing.T) {
	r := gin.New()
	r.GET("/api/v1/ui/config", uiConfigHandler(&config.Config{}, func() *suite.DiscoveryClient { return nil }))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ui/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["sibling"] != nil {
		t.Errorf("sibling = %v, want nil", resp["sibling"])
	}
}

func TestUIConfigHandler_ActiveSibling(t *testing.T) {
	sibling := suite.Manifest{
		SchemaVersion: suite.SchemaVersionV1,
		App:           "terraform-state-manager",
		PublicURL:     "https://tfstate.example.com",
		Links:         map[string]string{"sourceDetail": "/sources/{id}"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sibling)
	}))
	defer srv.Close()

	self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry"}
	// srv is a plaintext httptest.Server, so use the library's explicit
	// HTTPS opt-out constructor rather than the production one.
	dc := suite.NewInsecureDiscoveryClient(srv.URL, self, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go dc.Start(ctx)
	// Wait for the first poll to register an active state.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := dc.Snapshot(); st == suite.StateActive {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	r := gin.New()
	r.GET("/api/v1/ui/config", uiConfigHandler(&config.Config{}, func() *suite.DiscoveryClient { return dc }))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ui/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Sibling *struct {
			App       string `json:"app"`
			State     string `json:"state"`
			PublicURL string `json:"publicUrl"`
		} `json:"sibling"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Sibling == nil {
		t.Fatal("sibling is nil, want active state")
	}
	if resp.Sibling.State != "active" {
		t.Errorf("state = %q, want active", resp.Sibling.State)
	}
	if resp.Sibling.App != "terraform-state-manager" {
		t.Errorf("app = %q, want terraform-state-manager", resp.Sibling.App)
	}
	if resp.Sibling.PublicURL != "https://tfstate.example.com" {
		t.Errorf("publicUrl = %q", resp.Sibling.PublicURL)
	}
}

func TestUIConfigHandler_UnreachableSibling(t *testing.T) {
	self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry"}
	dc := suite.NewInsecureDiscoveryClient("http://127.0.0.1:1", self, 0)
	dc.Start(ctxThatCancelsImmediately())

	r := gin.New()
	r.GET("/api/v1/ui/config", uiConfigHandler(&config.Config{}, func() *suite.DiscoveryClient { return dc }))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ui/config", nil))

	var resp struct {
		Sibling *struct {
			State string `json:"state"`
		} `json:"sibling"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Sibling == nil {
		t.Fatal("sibling is nil, want unreachable state object")
	}
	if resp.Sibling.State != "unreachable" {
		t.Errorf("state = %q, want unreachable", resp.Sibling.State)
	}
}

func TestStartSuiteDiscovery_NilWhenNoSiblingURL(t *testing.T) {
	cfg := &config.Config{}
	if dc := startSuiteDiscovery(cfg); dc != nil {
		t.Error("expected nil when SiblingURL is empty")
	}
}

func TestUIConfigHandler_ForwardsIdentityBlock(t *testing.T) {
	sibling := suite.Manifest{
		SchemaVersion: suite.SchemaVersionV1,
		App:           "terraform-state-manager",
		PublicURL:     "https://tfstate.example.com",
		Identity:      suite.IdentityInfo{Issuer: "terraform-state-manager", SharedStore: true, Schema: "identity"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(sibling)
	}))
	defer srv.Close()

	self := suite.Manifest{SchemaVersion: suite.SchemaVersionV1, App: "terraform-registry"}
	// srv is a plaintext httptest.Server, so use the library's explicit
	// HTTPS opt-out constructor rather than the production one.
	dc := suite.NewInsecureDiscoveryClient(srv.URL, self, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go dc.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := dc.Snapshot(); st == suite.StateActive {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	decodeSibling := func(cfg *config.Config) map[string]any {
		r := gin.New()
		r.GET("/api/v1/ui/config", uiConfigHandler(cfg, func() *suite.DiscoveryClient { return dc }))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ui/config", nil))
		var resp struct {
			Sibling map[string]any `json:"sibling"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return resp.Sibling
	}

	// issuer is always forwarded; sharedStore is true only when THIS app also
	// asserts the shared store (seamless SSO).
	shared := decodeSibling(&config.Config{Suite: config.SuiteConfig{IdentitySharedStore: true}})
	if shared["issuer"] != "terraform-state-manager" {
		t.Errorf("issuer = %v, want terraform-state-manager", shared["issuer"])
	}
	if shared["sharedStore"] != true {
		t.Errorf("sharedStore = %v, want true (both apps assert it)", shared["sharedStore"])
	}

	// This app does NOT assert the shared store → keep the hint even though the
	// sibling claims one (the AND).
	notShared := decodeSibling(&config.Config{})
	if notShared["sharedStore"] != false {
		t.Errorf("sharedStore = %v, want false (this app does not assert it)", notShared["sharedStore"])
	}
}

// ctxThatCancelsImmediately returns a context that is already cancelled, so
// DiscoveryClient.Start performs exactly one poll then returns.
func ctxThatCancelsImmediately() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

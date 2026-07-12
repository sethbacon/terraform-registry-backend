package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// fetchBundle — scheme enforcement
// ---------------------------------------------------------------------------

func TestFetchBundle_RequiresHTTPS(t *testing.T) {
	_, err := fetchBundle(context.Background(), "http://bundles.example.com/bundle.tar.gz", "", nil)
	if err == nil {
		t.Fatal("expected error for non-HTTPS bundle_url, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement: %v", err)
	}
}

func TestFetchBundle_HTTPAllowedWhenHostAllowlisted(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	files, err := fetchBundle(context.Background(), srv.URL+"/bundle.tar.gz", "", loopbackGuard)
	if err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 rego file, got %d", len(files))
	}
}

// ---------------------------------------------------------------------------
// fetchBundle — pinned SHA-256 verification (fail closed)
// ---------------------------------------------------------------------------

func TestFetchBundle_SHA256Mismatch_FailsClosed(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	wrongSHA := strings.Repeat("a", 64)
	_, err = fetchBundle(context.Background(), srv.URL+"/bundle.tar.gz", wrongSHA, loopbackGuard)
	if err == nil {
		t.Fatal("expected error for sha256 mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("error should mention sha256 mismatch: %v", err)
	}
}

func TestFetchBundle_SHA256Match_Succeeds(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	sum := sha256.Sum256(bundleData)
	expected := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	files, err := fetchBundle(context.Background(), srv.URL+"/bundle.tar.gz", expected, loopbackGuard)
	if err != nil {
		t.Fatalf("fetchBundle with matching sha256: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 rego file, got %d", len(files))
	}
}

// ---------------------------------------------------------------------------
// PolicyEngine — bundle sha256 mismatch keeps previously loaded policies
// ---------------------------------------------------------------------------

func TestPolicyEngine_Reload_SHA256Mismatch_KeepsPreviousPolicies(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	engine, err := NewPolicyEngineWithGuard(Config{
		Enabled:   true,
		Mode:      "block",
		BundleURL: srv.URL + "/bundle.tar.gz",
	}, loopbackGuard)
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Sanity: the deny rule is active before the failed reload.
	result, err := engine.Evaluate(context.Background(), map[string]interface{}{"namespace": "blocked"})
	if err != nil {
		t.Fatalf("Evaluate (before): %v", err)
	}
	if result.Allowed {
		t.Fatal("expected deny rule to fire before reload attempt")
	}

	// Reload with a deliberately wrong pin — set directly on the engine so
	// loadBundle picks it up, mirroring a config change plus Reload call.
	engine.bundleSHA256 = strings.Repeat("b", 64)
	if err := engine.Reload(context.Background(), srv.URL+"/bundle.tar.gz"); err == nil {
		t.Fatal("expected Reload to fail on sha256 mismatch")
	}

	// The previously loaded (and still valid) policy must still be enforced —
	// fail closed means the bad bundle never takes effect, not that the
	// engine falls back to allow-everything.
	result, err = engine.Evaluate(context.Background(), map[string]interface{}{"namespace": "blocked"})
	if err != nil {
		t.Fatalf("Evaluate (after failed reload): %v", err)
	}
	if result.Allowed {
		t.Error("a failed reload must not discard the previously loaded policy")
	}
}

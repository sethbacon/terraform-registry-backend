package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── parseBundleTarGz ────────────────────────────────────────────────────────

func buildBundle(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestParseBundleTarGz_RegoFilesOnly(t *testing.T) {
	data, err := buildBundle(map[string]string{
		"policy/deny.rego": `package registry`,
		"README.md":        "# readme",
		"data.json":        `{}`,
	})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	files, err := parseBundleTarGz(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parseBundleTarGz: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 rego file, got %d", len(files))
	}
	if files[0].name != "policy/deny.rego" {
		t.Errorf("unexpected file name: %s", files[0].name)
	}
}

func TestParseBundleTarGz_Empty(t *testing.T) {
	data, err := buildBundle(map[string]string{})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}
	files, err := parseBundleTarGz(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parseBundleTarGz: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

// ─── PolicyEngine — disabled ─────────────────────────────────────────────────

func TestPolicyEngine_Disabled(t *testing.T) {
	engine, err := NewPolicyEngine(Config{Enabled: false, Mode: "block"})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	result, err := engine.Evaluate(context.Background(), map[string]interface{}{"anything": true})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Error("disabled engine should always allow")
	}
}

// ─── PolicyEngine — no bundle URL ────────────────────────────────────────────

func TestPolicyEngine_EnabledNoBundleURL(t *testing.T) {
	engine, err := NewPolicyEngine(Config{Enabled: true, Mode: "warn"})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	// No policies loaded — should pass through.
	result, err := engine.Evaluate(context.Background(), map[string]interface{}{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Error("engine with no policies loaded should allow")
	}
}

// ─── PolicyEngine — bundle from HTTP, deny rule fires ─────────────────────────

const denyNamespaceRego = `package registry

deny[msg] {
	input.namespace == "blocked"
	msg := "namespace 'blocked' is not permitted"
}
`

func TestPolicyEngine_BundleFromHTTP_DenyFires(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	engine, err := NewPolicyEngine(Config{
		Enabled:   true,
		Mode:      "block",
		BundleURL: srv.URL + "/bundle.tar.gz",
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Input that triggers deny.
	result, err := engine.Evaluate(context.Background(), map[string]interface{}{"namespace": "blocked"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Allowed {
		t.Error("expected deny rule to fire")
	}
	if len(result.Violations) == 0 {
		t.Error("expected at least one violation")
	}
	if result.Mode != "block" {
		t.Errorf("expected mode=block, got %s", result.Mode)
	}
}

func TestPolicyEngine_BundleFromHTTP_Allow(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	engine, err := NewPolicyEngine(Config{
		Enabled:   true,
		Mode:      "warn",
		BundleURL: srv.URL + "/bundle.tar.gz",
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Input that does NOT trigger deny.
	result, err := engine.Evaluate(context.Background(), map[string]interface{}{"namespace": "allowed"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Error("expected input to be allowed")
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations, got %d", len(result.Violations))
	}
}

// ─── Reload ──────────────────────────────────────────────────────────────────

func TestPolicyEngine_Reload(t *testing.T) {
	bundleData, err := buildBundle(map[string]string{"deny.rego": denyNamespaceRego})
	if err != nil {
		t.Fatalf("building bundle: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer srv.Close()

	engine, err := NewPolicyEngine(Config{
		Enabled:   true,
		Mode:      "block",
		BundleURL: srv.URL + "/bundle.tar.gz",
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Reload should succeed.
	if err := engine.Reload(context.Background(), srv.URL+"/bundle.tar.gz"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

// ─── IsEnabled / Mode ─────────────────────────────────────────────────────────

func TestPolicyEngine_IsEnabled(t *testing.T) {
	disabled, _ := NewPolicyEngine(Config{Enabled: false})
	if disabled.IsEnabled() {
		t.Error("expected disabled")
	}
	enabled, _ := NewPolicyEngine(Config{Enabled: true, Mode: "warn"})
	if !enabled.IsEnabled() {
		t.Error("expected enabled")
	}
}

func TestPolicyEngine_Mode(t *testing.T) {
	e, _ := NewPolicyEngine(Config{Mode: "block"})
	if e.Mode() != "block" {
		t.Errorf("expected block, got %s", e.Mode())
	}
}

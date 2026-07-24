package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

func jsonBodyAdmin(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func TestInstallScannerHandler_BadJSON(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	r := gin.New()
	r.POST("/install", NewScanningInstallHandler(cfg, nil, nil, nil, nil).Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin("not json{"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestInstallScannerHandler_UnsupportedTool(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	r := gin.New()
	r.POST("/install", NewScanningInstallHandler(cfg, nil, nil, nil, nil).Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin(map[string]string{"tool": "snyk"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp InstallScannerAdminResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false")
	}
}

func TestInstallScannerHandler_EmptyInstallDir(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: ""}
	r := gin.New()
	r.POST("/install", NewScanningInstallHandler(cfg, nil, nil, nil, nil).Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin(map[string]string{"tool": "trivy"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestInstallScannerHandler_InstallerSuccess(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	stub := func(ctx context.Context, c installer.InstallConfig, tool, version string) (*installer.Result, error) {
		return &installer.Result{
			BinaryPath: "/app/scanners/trivy",
			Version:    "0.52.2",
			Sha256:     "abcd",
			SourceURL:  "https://example.com",
		}, nil
	}

	r := gin.New()
	r.POST("/install", NewScanningInstallHandler(cfg, stub, nil, nil, nil).Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin(map[string]string{"tool": "trivy"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp InstallScannerAdminResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Errorf("expected success=true, error=%s", resp.Error)
	}
	if resp.Version != "0.52.2" {
		t.Errorf("version = %q", resp.Version)
	}
}

// TestInstallScannerHandler_ThreadsEgressGuard locks in that the admin install
// endpoint passes the operator-configured egress guard through installer.Handle
// into the InstallConfig the install func receives (issue #676's threading
// requirement), rather than silently falling back to the strict nil-guard
// default.
func TestInstallScannerHandler_ThreadsEgressGuard(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	g := httpsafe.MustGuard("10.0.0.0/8")
	var got *httpsafe.Guard
	stub := func(ctx context.Context, c installer.InstallConfig, tool, version string) (*installer.Result, error) {
		got = c.EgressGuard
		return &installer.Result{BinaryPath: "/app/scanners/trivy", Version: "0.52.2"}, nil
	}

	h := NewScanningInstallHandler(cfg, stub, nil, nil, nil)
	h.SetEgressGuard(g)
	r := gin.New()
	r.POST("/install", h.Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin(map[string]string{"tool": "trivy"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if got != g {
		t.Errorf("InstallConfig.EgressGuard = %v, want the guard set via SetEgressGuard", got)
	}
}

func TestInstallScannerHandler_InstallerError(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	stub := func(ctx context.Context, c installer.InstallConfig, tool, version string) (*installer.Result, error) {
		return nil, installer.ErrChecksumMismatch
	}

	r := gin.New()
	r.POST("/install", NewScanningInstallHandler(cfg, stub, nil, nil, nil).Install())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/install", jsonBodyAdmin(map[string]string{"tool": "trivy"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp InstallScannerAdminResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false")
	}
}

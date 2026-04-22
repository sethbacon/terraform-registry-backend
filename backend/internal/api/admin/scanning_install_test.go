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
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

func jsonBodyAdmin(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func TestInstallScannerHandler_BadJSON(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	r := gin.New()
	r.POST("/install", InstallScannerHandler(cfg, nil))

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
	r.POST("/install", InstallScannerHandler(cfg, nil))

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
	r.POST("/install", InstallScannerHandler(cfg, nil))

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
	r.POST("/install", InstallScannerHandler(cfg, stub))

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

func TestInstallScannerHandler_InstallerError(t *testing.T) {
	cfg := &config.ScanningConfig{InstallDir: "/tmp/test"}
	stub := func(ctx context.Context, c installer.InstallConfig, tool, version string) (*installer.Result, error) {
		return nil, installer.ErrChecksumMismatch
	}

	r := gin.New()
	r.POST("/install", InstallScannerHandler(cfg, stub))

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

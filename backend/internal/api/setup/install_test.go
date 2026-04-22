package setup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
)

func TestInstallScanner_BadJSON(t *testing.T) {
	env := newTestEnv(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody("not json{"))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestInstallScanner_MissingTool(t *testing.T) {
	env := newTestEnv(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]interface{}{}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestInstallScanner_UnsupportedTool_Snyk(t *testing.T) {
	env := newTestEnv(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]string{"tool": "snyk"}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp InstallScannerResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false")
	}
	if resp.Error == "" {
		t.Error("expected error message")
	}
}

func TestInstallScanner_UnsupportedTool_Custom(t *testing.T) {
	env := newTestEnv(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]string{"tool": "custom"}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp InstallScannerResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false")
	}
}

func TestInstallScanner_EmptyInstallDir(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = ""
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]string{"tool": "trivy"}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestInstallScanner_InstallerError(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = "/tmp/test"
	env.h.installFunc = func(ctx context.Context, cfg installer.InstallConfig, tool, version string) (*installer.Result, error) {
		return nil, installer.ErrChecksumMismatch
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]string{"tool": "trivy"}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp InstallScannerResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("expected success=false")
	}
	if resp.Error == "" {
		t.Error("expected error message")
	}
}

func TestInstallScanner_Success_LatestVersion(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = "/tmp/test"
	env.h.installFunc = func(ctx context.Context, cfg installer.InstallConfig, tool, version string) (*installer.Result, error) {
		return &installer.Result{
			BinaryPath: "/app/scanners/trivy",
			Version:    "0.52.2",
			Sha256:     "abcd1234",
			SourceURL:  "https://github.com/aquasecurity/trivy/releases/download/v0.52.2/trivy_0.52.2_Linux-64bit.tar.gz",
		}, nil
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]string{"tool": "trivy"}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp InstallScannerResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Errorf("expected success=true, error=%s", resp.Error)
	}
	if resp.Tool != "trivy" {
		t.Errorf("tool = %q, want trivy", resp.Tool)
	}
	if resp.Version != "0.52.2" {
		t.Errorf("version = %q, want 0.52.2", resp.Version)
	}
	if resp.BinaryPath == "" {
		t.Error("binary_path empty")
	}
}

func TestInstallScanner_PinnedVersion_PassedThrough(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = "/tmp/test"

	var receivedVersion string
	env.h.installFunc = func(ctx context.Context, cfg installer.InstallConfig, tool, version string) (*installer.Result, error) {
		receivedVersion = version
		return &installer.Result{
			BinaryPath: "/app/scanners/trivy",
			Version:    "0.52.2",
			Sha256:     "abcd1234",
			SourceURL:  "https://example.com",
		}, nil
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", jsonBody(map[string]interface{}{
		"tool":    "trivy",
		"version": "0.52.2",
	}))
	c.Request.Header.Set("Content-Type", "application/json")

	env.h.InstallScanner(c)
	if receivedVersion != "0.52.2" {
		t.Errorf("version passed to installer = %q, want 0.52.2", receivedVersion)
	}
}

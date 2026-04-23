package setup

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// TestScanningConfig
// ---------------------------------------------------------------------------

func TestTestScanningConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning/test", env.h.TestScanningConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning/test", bytes.NewBufferString("{invalid")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestScanningConfig_MissingToolField(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning/test", env.h.TestScanningConfig)

	// tool is required but missing; binary_path is also required
	body := jsonBody(map[string]string{
		"binary_path": "/usr/bin/trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing tool", w.Code)
	}
}

func TestTestScanningConfig_MissingBinaryPath(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning/test", env.h.TestScanningConfig)

	// binary_path is required but missing
	body := jsonBody(map[string]string{
		"tool": "trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing binary_path", w.Code)
	}
}

func TestTestScanningConfig_UnsupportedTool(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning/test", env.h.TestScanningConfig)

	body := jsonBody(map[string]string{
		"tool":        "unsupported-tool",
		"binary_path": "/usr/bin/fake",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning/test", body))

	// Returns 200 with success=false for unsupported tool
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	resp := getJSON(w)
	if resp["success"] != false {
		t.Errorf("success = %v, want false", resp["success"])
	}
}

func TestTestScanningConfig_BinaryNotFound(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning/test", env.h.TestScanningConfig)

	body := jsonBody(map[string]string{
		"tool":        "trivy",
		"binary_path": "/nonexistent/path/to/trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning/test", body))

	// Returns 200 with success=false for binary not found
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	resp := getJSON(w)
	if resp["success"] != false {
		t.Errorf("success = %v, want false for missing binary", resp["success"])
	}
}

// ---------------------------------------------------------------------------
// SaveScanningConfig
// ---------------------------------------------------------------------------

func TestSaveScanningConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", bytes.NewBufferString("{not-json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveScanningConfig_MissingToolField(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	// tool is required but missing
	body := jsonBody(map[string]string{
		"binary_path": "/usr/bin/trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing tool", w.Code)
	}
}

func TestSaveScanningConfig_MissingBinaryPath(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	// binary_path is required but missing
	body := jsonBody(map[string]string{
		"tool": "trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing binary_path", w.Code)
	}
}

func TestSaveScanningConfig_Success(t *testing.T) {
	env := newTestEnv(t)

	// Create a real temp file to pass the os.Stat existence check.
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":      true,
		"tool":         "trivy",
		"binary_path":  binaryPath,
		"timeout_secs": 60,
	})

	// SetScanningConfig
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["message"] != "Scanning configuration saved" {
		t.Errorf("message = %v", resp["message"])
	}
}

func TestSaveScanningConfig_DBError(t *testing.T) {
	env := newTestEnv(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": binaryPath,
	})

	// SetScanningConfig fails
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SaveScanningConfig — binary_path validation
// ---------------------------------------------------------------------------

func TestSaveScanningConfig_BinaryPathOutsideInstallDir(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = "/app/scanners"

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": "/usr/bin/trivy", // outside /app/scanners
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for binary_path outside install_dir", w.Code)
	}
	resp := getJSON(w)
	if resp["error"] != "binary_path must be within the scanner install directory" {
		t.Errorf("error = %v", resp["error"])
	}
}

func TestSaveScanningConfig_BinaryPathTraversalBlocked(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning.InstallDir = "/app/scanners"

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": "/app/scanners/../../../etc/passwd",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for path traversal attempt", w.Code)
	}
}

func TestSaveScanningConfig_BinaryNotExistOnDisk(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": "/nonexistent/path/to/trivy",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for non-existent binary", w.Code)
	}
	resp := getJSON(w)
	if resp["error"] != "binary_path does not exist" {
		t.Errorf("error = %v", resp["error"])
	}
}

func TestSaveScanningConfig_UpdatesInMemoryConfig(t *testing.T) {
	env := newTestEnv(t)
	// Start with scanning disabled in-memory.
	env.h.cfg.Scanning = config.ScanningConfig{
		Enabled:    false,
		Tool:       "",
		BinaryPath: "",
	}

	// Create a real temp file to pass the os.Stat check.
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":          true,
		"tool":             "trivy",
		"binary_path":      binaryPath,
		"expected_version": "0.50.0",
		"timeout_secs":     120,
		"worker_count":     4,
	})

	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	// Verify in-memory config was updated.
	sc := env.h.cfg.Scanning
	if !sc.Enabled {
		t.Error("cfg.Scanning.Enabled = false, want true")
	}
	if sc.Tool != "trivy" {
		t.Errorf("cfg.Scanning.Tool = %q, want trivy", sc.Tool)
	}
	if sc.BinaryPath != binaryPath {
		t.Errorf("cfg.Scanning.BinaryPath = %q, want %q", sc.BinaryPath, binaryPath)
	}
	if sc.ExpectedVersion != "0.50.0" {
		t.Errorf("cfg.Scanning.ExpectedVersion = %q, want 0.50.0", sc.ExpectedVersion)
	}
	if sc.Timeout != 120*time.Second {
		t.Errorf("cfg.Scanning.Timeout = %v, want 120s", sc.Timeout)
	}
	if sc.WorkerCount != 4 {
		t.Errorf("cfg.Scanning.WorkerCount = %d, want 4", sc.WorkerCount)
	}
}

func TestSaveScanningConfig_InMemoryNotUpdatedOnDBError(t *testing.T) {
	env := newTestEnv(t)
	env.h.cfg.Scanning = config.ScanningConfig{Enabled: false}

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": binaryPath,
	})

	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}

	// In-memory config must not have changed on DB failure.
	if env.h.cfg.Scanning.Enabled {
		t.Error("cfg.Scanning.Enabled updated on DB error, want unchanged (false)")
	}
}

func TestSaveScanningConfig_NoInstallDirSkipsPathValidation(t *testing.T) {
	env := newTestEnv(t)
	// InstallDir is empty — path validation is skipped; only existence is checked.
	env.h.cfg.Scanning.InstallDir = ""

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": binaryPath,
	})

	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scanning", body))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when install_dir is empty", w.Code)
	}
}

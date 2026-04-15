package setup

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
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

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":      true,
		"tool":         "trivy",
		"binary_path":  "/usr/bin/trivy",
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

	r := gin.New()
	r.POST("/scanning", env.h.SaveScanningConfig)

	body := jsonBody(map[string]interface{}{
		"enabled":     true,
		"tool":        "trivy",
		"binary_path": "/usr/bin/trivy",
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

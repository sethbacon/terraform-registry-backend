package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// minimal storage.Storage mock for readiness tests
// ---------------------------------------------------------------------------

type readinessMockStorage struct{ existsErr error }

func (m *readinessMockStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return nil, nil
}
func (m *readinessMockStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *readinessMockStorage) Delete(_ context.Context, _ string) error { return nil }
func (m *readinessMockStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (m *readinessMockStorage) Exists(_ context.Context, _ string) (bool, error) {
	return m.existsErr == nil, m.existsErr
}
func (m *readinessMockStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// healthCheckHandler
// ---------------------------------------------------------------------------

func newHealthDB(t *testing.T, pingOK bool) *sql.DB {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if pingOK {
		mock.ExpectPing()
	} else {
		mock.ExpectPing().WillReturnError(sql.ErrConnDone)
	}
	return db
}

func TestHealthCheckHandler_Healthy(t *testing.T) {
	db := newHealthDB(t, true)

	r := gin.New()
	r.GET("/health", healthCheckHandler(db))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
}

func TestHealthCheckHandler_Unhealthy(t *testing.T) {
	db := newHealthDB(t, false)

	r := gin.New()
	r.GET("/health", healthCheckHandler(db))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

// ---------------------------------------------------------------------------
// readinessHandler
// ---------------------------------------------------------------------------

func TestReadinessHandler_Ready(t *testing.T) {
	db := newHealthDB(t, true)

	r := gin.New()
	r.GET("/ready", readinessHandler(db, &readinessMockStorage{}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["ready"] != true {
		t.Errorf("ready = %v, want true", body["ready"])
	}
}

func TestReadinessHandler_NotReady(t *testing.T) {
	db := newHealthDB(t, false)

	r := gin.New()
	r.GET("/ready", readinessHandler(db, &readinessMockStorage{}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["ready"] != false {
		t.Errorf("ready = %v, want false", body["ready"])
	}
}

// ---------------------------------------------------------------------------
// serviceDiscoveryHandler
// ---------------------------------------------------------------------------

func TestServiceDiscoveryHandler(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.BaseURL = "https://registry.example.com"

	r := gin.New()
	r.GET("/.well-known/terraform.json", serviceDiscoveryHandler(cfg))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/terraform.json", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["modules.v1"] != "https://registry.example.com/v1/modules/" {
		t.Errorf("modules.v1 = %v, want correct URL", body["modules.v1"])
	}
	if body["providers.v1"] != "https://registry.example.com/v1/providers/" {
		t.Errorf("providers.v1 = %v, want correct URL", body["providers.v1"])
	}
}

// ---------------------------------------------------------------------------
// versionHandler
// ---------------------------------------------------------------------------

func TestVersionHandler(t *testing.T) {
	r := gin.New()
	r.GET("/version", versionHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/version", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["version"] == nil {
		t.Error("response missing 'version'")
	}
	if body["api_version"] == nil {
		t.Error("response missing 'api_version'")
	}
}

// ---------------------------------------------------------------------------
// LoggerMiddleware
// ---------------------------------------------------------------------------

func TestLoggerMiddleware_JSONFormat(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.Format = "json"

	r := gin.New()
	r.Use(LoggerMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestLoggerMiddleware_TextFormat(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.Format = "text"

	r := gin.New()
	r.Use(LoggerMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CORSMiddleware
// ---------------------------------------------------------------------------

func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://example.com"}

	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://example.com",
			w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_Wildcard(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"*"}

	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anything.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://allowed.com"}

	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)

	// Request passes through but no CORS header set
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header for disallowed origin")
	}
}

func TestCORSMiddleware_PreflightOptions(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"*"}

	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.OPTIONS("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	// OPTIONS should be aborted with 204
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 for OPTIONS preflight", w.Code)
	}
}

func TestCORSMiddleware_WildcardNoOriginHeader(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"*"}

	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Origin header set → origin is empty, wildcard allows it → Access-Control-Allow-Origin: *
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

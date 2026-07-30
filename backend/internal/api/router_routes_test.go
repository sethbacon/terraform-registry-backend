package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// Issue #684: /swagger.json and /openapi3.json hardcoded
// Access-Control-Allow-Origin: * regardless of the configured CORS policy,
// bypassing CORSMiddleware (which is applied globally ahead of these routes
// in NewRouter). A disallowed Origin must not get a wildcard CORS header.

func newPublicRoutesRouter(t *testing.T, cfg *config.Config) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	registerPublicRoutes(r, &publicRouteDeps{cfg: cfg})
	return r
}

func TestSwaggerJSON_RespectsCORSPolicy_DisallowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://allowed.com"}
	r := newPublicRoutesRouter(t, cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger.json", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if aco := w.Header().Get("Access-Control-Allow-Origin"); aco != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for disallowed origin", aco)
	}
}

func TestSwaggerJSON_RespectsCORSPolicy_AllowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://allowed.com"}
	r := newPublicRoutesRouter(t, cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/swagger.json", nil)
	req.Header.Set("Origin", "https://allowed.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if aco := w.Header().Get("Access-Control-Allow-Origin"); aco != "https://allowed.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://allowed.com", aco)
	}
}

func TestOpenAPI3JSON_RespectsCORSPolicy_DisallowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://allowed.com"}
	r := newPublicRoutesRouter(t, cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi3.json", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if aco := w.Header().Get("Access-Control-Allow-Origin"); aco != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for disallowed origin", aco)
	}
}

func TestOpenAPI3JSON_RespectsCORSPolicy_AllowedOrigin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"https://allowed.com"}
	r := newPublicRoutesRouter(t, cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi3.json", nil)
	req.Header.Set("Origin", "https://allowed.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if aco := w.Header().Get("Access-Control-Allow-Origin"); aco != "https://allowed.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://allowed.com", aco)
	}
}

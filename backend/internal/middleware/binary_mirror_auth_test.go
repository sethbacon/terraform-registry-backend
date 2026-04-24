package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func newBinaryMirrorRouter(cfg config.BinaryMirrorConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BinaryMirrorAuthMiddleware(cfg))
	r.GET("/terraform/binaries", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestBinaryMirrorAuth_None(t *testing.T) {
	r := newBinaryMirrorRouter(config.BinaryMirrorConfig{Auth: "none"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_Default(t *testing.T) {
	// Unrecognised auth value should pass through.
	r := newBinaryMirrorRouter(config.BinaryMirrorConfig{Auth: "unknown"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown auth mode, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_Allowlist_Allowed(t *testing.T) {
	cfg := config.BinaryMirrorConfig{
		Auth:      "allowlist",
		Allowlist: []string{"192.168.1.0/24", "10.0.0.0/8"},
	}
	r := newBinaryMirrorRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed IP, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_Allowlist_Denied(t *testing.T) {
	cfg := config.BinaryMirrorConfig{
		Auth:      "allowlist",
		Allowlist: []string{"192.168.1.0/24"},
	}
	r := newBinaryMirrorRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for denied IP, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_Allowlist_EmptyList(t *testing.T) {
	cfg := config.BinaryMirrorConfig{
		Auth:      "allowlist",
		Allowlist: []string{},
	}
	r := newBinaryMirrorRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for empty allowlist, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_MTLS_NoTLS(t *testing.T) {
	r := newBinaryMirrorRouter(config.BinaryMirrorConfig{Auth: "mtls"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	// req.TLS is nil — no TLS connection.
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for no TLS, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_MTLS_NoClientCert(t *testing.T) {
	r := newBinaryMirrorRouter(config.BinaryMirrorConfig{Auth: "mtls"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	// TLS present but no verified chains.
	req.TLS = &tls.ConnectionState{VerifiedChains: nil}
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for TLS without client cert, got %d", w.Code)
	}
}

func TestBinaryMirrorAuth_MTLS_WithClientCert(t *testing.T) {
	r := newBinaryMirrorRouter(config.BinaryMirrorConfig{Auth: "mtls"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/terraform/binaries", nil)
	// Simulate a verified client certificate chain.
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{}}},
	}
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid client cert, got %d", w.Code)
	}
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// applySecurityHeaders runs a GET / through SecurityHeadersMiddleware and returns
// the response recorder so callers can inspect headers.
func applySecurityHeaders(cfg SecurityHeadersConfig) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(cfg))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// DefaultSecurityHeadersConfig
// ---------------------------------------------------------------------------

func TestDefaultSecurityHeadersConfig(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	if !cfg.EnableHSTS {
		t.Error("DefaultSecurityHeadersConfig().EnableHSTS = false, want true")
	}
	if cfg.HSTSMaxAge != 31536000 {
		t.Errorf("HSTSMaxAge = %d, want 31536000", cfg.HSTSMaxAge)
	}
	if !cfg.HSTSIncludeSubdomains {
		t.Error("HSTSIncludeSubdomains = false, want true")
	}
	if cfg.HSTSPreload {
		t.Error("HSTSPreload = true, want false")
	}
	if !cfg.EnableFrameOptions {
		t.Error("EnableFrameOptions = false, want true")
	}
	if cfg.FrameOptionsValue != "DENY" {
		t.Errorf("FrameOptionsValue = %q, want DENY", cfg.FrameOptionsValue)
	}
	if !cfg.EnableContentTypeOptions {
		t.Error("EnableContentTypeOptions = false, want true")
	}
	if !cfg.EnableXSSProtection {
		t.Error("EnableXSSProtection = false, want true")
	}
	if cfg.ContentSecurityPolicy == "" {
		t.Error("ContentSecurityPolicy is empty, want non-empty")
	}
	if cfg.ReferrerPolicy == "" {
		t.Error("ReferrerPolicy is empty, want non-empty")
	}
	if cfg.PermissionsPolicy == "" {
		t.Error("PermissionsPolicy is empty, want non-empty")
	}
}

// ---------------------------------------------------------------------------
// APISecurityHeadersConfig
// ---------------------------------------------------------------------------

func TestAPISecurityHeadersConfig(t *testing.T) {
	cfg := APISecurityHeadersConfig()

	if !cfg.EnableHSTS {
		t.Error("APISecurityHeadersConfig().EnableHSTS = false, want true")
	}
	if cfg.EnableXSSProtection {
		t.Error("EnableXSSProtection = true, want false (not relevant for JSON APIs)")
	}
	if cfg.ContentSecurityPolicy == "" {
		t.Error("ContentSecurityPolicy is empty, want non-empty")
	}
	if cfg.ReferrerPolicy != "no-referrer" {
		t.Errorf("ReferrerPolicy = %q, want no-referrer", cfg.ReferrerPolicy)
	}
	if cfg.PermissionsPolicy != "" {
		t.Errorf("PermissionsPolicy = %q, want empty", cfg.PermissionsPolicy)
	}
}

// ---------------------------------------------------------------------------
// SecurityHeadersMiddleware
// ---------------------------------------------------------------------------

func TestSecurityHeadersMiddleware_HSTS(t *testing.T) {
	t.Run("hsts with subdomains and no preload", func(t *testing.T) {
		cfg := SecurityHeadersConfig{
			EnableHSTS:            true,
			HSTSMaxAge:            31536000,
			HSTSIncludeSubdomains: true,
			HSTSPreload:           false,
		}
		w := applySecurityHeaders(cfg)
		hsts := w.Header().Get("Strict-Transport-Security")
		if !strings.Contains(hsts, "max-age=31536000") {
			t.Errorf("HSTS = %q, want to contain max-age=31536000", hsts)
		}
		if !strings.Contains(hsts, "includeSubDomains") {
			t.Errorf("HSTS = %q, want to contain includeSubDomains", hsts)
		}
		if strings.Contains(hsts, "preload") {
			t.Errorf("HSTS = %q, should not contain preload", hsts)
		}
	})

	t.Run("hsts with preload", func(t *testing.T) {
		cfg := SecurityHeadersConfig{
			EnableHSTS:  true,
			HSTSMaxAge:  86400,
			HSTSPreload: true,
		}
		w := applySecurityHeaders(cfg)
		hsts := w.Header().Get("Strict-Transport-Security")
		if !strings.Contains(hsts, "preload") {
			t.Errorf("HSTS = %q, want to contain preload", hsts)
		}
	})

	t.Run("hsts disabled", func(t *testing.T) {
		cfg := SecurityHeadersConfig{EnableHSTS: false}
		w := applySecurityHeaders(cfg)
		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS should be absent when disabled, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_FrameOptions(t *testing.T) {
	t.Run("frame options set to DENY", func(t *testing.T) {
		cfg := SecurityHeadersConfig{EnableFrameOptions: true, FrameOptionsValue: "DENY"}
		w := applySecurityHeaders(cfg)
		if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
	})

	t.Run("frame options set to SAMEORIGIN", func(t *testing.T) {
		cfg := SecurityHeadersConfig{EnableFrameOptions: true, FrameOptionsValue: "SAMEORIGIN"}
		w := applySecurityHeaders(cfg)
		if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", got)
		}
	})

	t.Run("frame options disabled", func(t *testing.T) {
		cfg := SecurityHeadersConfig{EnableFrameOptions: false, FrameOptionsValue: "DENY"}
		w := applySecurityHeaders(cfg)
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("X-Frame-Options should be absent when disabled, got %q", got)
		}
	})

	t.Run("frame options enabled but empty value", func(t *testing.T) {
		cfg := SecurityHeadersConfig{EnableFrameOptions: true, FrameOptionsValue: ""}
		w := applySecurityHeaders(cfg)
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("X-Frame-Options should be absent for empty value, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_ContentTypeOptions(t *testing.T) {
	t.Run("content type options enabled", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{EnableContentTypeOptions: true})
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
	})

	t.Run("content type options disabled", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{EnableContentTypeOptions: false})
		if got := w.Header().Get("X-Content-Type-Options"); got != "" {
			t.Errorf("X-Content-Type-Options should be absent when disabled, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_XSSProtection(t *testing.T) {
	t.Run("xss protection enabled", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{EnableXSSProtection: true})
		if got := w.Header().Get("X-XSS-Protection"); got != "1; mode=block" {
			t.Errorf("X-XSS-Protection = %q, want '1; mode=block'", got)
		}
	})

	t.Run("xss protection disabled", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{EnableXSSProtection: false})
		if got := w.Header().Get("X-XSS-Protection"); got != "" {
			t.Errorf("X-XSS-Protection should be absent when disabled, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_CSP(t *testing.T) {
	t.Run("csp set when non-empty", func(t *testing.T) {
		policy := "default-src 'self'"
		w := applySecurityHeaders(SecurityHeadersConfig{ContentSecurityPolicy: policy})
		if got := w.Header().Get("Content-Security-Policy"); got != policy {
			t.Errorf("Content-Security-Policy = %q, want %q", got, policy)
		}
	})

	t.Run("csp not set when empty", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{ContentSecurityPolicy: ""})
		if got := w.Header().Get("Content-Security-Policy"); got != "" {
			t.Errorf("Content-Security-Policy should be absent when empty, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_ReferrerPolicy(t *testing.T) {
	t.Run("referrer policy set when non-empty", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{ReferrerPolicy: "no-referrer"})
		if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("Referrer-Policy = %q, want no-referrer", got)
		}
	})

	t.Run("referrer policy absent when empty", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{ReferrerPolicy: ""})
		if got := w.Header().Get("Referrer-Policy"); got != "" {
			t.Errorf("Referrer-Policy should be absent when empty, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_PermissionsPolicy(t *testing.T) {
	t.Run("permissions policy set when non-empty", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{PermissionsPolicy: "geolocation=()"})
		if got := w.Header().Get("Permissions-Policy"); got != "geolocation=()" {
			t.Errorf("Permissions-Policy = %q, want geolocation=()", got)
		}
	})

	t.Run("permissions policy absent when empty", func(t *testing.T) {
		w := applySecurityHeaders(SecurityHeadersConfig{PermissionsPolicy: ""})
		if got := w.Header().Get("Permissions-Policy"); got != "" {
			t.Errorf("Permissions-Policy should be absent when empty, got %q", got)
		}
	})
}

func TestSecurityHeadersMiddleware_FixedHeaders(t *testing.T) {
	// These headers are always set regardless of config.
	w := applySecurityHeaders(SecurityHeadersConfig{})
	tests := []struct{ header, want string }{
		{"X-Permitted-Cross-Domain-Policies", "none"},
		{"Cross-Origin-Embedder-Policy", "require-corp"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Cross-Origin-Resource-Policy", "same-origin"},
	}
	for _, tt := range tests {
		if got := w.Header().Get(tt.header); got != tt.want {
			t.Errorf("%s = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestSecurityHeadersMiddleware_DefaultConfig(t *testing.T) {
	w := applySecurityHeaders(DefaultSecurityHeadersConfig())
	if w.Code != http.StatusOK {
		t.Errorf("response code = %d, want 200", w.Code)
	}
	// Spot-check a few headers are set
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("Strict-Transport-Security should be set with default config")
	}
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("X-Frame-Options should be set with default config")
	}
}

// ---------------------------------------------------------------------------
// itoa (unexported helper)
// ---------------------------------------------------------------------------

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{123, "123"},
		{31536000, "31536000"},
		{-1, "-1"},
		{-100, "-100"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

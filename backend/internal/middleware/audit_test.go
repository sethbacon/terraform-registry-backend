package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/audit"
)

// captureShipper collects audit log entries via a buffered channel.
type captureShipper struct {
	ch chan *audit.LogEntry
}

func newCaptureShipper(buf int) *captureShipper {
	return &captureShipper{ch: make(chan *audit.LogEntry, buf)}
}

func (s *captureShipper) Ship(_ context.Context, e *audit.LogEntry) error {
	s.ch <- e
	return nil
}

func (s *captureShipper) Close() error { return nil }

// waitForEntry blocks until an entry arrives or the timeout fires.
func (s *captureShipper) waitForEntry(t *testing.T, timeout time.Duration) *audit.LogEntry {
	t.Helper()
	select {
	case e := <-s.ch:
		return e
	case <-time.After(timeout):
		t.Fatal("timed out waiting for audit log entry")
		return nil
	}
}

// ---------------------------------------------------------------------------
// contains helper
// ---------------------------------------------------------------------------

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "lo wo", true},
		{"hello world", "xyz", false},
		{"hello", "hello", true},
		{"", "", true},
		{"abc", "", true},
		{"", "x", false},
	}
	for _, tt := range tests {
		got := contains(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// indexOf helper
// ---------------------------------------------------------------------------

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s, substr string
		want      int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "xyz", -1},
		{"abcabc", "abc", 0},
		{"abc", "abcd", -1},
	}
	for _, tt := range tests {
		got := indexOf(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// AuditMiddlewareWithShipper — early-exit / skip paths
// ---------------------------------------------------------------------------

func TestAuditMiddleware_OptionsSkipped(t *testing.T) {
	cs := newCaptureShipper(1)
	r := gin.New()
	r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
	r.OPTIONS("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	r.ServeHTTP(w, req)

	select {
	case <-cs.ch:
		t.Error("shipper called for OPTIONS request, want no shipping")
	case <-time.After(100 * time.Millisecond):
		// good — nothing shipped
	}
}

func TestAuditMiddleware_GetSkippedWithNilConfig(t *testing.T) {
	cs := newCaptureShipper(1)
	r := gin.New()
	r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	select {
	case <-cs.ch:
		t.Error("shipper called for GET with nil config, want no shipping")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAuditMiddleware_FailedPostSkippedWithNilConfig(t *testing.T) {
	cs := newCaptureShipper(1)
	r := gin.New()
	r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
	r.POST("/", func(c *gin.Context) { c.Status(http.StatusBadRequest) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.ServeHTTP(w, req)

	select {
	case <-cs.ch:
		t.Error("shipper called for failed POST with nil config, want no shipping")
	case <-time.After(100 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// AuditMiddlewareWithShipper — shipping path
// ---------------------------------------------------------------------------

func TestAuditMiddleware_SuccessfulWriteShipped(t *testing.T) {
	cs := newCaptureShipper(1)
	r := gin.New()
	r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
	r.POST("/modules/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/modules/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)

	entry := cs.waitForEntry(t, 500*time.Millisecond)
	if entry.ResourceType != "module" {
		t.Errorf("ResourceType = %q, want module", entry.ResourceType)
	}
	if entry.Action == "" {
		t.Error("Action is empty, want non-empty")
	}
}

func TestAuditMiddleware_NilShipperAndRepo_NoPanic(t *testing.T) {
	r := gin.New()
	r.Use(AuditMiddlewareWithShipper(nil, nil, nil))
	r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.ServeHTTP(w, req)

	time.Sleep(50 * time.Millisecond) // let goroutine complete
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestAuditMiddleware_ResourceTypeDetection(t *testing.T) {
	paths := []struct {
		path    string
		wantRes string
	}{
		{"/modules/foo", "module"},
		{"/providers/bar", "provider"},
		{"/users/baz", "user"},
		{"/apikeys/1", "api_key"},
		{"/organizations/x", "organization"},
		{"/mirrors/y", "mirror"},
		{"/other/z", ""},
	}

	for _, tt := range paths {
		t.Run(tt.path, func(t *testing.T) {
			cs := newCaptureShipper(1)
			r := gin.New()
			r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
			r.POST(tt.path, func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, tt.path, nil)
			r.ServeHTTP(w, req)

			entry := cs.waitForEntry(t, 500*time.Millisecond)
			if entry.ResourceType != tt.wantRes {
				t.Errorf("path %q: ResourceType = %q, want %q", tt.path, entry.ResourceType, tt.wantRes)
			}
		})
	}
}

func TestAuditMiddleware_ContextValuesExtracted(t *testing.T) {
	cs := newCaptureShipper(1)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-42")
		c.Set("organization_id", "org-99")
		c.Set("auth_method", "api_key")
		c.Next()
	})
	r.Use(AuditMiddlewareWithShipper(nil, cs, nil))
	r.POST("/providers/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/providers/test", nil)
	r.ServeHTTP(w, req)

	entry := cs.waitForEntry(t, 500*time.Millisecond)
	if entry.UserID != "user-42" {
		t.Errorf("UserID = %q, want user-42", entry.UserID)
	}
	if entry.OrganizationID != "org-99" {
		t.Errorf("OrganizationID = %q, want org-99", entry.OrganizationID)
	}
	if entry.AuthMethod != "api_key" {
		t.Errorf("AuthMethod = %q, want api_key", entry.AuthMethod)
	}
}

func TestAuditMiddleware_BackwardCompat(t *testing.T) {
	// AuditMiddleware(nil) should not panic
	r := gin.New()
	r.Use(AuditMiddleware(nil))
	r.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.ServeHTTP(w, req)

	time.Sleep(50 * time.Millisecond)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

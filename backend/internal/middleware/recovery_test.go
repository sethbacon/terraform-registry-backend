package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRecoveryMiddleware_RedactsCookieOnPanic is the negative (attack-path)
// test for issue #663: a panic during request handling must not write the raw
// Cookie header (a live session/JWT token) to the log.
func TestRecoveryMiddleware_RedactsCookieOnPanic(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/", func(c *gin.Context) { panic("boom") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "tfr_session=super-secret-session-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	logged := buf.String()
	if strings.Contains(logged, "super-secret-session-token") {
		t.Errorf("panic-recovery log leaked the raw Cookie value: %q", logged)
	}
	if !strings.Contains(logged, "Cookie: [REDACTED]") {
		t.Errorf("panic-recovery log did not contain a redacted Cookie header: %q", logged)
	}
}

// TestRecoveryMiddleware_NormalRequestUnaffected is the positive (legit-path)
// counterpart: a request that does not panic behaves exactly as before.
func TestRecoveryMiddleware_NormalRequestUnaffected(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "tfr_session=some-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestRedactedRequestDump_MasksSensitiveHeadersOnly confirms only the
// documented sensitive headers are masked and unrelated headers pass through.
func TestRedactedRequestDump_MasksSensitiveHeadersOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
	req.Header.Set("Cookie", "tfr_session=abc123")
	req.Header.Set("Authorization", "Bearer some-jwt")
	req.Header.Set("X-Request-ID", "req-42")

	dump := redactedRequestDump(req)

	if strings.Contains(dump, "abc123") {
		t.Errorf("dump leaked raw Cookie value: %q", dump)
	}
	if strings.Contains(dump, "some-jwt") {
		t.Errorf("dump leaked raw Authorization value: %q", dump)
	}
	if !strings.Contains(dump, "X-Request-Id: req-42") {
		t.Errorf("dump unexpectedly redacted an unrelated header: %q", dump)
	}
}

// TestRedactedRequestDump_RedactsRequestLineQuery is the negative
// (attack-path) test for the request-line leak: httputil.DumpRequest
// reconstructs "METHOD /path?query HTTP/1.1" from r.URL, so an OAuth
// code/state value in the query string must not reach the panic log
// verbatim.
func TestRedactedRequestDump_RedactsRequestLineQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=super-secret-code&state=xyz", nil)

	dump := redactedRequestDump(req)

	if strings.Contains(dump, "super-secret-code") {
		t.Errorf("dump leaked the raw OAuth code from the request line: %q", dump)
	}
	if !strings.Contains(dump, "GET /api/v1/auth/callback?code=%5BREDACTED%5D&state=%5BREDACTED%5D HTTP/1.1") {
		t.Errorf("dump did not contain the expected redacted request line: %q", dump)
	}
}

// TestRedactedRequestDump_RedactsRequestLinePath is the negative
// (attack-path) test for the webhook-secret-in-path case: a panic during
// handling of a webhook URL must not write the raw secret/token path
// segment to the panic log.
func TestRedactedRequestDump_RedactsRequestLinePath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/webhooks/scm/repo-123/s3cr3t-value", nil)

	dump := redactedRequestDump(req)

	if strings.Contains(dump, "s3cr3t-value") {
		t.Errorf("dump leaked the raw webhook secret from the request line: %q", dump)
	}
	if !strings.Contains(dump, "POST /webhooks/scm/repo-123/[REDACTED] HTTP/1.1") {
		t.Errorf("dump did not contain the expected redacted request line: %q", dump)
	}
}

// TestRecoveryMiddleware_RedactsQueryOnPanic is the end-to-end counterpart:
// a panic while handling a request whose query string carries a live OAuth
// credential must not leak it via RecoveryMiddleware's log output.
func TestRecoveryMiddleware_RedactsQueryOnPanic(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/api/v1/auth/callback", func(c *gin.Context) { panic("boom") })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=super-secret-code&state=xyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	logged := buf.String()
	if strings.Contains(logged, "super-secret-code") {
		t.Errorf("panic-recovery log leaked the raw OAuth code from the request line: %q", logged)
	}
}

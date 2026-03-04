package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// newRequestIDRouter builds a minimal Gin engine with RequestIDMiddleware and a handler
// that echoes the request_id value stored in the context back as a response header.
func newRequestIDRouter() *gin.Engine {
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/", func(c *gin.Context) {
		id, _ := c.Get(RequestIDKey)
		c.Header("X-Context-Request-ID", id.(string))
		c.Status(http.StatusOK)
	})
	return r
}

// ---------------------------------------------------------------------------
// RequestIDMiddleware tests
// ---------------------------------------------------------------------------

func TestRequestIDMiddleware_GeneratesIDWhenAbsent(t *testing.T) {
	r := newRequestIDRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	id := w.Header().Get(RequestIDHeader)
	if id == "" {
		t.Error("expected X-Request-ID response header to be set, got empty string")
	}
}

func TestRequestIDMiddleware_GeneratesUUIDFormat(t *testing.T) {
	r := newRequestIDRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	id := w.Header().Get(RequestIDHeader)
	// UUID v4 has 36 characters: xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx
	if len(id) != 36 {
		t.Errorf("expected UUID-format request ID (length 36), got %q (length %d)", id, len(id))
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Errorf("expected UUID with dashes at positions 8, 13, 18, 23; got %q", id)
	}
}

func TestRequestIDMiddleware_PropagatesIncomingID(t *testing.T) {
	const upstreamID = "upstream-provided-request-id-001"

	r := newRequestIDRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, upstreamID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	got := w.Header().Get(RequestIDHeader)
	if got != upstreamID {
		t.Errorf("expected response X-Request-ID %q, got %q", upstreamID, got)
	}
}

func TestRequestIDMiddleware_StoresIDInContext(t *testing.T) {
	r := newRequestIDRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	responseID := w.Header().Get(RequestIDHeader)
	contextID := w.Header().Get("X-Context-Request-ID") // echoed by handler

	if contextID == "" {
		t.Error("request ID was not stored in gin.Context under RequestIDKey")
	}
	if responseID != contextID {
		t.Errorf("response header ID %q does not match context ID %q", responseID, contextID)
	}
}

func TestRequestIDMiddleware_DifferentIDsPerRequest(t *testing.T) {
	r := newRequestIDRouter()

	ids := make(map[string]struct{}, 10)
	for i := range 10 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		id := w.Header().Get(RequestIDHeader)
		if _, seen := ids[id]; seen {
			t.Errorf("duplicate request ID %q on iteration %d", id, i)
		}
		ids[id] = struct{}{}
	}
}

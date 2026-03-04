package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// newScopeRouter builds a gin engine where:
//  1. A setup handler sets c["scopes"] to userScopes (if non-nil)
//  2. The provided middleware runs
//  3. A final handler returns 200 {"ok":true} if not aborted
func newScopeRouter(mid gin.HandlerFunc, userScopes interface{}) *gin.Engine {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		if userScopes != nil {
			c.Set("scopes", userScopes)
		}
	}, mid, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func do(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	return w
}

func isAbortedWith403(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusForbidden
}

func isOK(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusOK
}

// ---------------------------------------------------------------------------
// RequireScope
// ---------------------------------------------------------------------------

func TestRequireScope(t *testing.T) {
	t.Run("no scopes in context returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireScope("admin:read"), nil))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("wrong type in context returns 403", func(t *testing.T) {
		// Put a non-[]string value so the type assertion fails
		w := do(newScopeRouter(RequireScope("admin:read"), "not-a-slice"))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("missing scope returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireScope("admin:write"), []string{"providers:read"}))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("exact scope match allows request", func(t *testing.T) {
		w := do(newScopeRouter(RequireScope("admin:read"), []string{"admin:read"}))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("multiple scopes includes required scope", func(t *testing.T) {
		scopes := []string{"providers:read", "admin:read", "modules:write"}
		w := do(newScopeRouter(RequireScope("admin:read"), scopes))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("403 body contains error field", func(t *testing.T) {
		w := do(newScopeRouter(RequireScope("admin:read"), []string{}))
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body parse error: %v", err)
		}
		if _, ok := body["error"]; !ok {
			t.Error("403 response body should have 'error' field")
		}
	})
}

// ---------------------------------------------------------------------------
// RequireAnyScope
// ---------------------------------------------------------------------------

func TestRequireAnyScope(t *testing.T) {
	t.Run("no scopes in context returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope("admin:read", "admin:write"), nil))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("wrong type in context returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope("admin:read"), 42))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("no matching scope returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope("admin:read", "admin:write"), []string{"providers:read"}))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("first scope matches allows request", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope("admin:read", "admin:write"), []string{"admin:read"}))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("second scope matches allows request", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope("admin:read", "admin:write"), []string{"admin:write"}))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("single required scope present allows request", func(t *testing.T) {
		w := do(newScopeRouter(RequireAnyScope(auth.Scope("providers:write")), []string{"providers:write"}))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// RequireAllScopes
// ---------------------------------------------------------------------------

func TestRequireAllScopes(t *testing.T) {
	t.Run("no scopes in context returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAllScopes("admin:read", "admin:write"), nil))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("wrong type in context returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAllScopes("admin:read"), true))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("missing one of two scopes returns 403", func(t *testing.T) {
		w := do(newScopeRouter(RequireAllScopes("admin:read", "admin:write"), []string{"admin:read"}))
		if !isAbortedWith403(w) {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("all scopes present allows request", func(t *testing.T) {
		scopes := []string{"admin:read", "admin:write"}
		w := do(newScopeRouter(RequireAllScopes("admin:read", "admin:write"), scopes))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("superset of required scopes allows request", func(t *testing.T) {
		scopes := []string{"admin:read", "admin:write", "providers:read"}
		w := do(newScopeRouter(RequireAllScopes("admin:read", "admin:write"), scopes))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("empty required scopes list allows request", func(t *testing.T) {
		w := do(newScopeRouter(RequireAllScopes(), []string{}))
		if !isOK(w) {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
}

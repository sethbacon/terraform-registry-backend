package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// csrfRouter builds a test router with CSRFMiddleware. It pre-sets the given
// auth_method in context (simulating what AuthMiddleware would do) so that
// CSRF enforcement can branch correctly.
func csrfRouter(authMethod string) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if authMethod != "" {
			c.Set("auth_method", authMethod)
		}
		c.Next()
	})
	r.Use(CSRFMiddleware())
	r.GET("/safe", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/mutate", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.PUT("/mutate", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.DELETE("/mutate", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestCSRF_SafeMethodsExempt(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	req := httptest.NewRequest("GET", "/safe", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET should be exempt from CSRF; got %d", w.Code)
	}
}

func TestCSRF_APIKeyExempt(t *testing.T) {
	r := csrfRouter("api_key")

	req := httptest.NewRequest("POST", "/mutate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("API-key-authenticated POST should be exempt from CSRF; got %d", w.Code)
	}
}

func TestCSRF_BearerJWTExempt(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT-authenticated POST should be exempt from CSRF; got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_MissingCookie(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	req := httptest.NewRequest("POST", "/mutate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("cookie-auth POST without CSRF cookie should be 403; got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_MissingHeader(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "some-token"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("cookie-auth POST without CSRF header should be 403; got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_Mismatch(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "token-a"})
	req.Header.Set(CSRFHeaderName, "token-b")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("cookie-auth POST with mismatched CSRF token should be 403; got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_ValidToken(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	token := "matching-csrf-token"
	req := httptest.NewRequest("POST", "/mutate", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cookie-auth POST with valid CSRF token should be 200; got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_PUTAndDELETE(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	token := "matching-csrf-token"
	for _, method := range []string{"PUT", "DELETE"} {
		req := httptest.NewRequest(method, "/mutate", nil)
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		req.Header.Set(CSRFHeaderName, token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s with valid CSRF token should be 200; got %d", method, w.Code)
		}
	}
}

func TestSetCSRFCookie(t *testing.T) {
	w := httptest.NewRecorder()
	token, err := SetCSRFCookie(w, true)
	if err != nil {
		t.Fatalf("SetCSRFCookie: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty CSRF token")
	}

	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			found = true
			if c.HttpOnly {
				t.Error("CSRF cookie must not be HttpOnly")
			}
			if c.Value != token {
				t.Errorf("cookie value %q != returned token %q", c.Value, token)
			}
		}
	}
	if !found {
		t.Error("CSRF cookie not found in response")
	}
}

func TestClearCSRFCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearCSRFCookie(w)

	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge -1 for cleared cookie; got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("cleared CSRF cookie not found in response")
	}
}

func TestGenerateCSRFToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := generateCSRFToken()
		if err != nil {
			t.Fatalf("generateCSRFToken: %v", err)
		}
		if tokens[tok] {
			t.Fatalf("duplicate CSRF token on iteration %d", i)
		}
		tokens[tok] = true
	}
}

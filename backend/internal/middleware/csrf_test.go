package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// csrfTestConfig returns a config whose CSRF origin allowlist contains the
// server public URL plus one explicitly configured CORS origin.
func csrfTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Server.BaseURL = "http://localhost:8080"
	cfg.Security.CORS.AllowedOrigins = []string{"https://app.example.com"}
	return cfg
}

// csrfRouter builds a test router with CSRFMiddleware. It pre-sets the given
// auth_method in context (simulating what AuthMiddleware would do) so that
// CSRF enforcement can branch correctly.
func csrfRouter(authMethod string) *gin.Engine {
	return csrfRouterWithConfig(authMethod, csrfTestConfig())
}

func csrfRouterWithConfig(authMethod string, cfg *config.Config) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if authMethod != "" {
			c.Set("auth_method", authMethod)
		}
		c.Next()
	})
	r.Use(CSRFMiddleware(cfg))
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

func TestCSRF_APIKeyExempt_WithBrowserOrigin(t *testing.T) {
	r := csrfRouter("api_key")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("API-key-authenticated POST should stay exempt even with a browser Origin; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_NoOrigin_Exempt(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT POST without Origin/Referer (programmatic) should be exempt; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_DisallowedOrigin(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Bearer-JWT POST with disallowed browser Origin should be 403; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_AllowedPublicURLOrigin(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://registry.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT POST from the public URL origin should pass; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_AllowedCORSOrigin(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT POST from a configured CORS origin should pass; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_AllowedBaseURLOrigin(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT POST from the base URL origin should pass; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_DefaultPortNormalization(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://registry.example.com:443")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("explicit default port should match the portless public URL; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_RefererFallback(t *testing.T) {
	r := csrfRouter("jwt")

	// Disallowed referer origin → 403 even without an Origin header.
	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Referer", "https://evil.example.com/some/page")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Bearer-JWT POST with disallowed Referer should be 403; got %d", w.Code)
	}

	// Allowed referer origin (path stripped) → passes.
	req = httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Referer", "https://registry.example.com/admin/modules")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Bearer-JWT POST with allowed Referer origin should pass; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_NullOrigin(t *testing.T) {
	r := csrfRouter("jwt")

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "null")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Bearer-JWT POST with opaque 'null' Origin should be 403; got %d", w.Code)
	}
}

func TestCSRF_BearerJWT_WildcardCORSNotHonored(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.AllowedOrigins = []string{"*"}
	r := csrfRouterWithConfig("jwt", cfg)

	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("CORS wildcard must not disable the Bearer origin check; got %d", w.Code)
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

func TestCSRF_CookieAuth_DoubleSubmitGovernsRegardlessOfOrigin(t *testing.T) {
	r := csrfRouter("jwt_cookie")

	// Valid double-submit passes even with an Origin header present …
	token := "matching-csrf-token"
	req := httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://registry.example.com")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("cookie-auth POST with valid CSRF token and Origin should be 200; got %d", w.Code)
	}

	// … and a missing token fails even from an allowed origin.
	req = httptest.NewRequest("POST", "/mutate", nil)
	req.Header.Set("Origin", "https://registry.example.com")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("cookie-auth POST without CSRF header should be 403 even from an allowed origin; got %d", w.Code)
	}
}

// TestCSRF_Integration_CookieSession_HeaderStripped runs the real middleware
// chain (AuthMiddleware → CSRFMiddleware) against a mutation route with a valid
// JWT session cookie: stripping the X-CSRF-Token header must yield 403, and
// echoing the double-submit token must succeed.
func TestCSRF_Integration_CookieSession_HeaderStripped(t *testing.T) {
	_ = auth.ValidateJWTSecret()
	jwtToken := generateTestJWT(t, "user-570")

	newRouter := func() (*gin.Engine, sqlmock.Sqlmock) {
		userRepo, userMock := newUserRepo(t)
		orgRepo, _ := newOrgRepo(t)
		r := gin.New()
		r.Use(AuthMiddleware(nil, userRepo, nil, orgRepo, nil, nil, nil))
		r.Use(CSRFMiddleware(csrfTestConfig()))
		r.POST("/api/v1/admin/modules/create", func(c *gin.Context) { c.Status(http.StatusCreated) })
		return r, userMock
	}

	expectUserLookup := func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT.*FROM users WHERE id").
			WillReturnRows(sqlmock.NewRows(jwtUserCols).
				AddRow("user-570", "test@example.com", "Test", "sub-570", time.Now(), time.Now()))
	}

	// CSRF header stripped → 403 despite a fully valid auth cookie.
	r, userMock := newRouter()
	expectUserLookup(userMock)
	req := httptest.NewRequest("POST", "/api/v1/admin/modules/create", nil)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: jwtToken})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-570"})
	req.Header.Set("Origin", "https://registry.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("mutation with cookie session and stripped CSRF header should be 403; got %d", w.Code)
	}

	// Same request with the double-submit token echoed → handler runs.
	r, userMock = newRouter()
	expectUserLookup(userMock)
	req = httptest.NewRequest("POST", "/api/v1/admin/modules/create", nil)
	req.AddCookie(&http.Cookie{Name: "tfr_auth_token", Value: jwtToken})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-570"})
	req.Header.Set(CSRFHeaderName, "csrf-570")
	req.Header.Set("Origin", "https://registry.example.com")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("mutation with cookie session and echoed CSRF token should be 201; got %d", w.Code)
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

// Issue #746 — mTLS clients were rejected by CSRF on every mutating request.
//
// mtls.AuthMiddleware sets auth_method = "mtls" and AuthMiddleware lets such
// requests through with no bearer token and no cookie. CSRFMiddleware's matrix
// covered only api_key, jwt and jwt_cookie, so an mTLS request fell to the
// final branch — which assumes cookie authentication, found no tfr_csrf cookie,
// and returned 403 for every POST/PUT/PATCH/DELETE. The documented
// machine-to-machine path could not perform a single mutation.
//
// The direction of failure was safe, which is why it went unnoticed: it also
// means no test crossed the mTLS chain and the CSRF middleware together.

func csrfRequestAs(t *testing.T, cfg *config.Config, authMethod, method, origin string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("auth_method", authMethod) })
	r.Use(CSRFMiddleware(cfg))
	r.Handle(method, "/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(method, "/x", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// TestCSRF_MTLSMachineClientCanMutate is the regression: no Origin (a machine
// client), so the request must go through.
func TestCSRF_MTLSMachineClientCanMutate(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			if code := csrfRequestAs(t, csrfTestConfig(), "mtls", method, ""); code != http.StatusOK {
				t.Errorf("%s as an mTLS machine client = %d, want 200 — the documented "+
					"m2m path must be able to mutate", method, code)
			}
		})
	}
}

// TestCSRF_MTLSFromAForeignOriginIsRejected is why mTLS is NOT blanket-exempt.
//
// A browser holding a client certificate presents it automatically on a
// cross-site request, exactly like a cookie. Exempting mTLS outright — the
// obvious one-line fix — would open the cross-site hole for anyone who
// provisions client certs to browsers.
func TestCSRF_MTLSFromAForeignOriginIsRejected(t *testing.T) {
	if code := csrfRequestAs(t, csrfTestConfig(), "mtls", "POST", "https://evil.example.com"); code != http.StatusForbidden {
		t.Errorf("mTLS POST from a foreign origin = %d, want 403 — a browser-held "+
			"client certificate is auto-presented cross-site", code)
	}
}

// TestCSRF_MTLSFromTheDeploymentsOwnOriginIsAllowed — a same-origin browser
// request with a client cert is legitimate.
func TestCSRF_MTLSFromOwnOriginIsAllowed(t *testing.T) {
	if code := csrfRequestAs(t, csrfTestConfig(), "mtls", "POST", "https://registry.example.com"); code != http.StatusOK {
		t.Errorf("mTLS POST from the deployment's own origin = %d, want 200", code)
	}
}

// TestCSRF_MTLSMatchesTheJWTTreatment pins that the two are handled
// identically. If they ever diverge, one of them is wrong — they are the same
// shape of credential for CSRF purposes: not a cookie, but browser-auto-sendable.
func TestCSRF_MTLSMatchesTheJWTTreatment(t *testing.T) {
	cfg := csrfTestConfig()
	for _, tc := range []struct{ name, origin string }{
		{"no origin", ""},
		{"own origin", "https://registry.example.com"},
		{"foreign origin", "https://evil.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwtCode := csrfRequestAs(t, cfg, "jwt", "POST", tc.origin)
			mtlsCode := csrfRequestAs(t, cfg, "mtls", "POST", tc.origin)
			if jwtCode != mtlsCode {
				t.Errorf("jwt = %d but mtls = %d for %s; the two must be treated alike",
					jwtCode, mtlsCode, tc.name)
			}
		})
	}
}

// TestCSRF_CookieAuthStillRequiresTheToken — the change must not weaken the
// branch it moved mTLS out of.
func TestCSRF_CookieAuthStillRequiresTheToken(t *testing.T) {
	if code := csrfRequestAs(t, csrfTestConfig(), "jwt_cookie", "POST", ""); code != http.StatusForbidden {
		t.Errorf("cookie-authenticated POST with no CSRF token = %d, want 403", code)
	}
}

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newMTLSTestProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=terraform-ci", Scopes: []string{"modules:read", "providers:read"}},
		},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// requestWithVerifiedChains builds a request whose TLS.VerifiedChains contains
// a single chain with the given leaf certificate — simulating what Go's TLS
// stack populates after ClientAuth=VerifyClientCertIfGiven successfully
// verifies a presented client certificate against ClientCAs (see
// tlsconfig.go). Used because httptest cannot terminate a real TLS handshake
// with client-cert verification in a unit test.
func requestWithVerifiedChains(leaf *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if leaf != nil {
		req.TLS = &tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{leaf}},
		}
	}
	return req
}

func TestAuthMiddleware_NilProvider_PassesThrough(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware(nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, requestWithVerifiedChains(&x509.Certificate{Subject: pkix.Name{CommonName: "terraform-ci"}}))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestAuthMiddleware_NoTLS_PassesThroughUnauthenticated(t *testing.T) {
	p := newMTLSTestProvider(t)
	r := gin.New()
	r.Use(AuthMiddleware(p))
	var authMethodSet bool
	r.GET("/", func(c *gin.Context) {
		_, authMethodSet = c.Get("auth_method")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil)) // req.TLS is nil

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if authMethodSet {
		t.Error("auth_method should not be set without a TLS connection")
	}
}

func TestAuthMiddleware_NoVerifiedChains_PassesThroughUnauthenticated(t *testing.T) {
	p := newMTLSTestProvider(t)
	r := gin.New()
	r.Use(AuthMiddleware(p))
	var authMethodSet bool
	r.GET("/", func(c *gin.Context) {
		_, authMethodSet = c.Get("auth_method")
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{} // TLS present, but no client cert was verified
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if authMethodSet {
		t.Error("auth_method should not be set when VerifiedChains is empty")
	}
}

func TestAuthMiddleware_VerifiedCert_MatchedMapping_SetsContext(t *testing.T) {
	p := newMTLSTestProvider(t)
	r := gin.New()
	r.Use(AuthMiddleware(p))

	var gotAuthMethod, gotSubject string
	var gotScopes []string
	r.GET("/", func(c *gin.Context) {
		gotAuthMethod = c.GetString("auth_method")
		gotSubject = c.GetString("mtls_subject")
		if v, ok := c.Get("scopes"); ok {
			gotScopes = v.([]string)
		}
		c.Status(http.StatusOK)
	})

	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "terraform-ci"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, requestWithVerifiedChains(cert))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if gotAuthMethod != "mtls" {
		t.Errorf("auth_method = %q, want mtls", gotAuthMethod)
	}
	if gotSubject != "CN=terraform-ci" {
		t.Errorf("mtls_subject = %q, want CN=terraform-ci", gotSubject)
	}
	if len(gotScopes) != 2 {
		t.Errorf("scopes = %v, want 2 entries", gotScopes)
	}
}

func TestAuthMiddleware_VerifiedCert_NoMapping_PassesThroughUnauthenticated(t *testing.T) {
	p := newMTLSTestProvider(t)
	r := gin.New()
	r.Use(AuthMiddleware(p))
	var authMethodSet bool
	r.GET("/", func(c *gin.Context) {
		_, authMethodSet = c.Get("auth_method")
		c.Status(http.StatusOK)
	})

	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "unmapped-client"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, requestWithVerifiedChains(cert))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if authMethodSet {
		t.Error("auth_method should not be set for a verified cert with no subject mapping")
	}
}

func TestRequireMTLS_NoSubject_Aborts(t *testing.T) {
	r := gin.New()
	r.Use(RequireMTLS())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireMTLS_WithSubject_PassesThrough(t *testing.T) {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("mtls_subject", "CN=terraform-ci")
		c.Next()
	})
	r.Use(RequireMTLS())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

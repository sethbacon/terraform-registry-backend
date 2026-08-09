package admin

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	samlpkg "github.com/terraform-registry/terraform-registry/internal/auth/saml"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Issue #747 — SAML IdP selection fell back to Go's randomised map iteration.
//
// Four places asked the provider map for "the first IdP": the login redirect
// (provider == "saml"), the SP metadata endpoint, the provider list, and — the
// one that matters — the ACS handler's fallback when no RelayState resolved an
// IdP (a genuine IdP-initiated login, an expired or replayed state entry, or an
// IdP removed from config mid-login).
//
// Two consequences in the ACS case:
//
//   - The response was validated against only that one randomly chosen
//     provider's signing certificate, so the same assertion could succeed on one
//     request and fail on the next.
//   - idpName feeds sub = "saml:<idpName>:<NameID>", the user's stable identity
//     key. A user who did succeed could be keyed under a DIFFERENT ACCOUNT
//     across logins.
//
// Signature verification still bound the assertion to whichever provider was
// chosen, so this was never impersonation — it was a nondeterministic identity
// namespace in a security-critical flow, and duplicate accounts under a
// multi-IdP deployment.
//
// These tests use TWO IdPs deliberately. With one configured provider, map
// iteration is trivially deterministic and every one of these passes against
// the unfixed code.

const secondIdPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp2.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp2.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// multiIdPHandler configures two SAML IdPs in a known order.
func multiIdPHandler(t *testing.T, allowIDPInitiated bool) *AuthHandlers {
	t.Helper()
	samlCfg := &config.SAMLConfig{
		Enabled:           true,
		ACSURL:            "https://registry.example.com/api/v1/auth/saml/acs",
		EntityID:          "https://registry.example.com",
		AllowIDPInitiated: allowIDPInitiated,
	}
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	cfg.Auth.SAML = *samlCfg

	h := &AuthHandlers{cfg: cfg, stateStore: auth.NewMemoryStateStore(time.Hour)}
	t.Cleanup(func() { h.stateStore.Close() })

	for _, idp := range []struct{ name, metadata string }{
		{"first-idp", samlTestIdPMetadata},
		{"second-idp", secondIdPMetadata},
	} {
		p, err := samlpkg.NewProvider(samlCfg, &config.SAMLIdPConfig{
			Name: idp.name, MetadataXML: idp.metadata,
		})
		if err != nil {
			t.Fatalf("NewProvider(%s): %v", idp.name, err)
		}
		h.addSAMLProvider(idp.name, p)
	}
	return h
}

func postUnsolicited(h *AuthHandlers, issuer string) *httptest.ResponseRecorder {
	r := gin.New()
	r.POST("/api/v1/auth/saml/acs", h.SAMLACSHandler())
	body := "SAMLResponse=" + url.QueryEscape(unsolicitedSAMLResponse(issuer))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestSAMLACS_UnsolicitedResponseResolvesToTheIssuingIdP is the core assertion:
// the IdP is chosen by matching the response's Issuer, not by map order.
//
// Repeated, because the defect is nondeterminism: a single run of the unfixed
// code has a 50% chance of picking the right provider by luck.
func TestSAMLACS_UnsolicitedResponseResolvesToTheIssuingIdP(t *testing.T) {
	for _, tc := range []struct{ issuer, wantIdP string }{
		{"https://idp.example.com", "first-idp"},
		{"https://idp2.example.com", "second-idp"},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				h := multiIdPHandler(t, true)
				w := postUnsolicited(h, tc.issuer)

				if w.Code != http.StatusFound {
					t.Fatalf("run %d: status = %d, want 302", i, w.Code)
				}
				loc := w.Header().Get("Location")
				// The bogus assertion cannot pass signature validation, and it
				// must not be rejected as unattributable either: reaching
				// assertion_invalid proves a provider WAS resolved and did the
				// validating.
				if strings.Contains(loc, "unknown_idp") || strings.Contains(loc, "invalid_response") {
					t.Fatalf("run %d: response from %s was not attributed to %s: %s",
						i, tc.issuer, tc.wantIdP, loc)
				}
				if !strings.Contains(loc, "assertion_invalid") {
					t.Fatalf("run %d: Location = %q, want assertion_invalid", i, loc)
				}
			}
		})
	}
}

// TestSAMLACS_UnknownIssuerIsRejectedNotGuessed — no match is a rejection.
// Falling back to an arbitrary provider is what produced the nondeterminism.
func TestSAMLACS_UnknownIssuerIsRejectedNotGuessed(t *testing.T) {
	h := multiIdPHandler(t, true)
	w := postUnsolicited(h, "https://attacker.example.com")

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "unknown_idp") {
		t.Errorf("Location = %q, want error=unknown_idp — an unattributable response "+
			"must be rejected rather than validated against a guessed provider", loc)
	}
}

// TestSAMLACS_UnparseableResponseIsRejected — a response whose issuer cannot be
// read at all is also unattributable.
func TestSAMLACS_UnparseableResponseIsRejected(t *testing.T) {
	h := multiIdPHandler(t, true)

	r := gin.New()
	r.POST("/api/v1/auth/saml/acs", h.SAMLACSHandler())
	for _, raw := range []string{
		base64.StdEncoding.EncodeToString([]byte("foo")),         // not XML
		base64.StdEncoding.EncodeToString([]byte("<Response/>")), // XML, no Issuer
		"!!!not-base64!!!", // not base64
	} {
		body := "SAMLResponse=" + url.QueryEscape(raw)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if loc := w.Header().Get("Location"); !strings.Contains(loc, "invalid_response") {
			t.Errorf("raw=%q: Location = %q, want error=invalid_response", raw, loc)
		}
	}
}

// TestSAMLIdPOrder_IsConfigOrderNotMapOrder pins the ordered index itself.
func TestSAMLIdPOrder_IsConfigOrderNotMapOrder(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := multiIdPHandler(t, false)
		if got := h.samlIdPOrder; len(got) != 2 || got[0] != "first-idp" || got[1] != "second-idp" {
			t.Fatalf("run %d: samlIdPOrder = %v, want [first-idp second-idp]", i, got)
		}
	}
}

// TestSAMLMetadataHandler_SelectsTheFirstConfiguredIdP.
//
// Note on what this can and cannot see: in production every IdP shares one SP
// config (NewProviderWithGuard is called with &cfg.Auth.SAML for all of them),
// so the rendered SP metadata is byte-identical whichever provider the handler
// picks — apart from a validUntil timestamp that changes on every call anyway.
// A test comparing rendered output across requests therefore CANNOT detect the
// random selection; my first attempt did exactly that and failed on the
// timestamp, which is a test that would have reported green for the wrong
// reason once the timestamp was normalised.
//
// So this test gives the two IdPs distinguishable SP settings on purpose. That
// is not a production shape; it is what makes the selection observable, and the
// selection is the thing under test.
func TestSAMLMetadataHandler_SelectsTheFirstConfiguredIdP(t *testing.T) {
	newHandler := func() *AuthHandlers {
		cfg := &config.Config{}
		cfg.Server.PublicURL = "https://registry.example.com"
		h := &AuthHandlers{cfg: cfg, stateStore: auth.NewMemoryStateStore(time.Hour)}
		t.Cleanup(func() { h.stateStore.Close() })

		for _, idp := range []struct{ name, entityID, metadata string }{
			{"first-idp", "https://sp-first.example.com", samlTestIdPMetadata},
			{"second-idp", "https://sp-second.example.com", secondIdPMetadata},
		} {
			spCfg := &config.SAMLConfig{
				Enabled:  true,
				ACSURL:   "https://registry.example.com/api/v1/auth/saml/acs",
				EntityID: idp.entityID,
			}
			p, err := samlpkg.NewProvider(spCfg, &config.SAMLIdPConfig{
				Name: idp.name, MetadataXML: idp.metadata,
			})
			if err != nil {
				t.Fatalf("NewProvider(%s): %v", idp.name, err)
			}
			h.addSAMLProvider(idp.name, p)
		}
		return h
	}

	// Repeated: the defect is nondeterminism, so one run has a 50%% chance of
	// picking the right provider by luck.
	for i := 0; i < 20; i++ {
		h := newHandler()
		r := gin.New()
		r.GET("/metadata", h.SAMLMetadataHandler())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metadata", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("run %d: status = %d, want 200", i, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "https://sp-first.example.com") {
			t.Fatalf("run %d: metadata is not the FIRST configured IdP's: %s", i, body)
		}
		if strings.Contains(body, "https://sp-second.example.com") {
			t.Fatalf("run %d: metadata came from the second IdP: %s", i, body)
		}
	}
}

// TestProvidersHandler_ListsIdPsInConfigOrder — the login page must not
// reshuffle its buttons.
func TestProvidersHandler_ListsIdPsInConfigOrder(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := multiIdPHandler(t, false)
		r := gin.New()
		r.GET("/providers", h.ProvidersHandler())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/providers", nil))

		body := w.Body.String()
		firstAt := strings.Index(body, "first-idp")
		secondAt := strings.Index(body, "second-idp")
		if firstAt < 0 || secondAt < 0 {
			t.Fatalf("run %d: both IdPs should be listed: %s", i, body)
		}
		if firstAt > secondAt {
			t.Fatalf("run %d: IdPs listed out of configured order: %s", i, body)
		}
	}
}

// TestAddSAMLProvider_KeepsMapAndOrderInStep is the guard for the divergence
// the helper exists to prevent — the map and the ordered index answering
// different questions about the same set.
func TestAddSAMLProvider_KeepsMapAndOrderInStep(t *testing.T) {
	h := &AuthHandlers{}
	h.addSAMLProvider("a", &samlpkg.Provider{})
	h.addSAMLProvider("b", &samlpkg.Provider{})
	h.addSAMLProvider("a", &samlpkg.Provider{}) // re-registering must not duplicate

	if len(h.samlProviders) != len(h.samlIdPOrder) {
		t.Fatalf("map has %d entries, order has %d: %v vs %v",
			len(h.samlProviders), len(h.samlIdPOrder), h.samlProviders, h.samlIdPOrder)
	}
	for _, name := range h.samlIdPOrder {
		if _, ok := h.samlProviders[name]; !ok {
			t.Errorf("order lists %q, which is not in the map", name)
		}
	}
	if got := h.samlIdPOrder; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("samlIdPOrder = %v, want [a b] (re-registering must not append again)", got)
	}
}

// TestLoginHandler_SAMLDefaultsToTheFirstConfiguredIdP covers the fourth
// selection site: GET /auth/login?provider=saml.
//
// The two test IdPs publish different SSO locations
// (idp.example.com/sso vs idp2.example.com/sso), so the redirect target reveals
// which provider was chosen — that is what makes this test sensitive to the
// defect rather than merely exercising the path.
func TestLoginHandler_SAMLDefaultsToTheFirstConfiguredIdP(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := multiIdPHandler(t, false)
		r := gin.New()
		r.GET("/auth/login", h.LoginHandler())

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=saml", nil))

		if w.Code != http.StatusFound && w.Code != http.StatusTemporaryRedirect {
			t.Fatalf("run %d: status = %d, want a redirect; body: %s", i, w.Code, w.Body.String())
		}
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "idp.example.com/sso") || strings.Contains(loc, "idp2.example.com") {
			t.Fatalf("run %d: redirected to %q, want the FIRST configured IdP "+
				"(idp.example.com); \"saml\" must not resolve to a random IdP", i, loc)
		}
	}
}

// TestLoginHandler_SAMLByNameStillWorks — the explicit "saml:<name>" form must
// keep selecting by name.
func TestLoginHandler_SAMLByNameStillWorks(t *testing.T) {
	h := multiIdPHandler(t, false)
	r := gin.New()
	r.GET("/auth/login", h.LoginHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=saml:second-idp", nil))

	if loc := w.Header().Get("Location"); !strings.Contains(loc, "idp2.example.com/sso") {
		t.Errorf("Location = %q, want the second IdP's SSO URL", loc)
	}
}

// TestLoginHandler_SAMLWithNoIdPsConfigured — the ordered index is empty, so
// idpName stays "" and the lookup must fail cleanly rather than panic.
func TestLoginHandler_SAMLWithNoIdPsConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://registry.example.com"
	h := &AuthHandlers{cfg: cfg, stateStore: auth.NewMemoryStateStore(time.Hour)}
	defer h.stateStore.Close()

	r := gin.New()
	r.GET("/auth/login", h.LoginHandler())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?provider=saml", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when no SAML IdP is configured; body: %s",
			w.Code, w.Body.String())
	}
}

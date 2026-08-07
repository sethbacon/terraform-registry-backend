// nonce_pkce_test.go exercises the BeginAuth / ExchangeAndVerify hardening
// (GHSA-2x28-2g7f-6whr): the nonce and PKCE verifier BeginAuth generates are
// carried as ONE CallbackSession and are both applied, unconditionally, by the
// only call that completes a login.
//
// It replaces the WithExpectedNonce / WithPKCEVerifier tests this file used to
// hold. Those options were deleted in identity v0.25.0 because omitting one
// compiled cleanly and produced an unbound exchange, so the assertions that
// used to prove "the option works when supplied" are re-pointed here at the
// stronger contract: there is no way to supply neither, and the omission cases
// they documented as "additive, still works" are now refusals.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	identityoidc "github.com/sethbacon/terraform-suite-identity/identity/auth/oidc"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// testIdP is a discovery+JWKS test identity provider (oidctest) with a token
// endpoint this test controls.
//
// oidctest.Server advertises token_endpoint = issuer + "/token" in its discovery
// document but serves 404 there, so the exchange half of ExchangeAndVerify has
// nowhere to go. Wrapping it lets one server satisfy the whole flow: discovery
// and JWKS come from oidctest, /token comes from the test.
type testIdP struct {
	ts   *httptest.Server
	priv *rsa.PrivateKey

	// idToken is returned as the id_token of the next token response. Empty
	// means the response carries no id_token at all.
	idToken string
	// gotVerifier records the code_verifier the token endpoint received, and
	// tokenCalled records whether it was reached at all — the latter is what
	// proves a refusal happened BEFORE the network call.
	gotVerifier string
	tokenCalled bool
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	idp := &testIdP{priv: priv}

	srv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: "RS256"},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenCalled = true
		if err := r.ParseForm(); err != nil {
			t.Errorf("token endpoint: ParseForm: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		idp.gotVerifier = r.FormValue("code_verifier")
		body := map[string]any{"access_token": "tok", "token_type": "Bearer"}
		if idp.idToken != "" {
			body["id_token"] = idp.idToken
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.Handle("/", srv)

	// TLS: the issuer must be HTTPS (the shared package requires it unless
	// AllowInsecureIssuer), and every discovered endpoint is scheme-checked too.
	idp.ts = httptest.NewTLSServer(mux)
	t.Cleanup(idp.ts.Close)
	srv.SetIssuer(idp.ts.URL)
	return idp
}

// signToken signs a minimal set of ID token claims for this IdP, including
// nonce only when non-empty (mirroring a real IdP that echoes back whatever
// nonce, if any, the authorization request carried).
func (idp *testIdP) signToken(t *testing.T, clientID, sub, nonce string) string {
	t.Helper()
	claims := map[string]any{
		"iss":            idp.ts.URL,
		"aud":            clientID,
		"sub":            sub,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return oidctest.SignIDToken(idp.priv, "test-key", "RS256", string(raw))
}

// rootPool trusts the test server's self-signed certificate.
func (idp *testIdP) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(idp.ts.Certificate())
	return pool
}

// newTestProvider builds a live Provider (real discovery + JWKS fetch) against
// the test IdP, so ExchangeAndVerify exercises the real verifier rather than the
// discovery-free NewOIDCProviderForTest stub.
//
// It goes through identityoidc.Config rather than this package's
// NewOIDCProviderWithContext because the test IdP needs two deployment inputs
// the registry's own config type does not carry, both introduced by v0.25.0:
//
//   - EgressGuard, because the default policy DENIES loopback and httptest
//     serves on 127.0.0.1. This is the same knob production sets from
//     security.egress.allowlist via ConfigureEgress.
//   - TLSClientConfig, because the previous way to trust httptest's self-signed
//     certificate — installing ts.Client() with oidc.ClientContext — is now
//     REFUSED outright: a caller-supplied client would displace the egress guard
//     on the module's most attacker-adjacent surface.
func newTestProvider(t *testing.T, idp *testIdP, clientID string) *OIDCProvider {
	t.Helper()
	guard, err := identityhttpsafe.NewGuard([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	p, err := identityoidc.NewProviderWithContext(context.Background(), identityoidc.Config{
		IssuerURL:       idp.ts.URL,
		ClientID:        clientID,
		ClientSecret:    "test-secret",
		Scopes:          []string{"openid"},
		EgressGuard:     guard,
		TLSClientConfig: &tls.Config{RootCAs: idp.rootPool(), MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatalf("NewProviderWithContext: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// BeginAuth
// ---------------------------------------------------------------------------

func TestBeginAuth_URLContainsNonceAndPKCEChallenge(t *testing.T) {
	p := newMockOIDCProvider()
	challenge, err := p.BeginAuth("my-state-123")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	for _, want := range []string{"state=my-state-123", "nonce=", "code_challenge=", "code_challenge_method=S256"} {
		if !containsParam(challenge.URL, want) {
			t.Errorf("BeginAuth URL = %q, want to contain %q", challenge.URL, want)
		}
	}
	if challenge.Session.Nonce == "" {
		t.Error("BeginAuth: Session.Nonce is empty, want a generated value")
	}
	if challenge.Session.CodeVerifier == "" {
		t.Error("BeginAuth: Session.CodeVerifier is empty, want a generated value")
	}
}

func TestBeginAuth_GeneratesDistinctNonceAndVerifierPerCall(t *testing.T) {
	p := newMockOIDCProvider()
	first, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	second, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	if first.Session.Nonce == second.Session.Nonce {
		t.Error("two BeginAuth calls produced the same Nonce, want distinct per-login values")
	}
	if first.Session.CodeVerifier == second.Session.CodeVerifier {
		t.Error("two BeginAuth calls produced the same CodeVerifier, want distinct per-login values")
	}
}

func containsParam(url, param string) bool {
	for i := 0; i+len(param) <= len(url); i++ {
		if url[i:i+len(param)] == param {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ExchangeAndVerify — nonce binding (GHSA-2x28-2g7f-6whr)
// ---------------------------------------------------------------------------

// TestExchangeAndVerify_NonceMismatch_Rejected proves the binding actually
// works: an ID token minted for a different login attempt (different nonce) is
// rejected rather than accepted.
func TestExchangeAndVerify_NonceMismatch_Rejected(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(t, idp, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	// Token signed with a DIFFERENT nonce than the one BeginAuth generated for
	// this login — an injected/replayed token from another attempt.
	idp.idToken = idp.signToken(t, "test-client", "user-1", "attacker-controlled-nonce")

	if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", challenge.Session); err == nil {
		t.Fatal("ExchangeAndVerify succeeded with a mismatched nonce, want rejection")
	}
}

// TestExchangeAndVerify_NonceMatch_Succeeds is the happy path: a token carrying
// exactly the nonce BeginAuth generated for this login verifies successfully.
func TestExchangeAndVerify_NonceMatch_Succeeds(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(t, idp, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	idp.idToken = idp.signToken(t, "test-client", "user-1", challenge.Session.Nonce)

	_, idToken, err := p.ExchangeAndVerify(context.Background(), "some-code", challenge.Session)
	if err != nil {
		t.Fatalf("ExchangeAndVerify returned error for a matching nonce: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != challenge.Session.Nonce {
		t.Errorf("Nonce = %q, want %q", idToken.Nonce, challenge.Session.Nonce)
	}
}

// TestExchangeAndVerify_TokenWithoutNonceClaim_Rejected is the inversion of the
// old TestVerifyIDToken_NoExpectedNonce_StillWorks. Under the removed
// option-based API a token carrying NO nonce claim verified successfully
// whenever WithExpectedNonce was omitted, because the deleted GetAuthURL flow
// never requested one. Every authorization request this package builds now
// carries a nonce, so a response without one means the provider dropped the
// binding, and dropping the binding is the attack.
func TestExchangeAndVerify_TokenWithoutNonceClaim_Rejected(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(t, idp, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	idp.idToken = idp.signToken(t, "test-client", "user-1", "") // no nonce claim

	if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", challenge.Session); err == nil {
		t.Fatal("ExchangeAndVerify accepted an ID token with no nonce claim, want rejection")
	}
}

// TestExchangeAndVerify_NoIDToken_Rejected covers the token response that
// carries no id_token at all: the caller must get an error, never an
// (unverified) OAuth2 token it might treat as a completed login.
func TestExchangeAndVerify_NoIDToken_Rejected(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(t, idp, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	idp.idToken = "" // token response omits id_token

	if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", challenge.Session); err == nil {
		t.Fatal("ExchangeAndVerify succeeded with no id_token in the token response, want rejection")
	}
}

// ---------------------------------------------------------------------------
// ExchangeAndVerify — PKCE binding (GHSA-2x28-2g7f-6whr)
// ---------------------------------------------------------------------------

// TestExchangeAndVerify_SendsCodeVerifier proves the PKCE plumbing end-to-end:
// the verifier generated by BeginAuth is actually sent on the token request as
// code_verifier, letting the IdP bind the exchange to the original
// authorization request.
func TestExchangeAndVerify_SendsCodeVerifier(t *testing.T) {
	idp := newTestIdP(t)
	p := newTestProvider(t, idp, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	idp.idToken = idp.signToken(t, "test-client", "user-1", challenge.Session.Nonce)

	if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", challenge.Session); err != nil {
		t.Fatalf("ExchangeAndVerify returned error: %v", err)
	}
	if idp.gotVerifier != challenge.Session.CodeVerifier {
		t.Errorf("code_verifier sent to token endpoint = %q, want %q",
			idp.gotVerifier, challenge.Session.CodeVerifier)
	}
}

// TestExchangeAndVerify_IncompleteSession_RefusedBeforeNetwork replaces the old
// TestExchangeCode_WithoutPKCEVerifier_OmitsCodeVerifier, which asserted that
// omitting the verifier merely left code_verifier off the request — the
// omittable path that made the option-based API unsafe. There is no such path
// now: a missing binding is refused, and refused before the token endpoint is
// dialled at all, which is what tokenCalled asserts.
func TestExchangeAndVerify_IncompleteSession_RefusedBeforeNetwork(t *testing.T) {
	for name, sess := range map[string]identityoidc.CallbackSession{
		"no code verifier": {Nonce: "some-nonce"},
		"no nonce":         {CodeVerifier: "some-verifier"},
		"neither":          {},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newTestIdP(t)
			p := newTestProvider(t, idp, "test-client")

			if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", sess); err == nil {
				t.Fatal("ExchangeAndVerify succeeded with an incomplete CallbackSession, want refusal")
			}
			if idp.tokenCalled {
				t.Error("token endpoint was reached despite an incomplete CallbackSession; " +
					"the refusal must happen before any network call")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Egress guard (identity v0.25.0)
// ---------------------------------------------------------------------------

// TestNewProvider_InternalIssuerDeniedWithoutAllowlist is the deployment
// behaviour that has no compile error to announce it: OIDC discovery, JWKS and
// the token exchange now go through the module's egress guard, whose default
// policy denies loopback and RFC 1918. An internal IdP is unreachable until the
// deployment names it in security.egress.allowlist — which is what
// ConfigureEgress installs.
//
// The assertion is deliberately on construction, because that is where an
// operator meets it: the process refuses to build the provider at startup
// rather than failing the first login.
func TestNewProvider_InternalIssuerDeniedWithoutAllowlist(t *testing.T) {
	idp := newTestIdP(t)

	_, err := identityoidc.NewProviderWithContext(context.Background(), identityoidc.Config{
		IssuerURL:       idp.ts.URL, // 127.0.0.1
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		Scopes:          []string{"openid"},
		EgressGuard:     nil, // strict default: loopback denied
		TLSClientConfig: &tls.Config{RootCAs: idp.rootPool(), MinVersion: tls.VersionTLS12},
	})
	if err == nil {
		t.Fatal("provider construction succeeded against a loopback issuer with no egress allow-list, want refusal")
	}
}

// TestConfigureEgress_AllowsInternalIssuer is the other half: once the
// deployment's allow-list names the internal address, the guard stops being the
// thing that refuses. ConfigureEgress is process-wide, so the previous value is
// restored on cleanup.
//
// The adapter carries no TLS material (the registry's OIDCConfig has no
// CA-bundle field), so construction still fails against a self-signed httptest
// certificate — but with a TLS trust error, NOT the guard's "blocked: loopback
// address" refusal. That difference is the assertion.
func TestConfigureEgress_AllowsInternalIssuer(t *testing.T) {
	idp := newTestIdP(t)

	prev := egressGuard.Load()
	t.Cleanup(func() { egressGuard.Store(prev) })
	if err := ConfigureEgress([]string{"127.0.0.1", "::1"}); err != nil {
		t.Fatalf("ConfigureEgress: %v", err)
	}

	_, err := NewOIDCProviderWithContext(context.Background(), &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    idp.ts.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"openid"},
	})
	if err == nil {
		t.Fatal("expected a TLS trust failure against the self-signed test IdP, got nil")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("want the dial to have been permitted and to fail on TLS trust instead, got: %v", err)
	}
}

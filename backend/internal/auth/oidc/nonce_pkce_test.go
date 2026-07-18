// nonce_pkce_test.go exercises the BeginAuth / WithExpectedNonce / WithPKCEVerifier
// hardening (GHSA-2x28-2g7f-6whr): BeginAuth's generated nonce and PKCE verifier
// actually gate VerifyIDToken and ExchangeCode respectively.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	extoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// newTestIdP starts a discovery+JWKS test identity provider (github.com/
// coreos/go-oidc/v3/oidc/oidctest) backed by a fresh RSA key pair. httptest's
// TLS server satisfies this package's RequireHTTPS-issuer requirement, and
// ts.Client() is preconfigured to trust its self-signed certificate.
func newTestIdP(t *testing.T) (ts *httptest.Server, priv *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	srv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: "RS256"},
		},
	}
	ts = httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	srv.SetIssuer(ts.URL)
	return ts, priv
}

// signToken signs a minimal set of ID token claims for issuer/clientID/sub,
// including nonce only when non-empty (mirroring a real IdP that echoes back
// whatever nonce, if any, was requested on the authorization URL).
func signToken(t *testing.T, priv *rsa.PrivateKey, issuer, clientID, sub, nonce string) string {
	t.Helper()
	claims := map[string]any{
		"iss":            issuer,
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
	return oidctest.SignIDToken(priv, "test-key", "RS256", string(raw))
}

// newTestProvider builds a live OIDCProvider (real discovery + JWKS fetch)
// against the test IdP, so VerifyIDToken exercises the real verifier rather
// than the discovery-free NewOIDCProviderForTest stub.
func newTestProvider(t *testing.T, ts *httptest.Server, clientID string) *OIDCProvider {
	t.Helper()
	ctx := extoidc.ClientContext(context.Background(), ts.Client())
	p, err := NewOIDCProviderWithContext(ctx, &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    ts.URL,
		ClientID:     clientID,
		ClientSecret: "test-secret",
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewOIDCProviderWithContext: %v", err)
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
	if challenge.Nonce == "" {
		t.Error("BeginAuth: Nonce is empty, want a generated value")
	}
	if challenge.CodeVerifier == "" {
		t.Error("BeginAuth: CodeVerifier is empty, want a generated value")
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
	if first.Nonce == second.Nonce {
		t.Error("two BeginAuth calls produced the same Nonce, want distinct per-login values")
	}
	if first.CodeVerifier == second.CodeVerifier {
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
// VerifyIDToken + WithExpectedNonce (nonce binding — GHSA-2x28-2g7f-6whr)
// ---------------------------------------------------------------------------

// TestVerifyIDToken_NonceMismatch_Rejected proves the binding actually works:
// an ID token minted for a different login attempt (different nonce) is
// rejected rather than accepted, closing the injection/replay gap the
// no-options legacy VerifyIDToken call left open.
func TestVerifyIDToken_NonceMismatch_Rejected(t *testing.T) {
	ts, priv := newTestIdP(t)
	p := newTestProvider(t, ts, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}

	// Token signed with a DIFFERENT nonce than the one BeginAuth generated for
	// this login — simulating a token injected/replayed from another attempt.
	token := signToken(t, priv, ts.URL, "test-client", "user-1", "attacker-controlled-nonce")

	if _, err := p.VerifyIDToken(context.Background(), token, WithExpectedNonce(challenge.Nonce)); err == nil {
		t.Fatal("VerifyIDToken succeeded with a mismatched nonce, want rejection")
	}
}

// TestVerifyIDToken_NonceMatch_Succeeds is the happy path: a token carrying
// exactly the nonce BeginAuth generated for this login verifies successfully.
func TestVerifyIDToken_NonceMatch_Succeeds(t *testing.T) {
	ts, priv := newTestIdP(t)
	p := newTestProvider(t, ts, "test-client")

	challenge, err := p.BeginAuth("state-1")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}

	token := signToken(t, priv, ts.URL, "test-client", "user-1", challenge.Nonce)

	idToken, err := p.VerifyIDToken(context.Background(), token, WithExpectedNonce(challenge.Nonce))
	if err != nil {
		t.Fatalf("VerifyIDToken returned error for a matching nonce: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != challenge.Nonce {
		t.Errorf("Nonce = %q, want %q", idToken.Nonce, challenge.Nonce)
	}
}

// TestVerifyIDToken_NoExpectedNonce_StillWorks confirms WithExpectedNonce is
// additive: calling VerifyIDToken without it still works for a token that
// carries no nonce claim at all. (A token that DOES carry a nonce claim now
// requires WithExpectedNonce — see the shared identity/auth/oidc package's
// issue #104 hardening — this repo's real callback path already always
// supplies it; internal/api/admin/auth.go:VerifyIDToken(ctx, rawIDToken,
// oidc.WithExpectedNonce(sessionState.Nonce)).)
func TestVerifyIDToken_NoExpectedNonce_StillWorks(t *testing.T) {
	ts, priv := newTestIdP(t)
	p := newTestProvider(t, ts, "test-client")
	token := signToken(t, priv, ts.URL, "test-client", "user-1", "")

	if _, err := p.VerifyIDToken(context.Background(), token); err != nil {
		t.Fatalf("VerifyIDToken returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode + WithPKCEVerifier (PKCE binding — GHSA-2x28-2g7f-6whr)
// ---------------------------------------------------------------------------

// TestExchangeCode_WithPKCEVerifier_SendsCodeVerifier proves the PKCE plumbing
// end-to-end: the verifier generated by BeginAuth is actually sent on the
// token request as code_verifier, letting the IdP's token endpoint bind the
// exchange to the original authorization request.
func TestExchangeCode_WithPKCEVerifier_SendsCodeVerifier(t *testing.T) {
	var gotVerifier string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotVerifier = r.FormValue("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer ts.Close()

	p := NewOIDCProviderForTest(&oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: ts.URL},
	})

	if _, err := p.ExchangeCode(context.Background(), "some-code", WithPKCEVerifier("test-verifier-123")); err != nil {
		t.Fatalf("ExchangeCode returned error: %v", err)
	}
	if gotVerifier != "test-verifier-123" {
		t.Errorf("code_verifier sent to token endpoint = %q, want test-verifier-123", gotVerifier)
	}
}

// TestExchangeCode_WithoutPKCEVerifier_OmitsCodeVerifier confirms
// WithPKCEVerifier is additive: omitting it (the pre-existing calling
// convention) sends no code_verifier param, unchanged from before.
func TestExchangeCode_WithoutPKCEVerifier_OmitsCodeVerifier(t *testing.T) {
	sawVerifier := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.FormValue("code_verifier") != "" {
			sawVerifier = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer ts.Close()

	p := NewOIDCProviderForTest(&oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: ts.URL},
	})

	if _, err := p.ExchangeCode(context.Background(), "some-code"); err != nil {
		t.Fatalf("ExchangeCode returned error: %v", err)
	}
	if sawVerifier {
		t.Error("code_verifier was sent without WithPKCEVerifier being passed")
	}
}

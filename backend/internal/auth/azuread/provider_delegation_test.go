package azuread

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	extoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidcpkg "github.com/terraform-registry/terraform-registry/internal/auth/oidc"
)

// makeTestIDToken mirrors the helper in internal/auth/oidc/provider_test.go:
// construct an *oidc.IDToken with opaque unexported claims by writing directly
// to the unexported `claims` field via reflect+unsafe.
func makeTestIDToken(claimsJSON string) *extoidc.IDToken {
	tok := &extoidc.IDToken{}
	rv := reflect.ValueOf(tok).Elem()
	f := rv.FieldByName("claims")
	p := (*[]byte)(unsafe.Pointer(f.UnsafeAddr()))
	*p = []byte(claimsJSON)
	return tok
}

// TestExtractUserInfo_DelegatesToOIDC exercises the AzureAD ExtractUserInfo
// wrapper via the underlying OIDC provider (tested more thoroughly in the oidc
// package). A single happy-path assertion here is sufficient to flip the
// delegation method from 0% to 100% coverage.
func TestExtractUserInfo_DelegatesToOIDC(t *testing.T) {
	p := &AzureADProvider{
		oidcProvider: oidcpkg.NewOIDCProviderForTest(&oauth2.Config{ClientID: "c"}),
		tenantID:     "tenant",
	}

	tok := makeTestIDToken(`{"sub":"user-123","email":"alice@example.com","name":"Alice","email_verified":true}`)
	sub, email, name, emailVerified, err := p.ExtractUserInfo(tok)
	if err != nil {
		t.Fatalf("ExtractUserInfo returned error: %v", err)
	}
	if sub != "user-123" {
		t.Errorf("sub = %q, want user-123", sub)
	}
	if email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", email)
	}
	if name != "Alice" {
		t.Errorf("name = %q, want Alice", name)
	}
	if !emailVerified {
		t.Error("emailVerified = false, want true")
	}
}

// TestExtractUserInfo_DelegatesError confirms the wrapper propagates errors
// returned by the underlying OIDC provider (missing sub claim).
func TestExtractUserInfo_DelegatesError(t *testing.T) {
	p := &AzureADProvider{
		oidcProvider: oidcpkg.NewOIDCProviderForTest(&oauth2.Config{ClientID: "c"}),
	}
	tok := makeTestIDToken(`{"email":"bob@example.com"}`) // no sub
	if _, _, _, _, err := p.ExtractUserInfo(tok); err == nil {
		t.Error("expected error for missing sub claim")
	}
}

// TestExchangeAndVerify_DelegatesError ensures the AzureAD ExchangeAndVerify
// wrapper forwards to the underlying provider. A provider built without
// discovery has no verifier, and ExchangeAndVerify refuses outright rather than
// performing an exchange whose ID token it could never check — so this asserts
// the delegation AND the fail-closed direction, where the pre-v0.25.0
// VerifyIDToken wrapper could only be exercised by recovering a nil-verifier
// panic.
func TestExchangeAndVerify_DelegatesError(t *testing.T) {
	p := &AzureADProvider{
		oidcProvider: oidcpkg.NewOIDCProviderForTest(&oauth2.Config{ClientID: "c"}),
	}
	_, _, err := p.ExchangeAndVerify(context.Background(), "some-code", oidcpkg.CallbackSession{
		Nonce: "n", CodeVerifier: "v",
	})
	if err == nil {
		t.Fatal("ExchangeAndVerify succeeded on a provider with no verifier, want refusal")
	}
}

// TestExchangeAndVerify_RefusesMissingBinding is the contract that replaced the
// removed WithPKCEVerifier/WithExpectedNonce options: both bindings are required
// parameters, and an empty one is refused BEFORE any network call rather than
// producing an unbound exchange the IdP may or may not reject.
func TestExchangeAndVerify_RefusesMissingBinding(t *testing.T) {
	p := &AzureADProvider{
		oidcProvider: oidcpkg.NewOIDCProviderForTest(&oauth2.Config{ClientID: "c"}),
	}
	for name, sess := range map[string]oidcpkg.CallbackSession{
		"no code verifier": {Nonce: "n"},
		"no nonce":         {CodeVerifier: "v"},
		"neither":          {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := p.ExchangeAndVerify(context.Background(), "some-code", sess); err == nil {
				t.Fatal("ExchangeAndVerify succeeded with an incomplete CallbackSession, want refusal")
			}
		})
	}
}

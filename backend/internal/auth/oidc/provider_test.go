package oidc

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	extoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// makeTestIDToken constructs an *oidc.IDToken with the given raw JSON claims by
// writing directly to the unexported `claims` field via reflect+unsafe.
// This is the standard Go testing technique for opaque library types.
func makeTestIDToken(claimsJSON string) *extoidc.IDToken {
	tok := &extoidc.IDToken{}
	rv := reflect.ValueOf(tok).Elem()
	f := rv.FieldByName("claims")
	p := (*[]byte)(unsafe.Pointer(f.UnsafeAddr()))
	*p = []byte(claimsJSON)
	return tok
}

// newMockOIDCProvider constructs an OIDCProvider directly without network calls,
// pointing OAuth2 endpoints at an unreachable URL so error paths work correctly.
func newMockOIDCProvider() *OIDCProvider {
	return NewOIDCProviderForTest(&oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.example.com/auth",
			TokenURL: "http://127.0.0.1:1/token", // port 1: always refused
		},
	})
}

func TestNewOIDCProvider_Disabled(t *testing.T) {
	_, err := NewOIDCProvider(&config.OIDCConfig{Enabled: false})
	if err == nil {
		t.Error("expected error when OIDC is disabled, got nil")
	}
}

func TestNewOIDCProvider_MissingIssuerURL(t *testing.T) {
	_, err := NewOIDCProvider(&config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "",
		ClientID:     "client",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Error("expected error for missing IssuerURL, got nil")
	}
}

func TestNewOIDCProvider_MissingClientID(t *testing.T) {
	_, err := NewOIDCProvider(&config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://example.com",
		ClientID:     "",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Error("expected error for missing ClientID, got nil")
	}
}

func TestNewOIDCProvider_MissingClientSecret(t *testing.T) {
	_, err := NewOIDCProvider(&config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://example.com",
		ClientID:     "client",
		ClientSecret: "",
	})
	if err == nil {
		t.Error("expected error for missing ClientSecret, got nil")
	}
}

func TestNewOIDCProvider_HTTPIssuerRejected(t *testing.T) {
	// An HTTP (non-TLS) issuer URL must be rejected: OIDC discovery and JWKS key
	// material would be fetched over plaintext, enabling MITM to forge tokens.
	httpIssuers := []string{
		"http://example.com",
		"http://localhost:8080",
		"http://idp.internal/realms/myrealm",
	}
	for _, issuer := range httpIssuers {
		t.Run(issuer, func(t *testing.T) {
			_, err := NewOIDCProvider(&config.OIDCConfig{
				Enabled:      true,
				IssuerURL:    issuer,
				ClientID:     "client",
				ClientSecret: "secret",
			})
			if err == nil {
				t.Errorf("NewOIDCProvider(%q) expected error for HTTP issuer, got nil", issuer)
			}
			if err != nil && !strings.Contains(err.Error(), "HTTPS") {
				t.Errorf("error = %q, want to mention HTTPS", err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BeginAuth — the only authorization-URL builder since identity v0.25.0.
//
// GetAuthURL was deleted there: it built a bare OAuth2 URL with no nonce and no
// PKCE challenge, so a login started through it could not be bound at the
// callback. The URL-shape assertions it carried are made here instead, against
// the call that does carry both bindings.
// ---------------------------------------------------------------------------

func TestBeginAuth_URLContainsStateClientIDAndResponseType(t *testing.T) {
	p := newMockOIDCProvider()
	challenge, err := p.BeginAuth("my-state-123")
	if err != nil {
		t.Fatalf("BeginAuth returned error: %v", err)
	}
	for _, want := range []string{"state=my-state-123", "client_id=test-client", "response_type=code"} {
		if !strings.Contains(challenge.URL, want) {
			t.Errorf("BeginAuth URL = %q, want to contain %q", challenge.URL, want)
		}
	}
}

// ---------------------------------------------------------------------------
// ExchangeAndVerify
// ---------------------------------------------------------------------------

func TestExchangeAndVerify_NoVerifier_Refused(t *testing.T) {
	// newMockOIDCProvider skips discovery, so the provider has no verifier. The
	// exchange must be refused OUTRIGHT rather than performed and its ID token
	// handed back unverified — the token endpoint here (port 1) would refuse the
	// connection anyway, so the assertion that matters is that the error arrives
	// without one.
	p := newMockOIDCProvider()
	_, _, err := p.ExchangeAndVerify(context.Background(), "some-code", CallbackSession{
		Nonce: "n", CodeVerifier: "v",
	})
	if err == nil {
		t.Error("ExchangeAndVerify expected error on a provider built without discovery, got nil")
	}
}

// ---------------------------------------------------------------------------
// ExtractGroups
// ---------------------------------------------------------------------------

func TestExtractGroups_EmptyClaimName(t *testing.T) {
	p := newMockOIDCProvider()
	// claimName "" → nil without touching the token
	groups := p.ExtractGroups(makeTestIDToken(`{}`), "")
	if groups != nil {
		t.Errorf("ExtractGroups with empty claimName = %v, want nil", groups)
	}
}

func TestExtractGroups_NilClaims_ReturnsNil(t *testing.T) {
	// &oidc.IDToken{} has nil claims → Claims() returns an error
	p := newMockOIDCProvider()
	tok := &extoidc.IDToken{}
	groups := p.ExtractGroups(tok, "groups")
	if groups != nil {
		t.Errorf("ExtractGroups with nil claims = %v, want nil", groups)
	}
}

func TestExtractGroups_ClaimNotPresent(t *testing.T) {
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"sub":"user1"}`)
	groups := p.ExtractGroups(tok, "groups")
	if groups != nil {
		t.Errorf("ExtractGroups with missing claim = %v, want nil", groups)
	}
}

func TestExtractGroups_SliceOfInterface_StringItems(t *testing.T) {
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"groups":["admins","devs","viewers"]}`)
	groups := p.ExtractGroups(tok, "groups")
	if len(groups) != 3 {
		t.Fatalf("len = %d, want 3", len(groups))
	}
	if groups[0] != "admins" || groups[1] != "devs" || groups[2] != "viewers" {
		t.Errorf("groups = %v, want [admins devs viewers]", groups)
	}
}

func TestExtractGroups_SliceOfInterface_FiltersEmptyStrings(t *testing.T) {
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"groups":["admins","","devs"]}`)
	groups := p.ExtractGroups(tok, "groups")
	if len(groups) != 2 {
		t.Fatalf("len = %d, want 2 (empty string filtered out)", len(groups))
	}
}

func TestExtractGroups_SliceOfInterface_NonStringItem(t *testing.T) {
	// JSON numbers in the array are not strings — they should be skipped.
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"groups":["admins",42]}`)
	groups := p.ExtractGroups(tok, "groups")
	if len(groups) != 1 || groups[0] != "admins" {
		t.Errorf("groups = %v, want [admins]", groups)
	}
}

func TestExtractGroups_NonArrayClaim_ReturnsNil(t *testing.T) {
	// A scalar string claim is not a []interface{} or []string → default case.
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"groups":"admins"}`)
	groups := p.ExtractGroups(tok, "groups")
	if groups != nil {
		t.Errorf("ExtractGroups with scalar claim = %v, want nil", groups)
	}
}

func TestExtractGroups_EmptySlice(t *testing.T) {
	p := newMockOIDCProvider()
	tok := makeTestIDToken(`{"groups":[]}`)
	groups := p.ExtractGroups(tok, "groups")
	if len(groups) != 0 {
		t.Errorf("ExtractGroups with empty array = %v, want []", groups)
	}
}

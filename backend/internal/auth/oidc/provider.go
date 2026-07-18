// Package oidc - provider.go delegates generic OpenID Connect handling to the
// shared identity/auth/oidc package, keeping the registry's config mapping, the
// "enabled" gate, and the HTTPS-issuer requirement. Provider-specific behavior
// (Azure AD, etc.) is handled by sibling packages built on this adapter.
package oidc

import (
	"context"
	"fmt"

	identityoidc "github.com/sethbacon/terraform-suite-identity/identity/auth/oidc"
	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// OIDCProvider is the suite identity OIDC provider, aliased so existing call
// sites (including the azuread sibling package) keep referring to
// oidc.OIDCProvider. Its BeginAuth method (nonce + PKCE) carries over via this
// alias with no extra wrapping needed.
type OIDCProvider = identityoidc.Provider

// AuthChallenge re-exports identityoidc.AuthChallenge so callers don't need to
// import the identity package directly. It is returned by BeginAuth and holds
// the per-login Nonce and CodeVerifier that must be persisted (keyed to the
// state token) and supplied back at the callback via WithExpectedNonce and
// WithPKCEVerifier.
type AuthChallenge = identityoidc.AuthChallenge

// VerifyOption re-exports identityoidc.VerifyOption.
type VerifyOption = identityoidc.VerifyOption

// ExchangeOption re-exports identityoidc.ExchangeOption.
type ExchangeOption = identityoidc.ExchangeOption

// WithExpectedNonce re-exports identityoidc.WithExpectedNonce so VerifyIDToken
// callers can bind verification to the nonce a BeginAuth call generated for
// this login, defending against ID-token injection/replay.
func WithExpectedNonce(nonce string) VerifyOption {
	return identityoidc.WithExpectedNonce(nonce)
}

// WithPKCEVerifier re-exports identityoidc.WithPKCEVerifier so ExchangeCode
// callers can bind the token exchange to the PKCE verifier a BeginAuth call
// generated for this login, defending against authorization-code interception.
func WithPKCEVerifier(verifier string) ExchangeOption {
	return identityoidc.WithPKCEVerifier(verifier)
}

// NewOIDCProvider initializes a new OIDC provider using a background context.
func NewOIDCProvider(cfg *config.OIDCConfig) (*OIDCProvider, error) {
	return NewOIDCProviderWithContext(context.Background(), cfg)
}

// NewOIDCProviderWithContext initializes a new OIDC provider with the given
// context (governing the discovery request). The "enabled" gate stays in the
// app; HTTPS is required for the issuer URL to prevent MITM key substitution.
func NewOIDCProviderWithContext(ctx context.Context, cfg *config.OIDCConfig) (*OIDCProvider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	return identityoidc.NewProviderWithContext(ctx, identityoidc.Config{
		IssuerURL:    cfg.IssuerURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		// AllowInsecureIssuer left false (the zero value): HTTPS is required
		// for the issuer/redirect URLs by default in the shared package,
		// matching this provider's original RequireHTTPS:true intent (the
		// field was renamed/inverted upstream — see identity/auth/oidc.Config).
	})
}

// NewOIDCProviderForTest constructs an OIDCProvider backed by the given oauth2
// config without performing OIDC discovery. Exported for sibling packages (e.g.
// azuread) and tests that exercise the OAuth2 methods without a live provider.
func NewOIDCProviderForTest(cfg *oauth2.Config) *OIDCProvider {
	return identityoidc.NewProviderForConfig(cfg)
}

// Package oidc - provider.go delegates generic OpenID Connect handling to the
// shared identity/auth/oidc package, keeping the registry's config mapping, the
// "enabled" gate, and the HTTPS-issuer requirement. Provider-specific behavior
// (Azure AD, etc.) is handled by sibling packages built on this adapter.
package oidc

import (
	"context"
	"fmt"
	"sync/atomic"

	identityoidc "github.com/sethbacon/terraform-suite-identity/identity/auth/oidc"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// egressGuard carries the deployment's egress allow-list
// (security.egress.allowlist) into every provider this package constructs.
//
// As of identity v0.25.0 the shared package routes ALL of its outbound traffic —
// the discovery document, the JWKS signing keys that decide which ID tokens are
// valid, and the token exchange that carries the client_secret — through
// identity/httpsafe, whose default policy DENIES loopback, RFC 1918, link-local,
// CGNAT and IPv6 ULA. A deployment whose IdP lives on an internal address (every
// self-hosted Keycloak/ADFS, and every local compose stack) must therefore say so
// or provider construction fails at startup naming the denied endpoint.
//
// It is package state, set once at startup, for the same reason
// scm.ConfigureEgress is: the constructors are reached from four places
// (router startup, the admin auth handler, the setup wizard, and the azuread
// sibling, which holds only a *config.AzureADConfig and has no route to the
// deployment's security block at all). Threading a guard parameter through all
// of them would put the same value in four signatures to serve one process-wide
// deployment setting.
//
// A nil guard — the value until ConfigureEgress runs — is the STRICT policy, not
// an absent one, so the failure direction of a missed call is refusal rather
// than an unguarded fetch.
var egressGuard atomic.Pointer[identityhttpsafe.Guard]

// ConfigureEgress installs the operator-configured egress allow-list for OIDC
// discovery, JWKS and token-exchange traffic. Call once at startup, before any
// provider is constructed; entries may be hostnames, IPs or CIDR ranges.
// Allow-listing the IdP's HOSTNAME is preferred over its CIDR: it is narrower,
// and it survives the host getting a different address.
func ConfigureEgress(allowlist []string) error {
	g, err := identityhttpsafe.NewGuard(allowlist)
	if err != nil {
		return err
	}
	egressGuard.Store(g)
	return nil
}

// OIDCProvider is the suite identity OIDC provider, aliased so existing call
// sites (including the azuread sibling package) keep referring to
// oidc.OIDCProvider. Its BeginAuth method (nonce + PKCE) carries over via this
// alias with no extra wrapping needed.
type OIDCProvider = identityoidc.Provider

// AuthChallenge re-exports identityoidc.AuthChallenge so callers don't need to
// import the identity package directly. It is returned by BeginAuth and holds
// the per-login Session (nonce + PKCE code verifier) that must be persisted
// (keyed to the state token) and supplied back to ExchangeAndVerify at the
// callback.
type AuthChallenge = identityoidc.AuthChallenge

// CallbackSession re-exports identityoidc.CallbackSession — the single value
// that carries this login's nonce and PKCE verifier from BeginAuth to
// ExchangeAndVerify. It replaces the removed WithExpectedNonce/WithPKCEVerifier
// options: both bindings are now required parameters of the only method that
// completes an exchange, so neither can be omitted at a call site.
type CallbackSession = identityoidc.CallbackSession

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
		//
		// EgressGuard is a SEPARATE rule from that one: opting out of HTTPS
		// would not opt out of knowing where the traffic goes, and neither
		// grants the other. Nil here is the strict default policy.
		EgressGuard: egressGuard.Load(),
	})
}

// NewOIDCProviderForTest constructs an OIDCProvider backed by the given oauth2
// config without performing OIDC discovery. Exported for sibling packages (e.g.
// azuread) and tests that exercise the OAuth2 methods without a live provider.
func NewOIDCProviderForTest(cfg *oauth2.Config) *OIDCProvider {
	return identityoidc.NewProviderForConfig(cfg)
}

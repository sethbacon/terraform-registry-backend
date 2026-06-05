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
// oidc.OIDCProvider.
type OIDCProvider = identityoidc.Provider

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
		RequireHTTPS: true,
	})
}

// NewOIDCProviderForTest constructs an OIDCProvider backed by the given oauth2
// config without performing OIDC discovery. Exported for sibling packages (e.g.
// azuread) and tests that exercise the OAuth2 methods without a live provider.
func NewOIDCProviderForTest(cfg *oauth2.Config) *OIDCProvider {
	return identityoidc.NewProviderForConfig(cfg)
}

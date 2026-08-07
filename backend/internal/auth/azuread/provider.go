// Package azuread implements Azure Active Directory / Entra ID authentication for the registry.
// It wraps the standard OIDC flow with Azure-specific claims handling (groups, roles, tenant validation).
// Use this provider when your organization uses Microsoft identity for SSO.
package azuread

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	oidcpkg "github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"golang.org/x/oauth2"
)

// AzureADProvider wraps OIDC provider with Azure AD-specific configuration
type AzureADProvider struct {
	oidcProvider *oidcpkg.OIDCProvider
	tenantID     string
}

// NewAzureADProviderForTest builds an AzureADProvider around an already-
// constructed OIDC provider (e.g. oidcpkg.NewOIDCProviderForTest), without
// performing Azure AD discovery. Exported for tests in other packages (e.g.
// api/admin) that need a working AzureADProvider without a live tenant.
func NewAzureADProviderForTest(oidcProvider *oidcpkg.OIDCProvider, tenantID string) *AzureADProvider {
	return &AzureADProvider{oidcProvider: oidcProvider, tenantID: tenantID}
}

// NewAzureADProvider initializes a new Azure AD provider
func NewAzureADProvider(cfg *config.AzureADConfig) (*AzureADProvider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("Azure AD is not enabled")
	}

	if cfg.TenantID == "" {
		return nil, fmt.Errorf("Azure AD tenant ID is required")
	}

	if cfg.ClientID == "" {
		return nil, fmt.Errorf("Azure AD client ID is required")
	}

	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("Azure AD client secret is required")
	}

	// Construct Azure AD OIDC configuration
	// Azure AD v2.0 endpoint format
	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.TenantID)

	// Convert Azure AD config to OIDC config
	oidcConfig := &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    issuerURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
	}

	// Create OIDC provider
	oidcProv, err := oidcpkg.NewOIDCProvider(oidcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for Azure AD: %w", err)
	}

	return &AzureADProvider{
		oidcProvider: oidcProv,
		tenantID:     cfg.TenantID,
	}, nil
}

// BeginAuth builds an Azure AD authorization URL that includes a random nonce
// and a PKCE (S256) code challenge, returning it alongside the CallbackSession
// carrying both. The caller MUST persist that session server-side (keyed to the
// state token) and hand it back to ExchangeAndVerify at the callback. See
// oidc.Provider.BeginAuth for details.
func (p *AzureADProvider) BeginAuth(state string) (oidcpkg.AuthChallenge, error) {
	return p.oidcProvider.BeginAuth(state)
}

// ExchangeAndVerify completes an Azure AD login: it exchanges the authorization
// code and verifies the resulting ID token, applying this login's PKCE verifier
// and nonce itself. session must be the CallbackSession BeginAuth produced for
// this login; an empty Nonce or CodeVerifier is refused before any network call.
// coverage:skip:integration-only — delegates to oidc.ExchangeAndVerify which requires a live IdP to exercise.
func (p *AzureADProvider) ExchangeAndVerify(ctx context.Context, code string, session oidcpkg.CallbackSession) (*oauth2.Token, *oidc.IDToken, error) {
	return p.oidcProvider.ExchangeAndVerify(ctx, code, session)
}

// ExtractUserInfo extracts user information from the Azure AD token
// coverage:skip:integration-only — thin delegation to oidc.ExtractUserInfo; the underlying logic is fully unit-tested in the oidc package.
func (p *AzureADProvider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, emailVerified bool, err error) {
	return p.oidcProvider.ExtractUserInfo(idToken)
}

// GetTenantID returns the Azure AD tenant ID
func (p *AzureADProvider) GetTenantID() string {
	return p.tenantID
}

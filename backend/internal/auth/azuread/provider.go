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

// GetAuthURL returns the Azure AD authorization URL
func (p *AzureADProvider) GetAuthURL(state string) string {
	return p.oidcProvider.GetAuthURL(state)
}

// ExchangeCode exchanges the authorization code for tokens
func (p *AzureADProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oidcProvider.ExchangeCode(ctx, code)
}

// VerifyIDToken verifies the Azure AD ID token
func (p *AzureADProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return p.oidcProvider.VerifyIDToken(ctx, rawIDToken)
}

// ExtractUserInfo extracts user information from the Azure AD token
func (p *AzureADProvider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, err error) {
	return p.oidcProvider.ExtractUserInfo(idToken)
}

// GetTenantID returns the Azure AD tenant ID
func (p *AzureADProvider) GetTenantID() string {
	return p.tenantID
}

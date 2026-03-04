// Package oidc implements generic OpenID Connect authentication for the registry.
// It handles OIDC service discovery, token exchange, and claims extraction.
// Provider-specific behavior (Azure AD, GitHub, etc.) is handled by sub-packages or configuration.
package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"golang.org/x/oauth2"
)

// OIDCProvider wraps the generic OIDC provider
type OIDCProvider struct {
	verifier *oidc.IDTokenVerifier
	config   *oauth2.Config
	provider *oidc.Provider
}

// NewOIDCProvider initializes a new OIDC provider using a background context.
func NewOIDCProvider(cfg *config.OIDCConfig) (*OIDCProvider, error) {
	return NewOIDCProviderWithContext(context.Background(), cfg)
}

// NewOIDCProviderWithContext initializes a new OIDC provider with the given context,
// allowing callers to set deadlines or cancellation for the OIDC discovery request.
func NewOIDCProviderWithContext(ctx context.Context, cfg *config.OIDCConfig) (*OIDCProvider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("OIDC is not enabled")
	}

	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is required")
	}

	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OIDC client ID is required")
	}

	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC client secret is required")
	}

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	return &OIDCProvider{
		verifier: verifier,
		config:   oauth2Config,
		provider: provider,
	}, nil
}

// GetAuthURL returns the OAuth2 authorization URL
func (p *OIDCProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// GetEndSessionEndpoint returns the OIDC end_session_endpoint from the discovery document,
// or an empty string if the provider does not advertise one.
func (p *OIDCProvider) GetEndSessionEndpoint() string {
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return ""
	}
	return claims.EndSessionEndpoint
}

// ExchangeCode exchanges the authorization code for tokens
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

// VerifyIDToken verifies and extracts claims from the ID token
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	return idToken, nil
}

// ExtractGroups reads the named claim from the ID token and returns its string values.
// claimName is typically "groups", "roles", or "memberOf" depending on the IdP.
// Returns an empty slice (not an error) when the claim is absent or empty.
func (p *OIDCProvider) ExtractGroups(idToken *oidc.IDToken, claimName string) []string {
	if claimName == "" {
		return nil
	}

	var raw map[string]interface{}
	if err := idToken.Claims(&raw); err != nil {
		return nil
	}

	val, ok := raw[claimName]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	case []string:
		return v
	default:
		return nil
	}
}

// ExtractUserInfo extracts user information from the ID token
func (p *OIDCProvider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, err error) {
	// Standard claims
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Validate required fields
	if claims.Sub == "" {
		return "", "", "", fmt.Errorf("ID token missing 'sub' claim")
	}

	if claims.Email == "" {
		return "", "", "", fmt.Errorf("ID token missing 'email' claim")
	}

	// Name is optional, use email if not provided
	if claims.Name == "" {
		claims.Name = claims.Email
	}

	return claims.Sub, claims.Email, claims.Name, nil
}

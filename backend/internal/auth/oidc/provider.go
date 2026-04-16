// Package oidc implements generic OpenID Connect authentication for the registry.
// It handles OIDC service discovery, token exchange, and claims extraction.
// Provider-specific behavior (Azure AD, GitHub, etc.) is handled by sub-packages or configuration.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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

	// Require HTTPS for the issuer URL. An HTTP issuer means discovery and JWKS
	// key material are fetched over plaintext, allowing a MITM to substitute
	// signing keys and forge valid ID tokens.
	if !strings.HasPrefix(cfg.IssuerURL, "https://") {
		return nil, fmt.Errorf("OIDC issuer URL must use HTTPS, got: %q", cfg.IssuerURL)
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

// NewOIDCProviderForTest constructs an OIDCProvider backed by the given oauth2 config
// without performing OIDC discovery. Exported for sibling packages (e.g. azuread) that
// need to unit-test delegation methods without a live identity provider.
func NewOIDCProviderForTest(cfg *oauth2.Config) *OIDCProvider {
	return &OIDCProvider{config: cfg}
}

// GetAuthURL returns the OAuth2 authorization URL
func (p *OIDCProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// GetEndSessionEndpoint returns the OIDC end_session_endpoint from the discovery document,
// or an empty string if the provider does not advertise one.
// coverage:skip:integration-only — requires a live OIDC provider
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

// VerifyIDToken verifies and extracts claims from the ID token.
// coverage:skip:integration-only — requires a live OIDC provider and signed token
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

// ExtractUserInfo extracts user information from the ID token.
// coverage:skip:integration-only — requires a live OIDC provider and signed token
func (p *OIDCProvider) ExtractUserInfo(idToken *oidc.IDToken) (sub, email, name string, err error) {
	// Standard claims plus Azure AD / Entra ID extensions:
	//   preferred_username — v2.0 token UPN, always present for member accounts
	//   upn               — on-premises synced accounts
	//   unique_name       — v1.0 token UPN (legacy)
	// Azure AD does not include `email` by default unless the optional claim is
	// added to the App Registration token configuration.
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		UPN               string `json:"upn"`
		UniqueName        string `json:"unique_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if claims.Sub == "" {
		return "", "", "", fmt.Errorf("ID token missing 'sub' claim")
	}

	// Resolve email: try standard claim first, then Azure AD UPN variants.
	resolved := claims.Email
	if resolved == "" {
		resolved = claims.PreferredUsername
	}
	if resolved == "" {
		resolved = claims.UPN
	}
	if resolved == "" {
		resolved = claims.UniqueName
	}
	if resolved == "" {
		// Log the raw token claims so the administrator can diagnose which
		// claims the identity provider is actually sending.
		var raw map[string]json.RawMessage
		if jsonErr := idToken.Claims(&raw); jsonErr == nil {
			keys := make([]string, 0, len(raw))
			for k := range raw {
				keys = append(keys, k)
			}
			slog.Error("oidc: no email identifier found in ID token",
				"available_claims", keys,
				"sub", string(raw["sub"]),
				"preferred_username", string(raw["preferred_username"]),
				"upn", string(raw["upn"]),
				"unique_name", string(raw["unique_name"]),
				"email", string(raw["email"]),
			)
		}
		return "", "", "", fmt.Errorf("ID token missing email identifier (checked: email, preferred_username, upn, unique_name)")
	}

	// Name is optional, fall back to resolved email.
	if claims.Name == "" {
		claims.Name = resolved
	}

	return claims.Sub, resolved, claims.Name, nil
}

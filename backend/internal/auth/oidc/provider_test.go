package oidc

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// newMockOIDCProvider constructs an OIDCProvider directly without network calls,
// pointing OAuth2 endpoints at an unreachable URL so error paths work correctly.
func newMockOIDCProvider() *OIDCProvider {
	return &OIDCProvider{
		config: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://provider.example.com/auth",
				TokenURL: "http://127.0.0.1:1/token", // port 1: always refused
			},
		},
	}
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

// ---------------------------------------------------------------------------
// GetAuthURL
// ---------------------------------------------------------------------------

func TestGetAuthURL_ContainsState(t *testing.T) {
	p := newMockOIDCProvider()
	url := p.GetAuthURL("my-state-123")
	if !strings.Contains(url, "state=my-state-123") {
		t.Errorf("GetAuthURL = %q, want to contain state=my-state-123", url)
	}
}

func TestGetAuthURL_ContainsClientID(t *testing.T) {
	p := newMockOIDCProvider()
	url := p.GetAuthURL("s")
	if !strings.Contains(url, "client_id=test-client") {
		t.Errorf("GetAuthURL = %q, want to contain client_id=test-client", url)
	}
}

func TestGetAuthURL_ContainsResponseTypeCode(t *testing.T) {
	p := newMockOIDCProvider()
	url := p.GetAuthURL("s")
	if !strings.Contains(url, "response_type=code") {
		t.Errorf("GetAuthURL = %q, want to contain response_type=code", url)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode
// ---------------------------------------------------------------------------

func TestExchangeCode_NetworkError(t *testing.T) {
	p := newMockOIDCProvider()
	// Token URL is port 1 — always refused immediately.
	_, err := p.ExchangeCode(context.Background(), "some-code")
	if err == nil {
		t.Error("ExchangeCode expected error for unreachable token endpoint, got nil")
	}
}

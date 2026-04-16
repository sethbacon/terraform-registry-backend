package azuread

import (
	"context"
	"strings"
	"testing"

	oidcpkg "github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"golang.org/x/oauth2"
)

func TestNewAzureADProvider_Disabled(t *testing.T) {
	_, err := NewAzureADProvider(&config.AzureADConfig{Enabled: false})
	if err == nil {
		t.Error("expected error when Azure AD is disabled, got nil")
	}
}

func TestNewAzureADProvider_MissingTenantID(t *testing.T) {
	_, err := NewAzureADProvider(&config.AzureADConfig{
		Enabled:      true,
		TenantID:     "",
		ClientID:     "client",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Error("expected error for missing TenantID, got nil")
	}
}

func TestNewAzureADProvider_MissingClientID(t *testing.T) {
	_, err := NewAzureADProvider(&config.AzureADConfig{
		Enabled:      true,
		TenantID:     "tenant",
		ClientID:     "",
		ClientSecret: "secret",
	})
	if err == nil {
		t.Error("expected error for missing ClientID, got nil")
	}
}

func TestNewAzureADProvider_MissingClientSecret(t *testing.T) {
	_, err := NewAzureADProvider(&config.AzureADConfig{
		Enabled:      true,
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "",
	})
	if err == nil {
		t.Error("expected error for missing ClientSecret, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetTenantID
// ---------------------------------------------------------------------------

func TestGetTenantID(t *testing.T) {
	p := &AzureADProvider{tenantID: "my-tenant-id"}
	if got := p.GetTenantID(); got != "my-tenant-id" {
		t.Errorf("GetTenantID() = %q, want my-tenant-id", got)
	}
}

func TestGetTenantID_Empty(t *testing.T) {
	p := &AzureADProvider{}
	if got := p.GetTenantID(); got != "" {
		t.Errorf("GetTenantID() = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// GetAuthURL (delegates to oidcProvider)
// ---------------------------------------------------------------------------

func TestGetAuthURL(t *testing.T) {
	mockOIDC := oidcpkg.NewOIDCProviderForTest(&oauth2.Config{
		ClientID: "azure-client",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
		},
		RedirectURL: "https://registry.example.com/callback",
		Scopes:      []string{"openid", "email"},
	})
	p := &AzureADProvider{
		oidcProvider: mockOIDC,
		tenantID:     "tenant-abc",
	}

	url := p.GetAuthURL("test-state")
	if !strings.Contains(url, "state=test-state") {
		t.Errorf("URL missing state param, got: %s", url)
	}
	if !strings.Contains(url, "client_id=azure-client") {
		t.Errorf("URL missing client_id, got: %s", url)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode (delegates to oidcProvider — verifies error path)
// ---------------------------------------------------------------------------

func TestExchangeCode_NetworkError(t *testing.T) {
	mockOIDC := oidcpkg.NewOIDCProviderForTest(&oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: "http://127.0.0.1:1/token", // always refused
		},
	})
	p := &AzureADProvider{
		oidcProvider: mockOIDC,
		tenantID:     "tenant",
	}

	_, err := p.ExchangeCode(context.Background(), "some-code")
	if err == nil {
		t.Error("ExchangeCode expected error for unreachable token endpoint, got nil")
	}
}

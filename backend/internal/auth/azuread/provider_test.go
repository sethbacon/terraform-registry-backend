package azuread

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
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

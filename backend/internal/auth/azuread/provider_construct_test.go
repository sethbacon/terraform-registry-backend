package azuread

import (
	"strings"
	"testing"

	oidcpkg "github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// The constructor rejects an incomplete configuration BEFORE it reaches Azure AD
// discovery. Each required field is asserted separately: a single "invalid
// config is refused" case passes even if only one guard survives, which is how a
// refactor quietly drops the others.
func TestNewAzureADProvider_RejectsIncompleteConfig(t *testing.T) {
	complete := func() *config.AzureADConfig {
		return &config.AzureADConfig{Enabled: true, TenantID: "t", ClientID: "c", ClientSecret: "s"}
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*config.AzureADConfig)
		wantSub string
	}{
		{"disabled", func(c *config.AzureADConfig) { c.Enabled = false }, "not enabled"},
		{"no tenant", func(c *config.AzureADConfig) { c.TenantID = "" }, "tenant ID"},
		{"no client id", func(c *config.AzureADConfig) { c.ClientID = "" }, "client ID"},
		{"no client secret", func(c *config.AzureADConfig) { c.ClientSecret = "" }, "client secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := complete()
			tc.mutate(cfg)
			p, err := NewAzureADProvider(cfg)
			if err == nil {
				t.Fatalf("incomplete config was accepted; a provider built without %s would attempt discovery against a tenant it cannot authenticate to", tc.name)
			}
			if p != nil {
				t.Fatalf("got a non-nil provider alongside the error; a partially-built provider must never escape the constructor")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantSub)) {
				t.Fatalf("error = %q, want it to name %q so the operator knows which field is missing", err, tc.wantSub)
			}
		})
	}
}

// The test constructor must wire both fields through — a provider with a nil
// inner OIDC provider or a blank tenant would fail later and far from here.
func TestNewAzureADProviderForTest_WiresBothFields(t *testing.T) {
	inner := &oidcpkg.OIDCProvider{}
	p := NewAzureADProviderForTest(inner, "tenant-123")
	if p == nil {
		t.Fatal("constructor returned nil")
	}
	if p.oidcProvider != inner {
		t.Fatal("inner OIDC provider was not wired through")
	}
	if p.tenantID != "tenant-123" {
		t.Fatalf("tenantID = %q, want %q", p.tenantID, "tenant-123")
	}
}

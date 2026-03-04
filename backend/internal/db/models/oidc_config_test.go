package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// OIDCConfig.ToResponse
// ---------------------------------------------------------------------------

func TestOIDCConfig_ToResponse_BasicFields(t *testing.T) {
	id := uuid.New()
	now := time.Now()
	cfg := &OIDCConfig{
		ID:           id,
		Name:         "my-provider",
		ProviderType: "generic_oidc",
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "client-123",
		RedirectURL:  "https://app.example.com/callback",
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	resp := cfg.ToResponse()

	if resp.ID != id {
		t.Errorf("ID = %v, want %v", resp.ID, id)
	}
	if resp.Name != "my-provider" {
		t.Errorf("Name = %q, want %q", resp.Name, "my-provider")
	}
	if resp.ProviderType != "generic_oidc" {
		t.Errorf("ProviderType = %q, want %q", resp.ProviderType, "generic_oidc")
	}
	if resp.IssuerURL != "https://issuer.example.com" {
		t.Errorf("IssuerURL = %q", resp.IssuerURL)
	}
	if resp.ClientID != "client-123" {
		t.Errorf("ClientID = %q", resp.ClientID)
	}
	if resp.RedirectURL != "https://app.example.com/callback" {
		t.Errorf("RedirectURL = %q", resp.RedirectURL)
	}
	if !resp.IsActive {
		t.Error("IsActive should be true")
	}
}

func TestOIDCConfig_ToResponse_DefaultScopes(t *testing.T) {
	cfg := &OIDCConfig{}
	resp := cfg.ToResponse()

	if len(resp.Scopes) != 3 {
		t.Fatalf("default scopes length = %d, want 3", len(resp.Scopes))
	}
	expected := []string{"openid", "email", "profile"}
	for i, s := range expected {
		if resp.Scopes[i] != s {
			t.Errorf("scope[%d] = %q, want %q", i, resp.Scopes[i], s)
		}
	}
}

func TestOIDCConfig_ToResponse_CustomScopes(t *testing.T) {
	scopes := []string{"openid", "groups"}
	scopesJSON, _ := json.Marshal(scopes)
	cfg := &OIDCConfig{
		Scopes: scopesJSON,
	}

	resp := cfg.ToResponse()
	if len(resp.Scopes) != 2 {
		t.Fatalf("scopes length = %d, want 2", len(resp.Scopes))
	}
	if resp.Scopes[0] != "openid" || resp.Scopes[1] != "groups" {
		t.Errorf("scopes = %v, want [openid groups]", resp.Scopes)
	}
}

func TestOIDCConfig_ToResponse_ExtraConfig(t *testing.T) {
	extraJSON, _ := json.Marshal(map[string]interface{}{"tenant_id": "abc"})
	cfg := &OIDCConfig{
		ExtraConfig: extraJSON,
	}

	resp := cfg.ToResponse()
	if resp.ExtraConfig == nil {
		t.Fatal("ExtraConfig should not be nil")
	}
	if resp.ExtraConfig["tenant_id"] != "abc" {
		t.Errorf("ExtraConfig[tenant_id] = %v, want abc", resp.ExtraConfig["tenant_id"])
	}
}

func TestOIDCConfig_ToResponse_NilExtraConfig(t *testing.T) {
	cfg := &OIDCConfig{}
	resp := cfg.ToResponse()
	if resp.ExtraConfig != nil {
		t.Errorf("ExtraConfig should be nil for empty extra_config, got %v", resp.ExtraConfig)
	}
}

func TestOIDCConfig_ToResponse_CreatedByUpdatedBy(t *testing.T) {
	userID := uuid.New()
	cfg := &OIDCConfig{
		CreatedBy: uuid.NullUUID{UUID: userID, Valid: true},
		UpdatedBy: uuid.NullUUID{UUID: userID, Valid: true},
	}

	resp := cfg.ToResponse()
	if resp.CreatedBy == nil || *resp.CreatedBy != userID {
		t.Errorf("CreatedBy = %v, want %v", resp.CreatedBy, userID)
	}
	if resp.UpdatedBy == nil || *resp.UpdatedBy != userID {
		t.Errorf("UpdatedBy = %v, want %v", resp.UpdatedBy, userID)
	}
}

func TestOIDCConfig_ToResponse_NullCreatedByUpdatedBy(t *testing.T) {
	cfg := &OIDCConfig{}
	resp := cfg.ToResponse()
	if resp.CreatedBy != nil {
		t.Errorf("CreatedBy should be nil, got %v", resp.CreatedBy)
	}
	if resp.UpdatedBy != nil {
		t.Errorf("UpdatedBy should be nil, got %v", resp.UpdatedBy)
	}
}

// ---------------------------------------------------------------------------
// OIDCConfig.GetScopes
// ---------------------------------------------------------------------------

func TestOIDCConfig_GetScopes_Default(t *testing.T) {
	cfg := &OIDCConfig{}
	scopes := cfg.GetScopes()

	if len(scopes) != 3 {
		t.Fatalf("default scopes length = %d, want 3", len(scopes))
	}
	if scopes[0] != "openid" || scopes[1] != "email" || scopes[2] != "profile" {
		t.Errorf("scopes = %v, want [openid email profile]", scopes)
	}
}

func TestOIDCConfig_GetScopes_Custom(t *testing.T) {
	scopesJSON, _ := json.Marshal([]string{"openid", "groups", "offline_access"})
	cfg := &OIDCConfig{Scopes: scopesJSON}

	scopes := cfg.GetScopes()
	if len(scopes) != 3 {
		t.Fatalf("scopes length = %d, want 3", len(scopes))
	}
	if scopes[1] != "groups" {
		t.Errorf("scopes[1] = %q, want groups", scopes[1])
	}
}

func TestOIDCConfig_GetScopes_EmptyArray(t *testing.T) {
	scopesJSON, _ := json.Marshal([]string{})
	cfg := &OIDCConfig{Scopes: scopesJSON}

	scopes := cfg.GetScopes()
	// Empty array should return defaults
	if len(scopes) != 3 {
		t.Fatalf("empty scopes should return defaults, got %v", scopes)
	}
}

func TestOIDCConfig_GetScopes_InvalidJSON(t *testing.T) {
	cfg := &OIDCConfig{Scopes: []byte("{invalid")}
	scopes := cfg.GetScopes()
	// Invalid JSON should return defaults
	if len(scopes) != 3 {
		t.Fatalf("invalid JSON scopes should return defaults, got %v", scopes)
	}
}

// ---------------------------------------------------------------------------
// OIDCConfigResponse does not expose secrets
// ---------------------------------------------------------------------------

func TestOIDCConfig_ToResponse_NoSecrets(t *testing.T) {
	cfg := &OIDCConfig{
		ClientSecretEncrypted: "super-secret-encrypted-data",
	}

	resp := cfg.ToResponse()
	// Ensure the response type has no secret field — this is a compile-time check.
	// The OIDCConfigResponse struct simply omits ClientSecretEncrypted.
	data, _ := json.Marshal(resp)
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if _, found := raw["client_secret_encrypted"]; found {
		t.Error("response JSON must not contain client_secret_encrypted")
	}
	if _, found := raw["client_secret"]; found {
		t.Error("response JSON must not contain client_secret")
	}
}

// ---------------------------------------------------------------------------
// OIDCConfig.SetGroupMappingConfig / GetGroupMappingConfig
// ---------------------------------------------------------------------------

func TestSetGroupMappingConfig_RoundTrip(t *testing.T) {
	cfg := &OIDCConfig{}
	mappings := []OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "admin"},
		{Group: "viewers", Organization: "acme", Role: "readonly"},
	}
	if err := cfg.SetGroupMappingConfig("groups", mappings, "viewer"); err != nil {
		t.Fatalf("SetGroupMappingConfig error: %v", err)
	}

	cn, got, dr := cfg.GetGroupMappingConfig()
	if cn != "groups" {
		t.Errorf("claimName = %q, want groups", cn)
	}
	if dr != "viewer" {
		t.Errorf("defaultRole = %q, want viewer", dr)
	}
	if len(got) != 2 {
		t.Fatalf("mappings len = %d, want 2", len(got))
	}
	if got[0].Group != "admins" || got[0].Organization != "acme" || got[0].Role != "admin" {
		t.Errorf("mappings[0] = %+v", got[0])
	}
	if got[1].Group != "viewers" || got[1].Role != "readonly" {
		t.Errorf("mappings[1] = %+v", got[1])
	}
}

func TestSetGroupMappingConfig_PreservesExistingKeys(t *testing.T) {
	existingJSON, _ := json.Marshal(map[string]interface{}{"tenant_id": "abc"})
	cfg := &OIDCConfig{ExtraConfig: existingJSON}

	if err := cfg.SetGroupMappingConfig("groups", nil, ""); err != nil {
		t.Fatalf("SetGroupMappingConfig error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(cfg.ExtraConfig, &raw); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if raw["tenant_id"] != "abc" {
		t.Errorf("tenant_id was not preserved, got %v", raw["tenant_id"])
	}
	if raw["group_claim_name"] != "groups" {
		t.Errorf("group_claim_name = %v, want groups", raw["group_claim_name"])
	}
}

func TestSetGroupMappingConfig_EmptyValues(t *testing.T) {
	cfg := &OIDCConfig{}
	if err := cfg.SetGroupMappingConfig("", nil, ""); err != nil {
		t.Fatalf("SetGroupMappingConfig error: %v", err)
	}

	cn, mappings, dr := cfg.GetGroupMappingConfig()
	if cn != "" {
		t.Errorf("claimName = %q, want empty", cn)
	}
	if dr != "" {
		t.Errorf("defaultRole = %q, want empty", dr)
	}
	if len(mappings) != 0 {
		t.Errorf("mappings = %v, want empty", mappings)
	}
}

func TestGetGroupMappingConfig_EmptyExtraConfig(t *testing.T) {
	cfg := &OIDCConfig{}
	cn, mappings, dr := cfg.GetGroupMappingConfig()
	if cn != "" || dr != "" || len(mappings) != 0 {
		t.Errorf("expected zero values, got cn=%q dr=%q mappings=%v", cn, dr, mappings)
	}
}

func TestGetGroupMappingConfig_InvalidJSON(t *testing.T) {
	cfg := &OIDCConfig{ExtraConfig: []byte("{invalid")}
	cn, mappings, dr := cfg.GetGroupMappingConfig()
	if cn != "" || dr != "" || len(mappings) != 0 {
		t.Errorf("expected zero values on invalid JSON, got cn=%q dr=%q mappings=%v", cn, dr, mappings)
	}
}

func TestSetGroupMappingConfig_OverwritesPrevious(t *testing.T) {
	cfg := &OIDCConfig{}
	// Set initial config
	_ = cfg.SetGroupMappingConfig("groups", []OIDCGroupMapping{{Group: "old", Organization: "org", Role: "r"}}, "old-default")
	// Overwrite
	_ = cfg.SetGroupMappingConfig("roles", []OIDCGroupMapping{{Group: "new", Organization: "org2", Role: "admin"}}, "new-default")

	cn, mappings, dr := cfg.GetGroupMappingConfig()
	if cn != "roles" {
		t.Errorf("claimName = %q, want roles", cn)
	}
	if dr != "new-default" {
		t.Errorf("defaultRole = %q, want new-default", dr)
	}
	if len(mappings) != 1 || mappings[0].Group != "new" {
		t.Errorf("mappings = %v, want [{new org2 admin}]", mappings)
	}
}

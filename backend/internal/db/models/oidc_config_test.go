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

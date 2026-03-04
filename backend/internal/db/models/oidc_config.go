// Package models - oidc_config.go defines the OIDCConfig model for OIDC provider
// configuration stored encrypted in the database. Follows the same pattern as
// StorageConfig: sensitive fields use _encrypted suffix and are hidden from JSON.
package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OIDCConfig holds OIDC provider configuration stored in the database
type OIDCConfig struct {
	ID                    uuid.UUID       `db:"id" json:"id"`
	Name                  string          `db:"name" json:"name"`
	ProviderType          string          `db:"provider_type" json:"provider_type"`
	IssuerURL             string          `db:"issuer_url" json:"issuer_url"`
	ClientID              string          `db:"client_id" json:"client_id"`
	ClientSecretEncrypted string          `db:"client_secret_encrypted" json:"-"` // Never expose
	RedirectURL           string          `db:"redirect_url" json:"redirect_url"`
	Scopes                json.RawMessage `db:"scopes" json:"scopes"`
	IsActive              bool            `db:"is_active" json:"is_active"`
	ExtraConfig           json.RawMessage `db:"extra_config" json:"extra_config,omitempty"`
	CreatedAt             time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time       `db:"updated_at" json:"updated_at"`
	CreatedBy             uuid.NullUUID   `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy             uuid.NullUUID   `db:"updated_by" json:"updated_by,omitempty"`
}

// OIDCGroupMapping maps a single IdP group claim value to an organization and role template.
type OIDCGroupMapping struct {
	Group        string `json:"group"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
}

// OIDCConfigInput is used for creating/updating OIDC configuration via the API
type OIDCConfigInput struct {
	Name         string                 `json:"name,omitempty"`
	ProviderType string                 `json:"provider_type" binding:"required,oneof=generic_oidc azuread"`
	IssuerURL    string                 `json:"issuer_url" binding:"required"`
	ClientID     string                 `json:"client_id" binding:"required"`
	ClientSecret string                 `json:"client_secret" binding:"required"` // Plain text input, encrypted before storage
	RedirectURL  string                 `json:"redirect_url" binding:"required"`
	Scopes       []string               `json:"scopes,omitempty"`
	ExtraConfig  map[string]interface{} `json:"extra_config,omitempty"`
}

// OIDCGroupMappingInput is used for updating only the group mapping configuration.
// The client_secret is not required for this partial update.
type OIDCGroupMappingInput struct {
	GroupClaimName string             `json:"group_claim_name"`
	GroupMappings  []OIDCGroupMapping `json:"group_mappings"`
	DefaultRole    string             `json:"default_role"`
}

// OIDCConfigResponse is the API response for OIDC configuration (no secrets)
type OIDCConfigResponse struct {
	ID             uuid.UUID              `json:"id"`
	Name           string                 `json:"name"`
	ProviderType   string                 `json:"provider_type"`
	IssuerURL      string                 `json:"issuer_url"`
	ClientID       string                 `json:"client_id"`
	RedirectURL    string                 `json:"redirect_url"`
	Scopes         []string               `json:"scopes"`
	IsActive       bool                   `json:"is_active"`
	GroupClaimName string                 `json:"group_claim_name,omitempty"`
	GroupMappings  []OIDCGroupMapping     `json:"group_mappings,omitempty"`
	DefaultRole    string                 `json:"default_role,omitempty"`
	ExtraConfig    map[string]interface{} `json:"extra_config,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	CreatedBy      *uuid.UUID             `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID             `json:"updated_by,omitempty"`
}

// groupMappingExtra is the shape of the group-mapping keys inside ExtraConfig.
type groupMappingExtra struct {
	GroupClaimName string             `json:"group_claim_name"`
	GroupMappings  []OIDCGroupMapping `json:"group_mappings"`
	DefaultRole    string             `json:"default_role"`
}

// GetGroupMappingConfig reads group mapping settings from ExtraConfig.
func (c *OIDCConfig) GetGroupMappingConfig() (claimName string, mappings []OIDCGroupMapping, defaultRole string) {
	if len(c.ExtraConfig) == 0 {
		return
	}
	var extra groupMappingExtra
	if err := json.Unmarshal(c.ExtraConfig, &extra); err != nil {
		return
	}
	return extra.GroupClaimName, extra.GroupMappings, extra.DefaultRole
}

// SetGroupMappingConfig stores group mapping settings into ExtraConfig, preserving
// any unrelated keys that may already be present.
func (c *OIDCConfig) SetGroupMappingConfig(claimName string, mappings []OIDCGroupMapping, defaultRole string) error {
	// Decode existing extra config to preserve unknown keys.
	existing := make(map[string]interface{})
	if len(c.ExtraConfig) > 0 {
		if err := json.Unmarshal(c.ExtraConfig, &existing); err != nil {
			return err
		}
	}
	existing["group_claim_name"] = claimName
	existing["group_mappings"] = mappings
	existing["default_role"] = defaultRole
	b, err := json.Marshal(existing)
	if err != nil {
		return err
	}
	c.ExtraConfig = json.RawMessage(b)
	return nil
}

// ToResponse converts an OIDCConfig to a safe API response (no secrets)
func (c *OIDCConfig) ToResponse() *OIDCConfigResponse {
	resp := &OIDCConfigResponse{
		ID:           c.ID,
		Name:         c.Name,
		ProviderType: c.ProviderType,
		IssuerURL:    c.IssuerURL,
		ClientID:     c.ClientID,
		RedirectURL:  c.RedirectURL,
		IsActive:     c.IsActive,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}

	// Parse scopes from JSONB
	if len(c.Scopes) > 0 {
		_ = json.Unmarshal(c.Scopes, &resp.Scopes) // nolint:errcheck
	}
	if resp.Scopes == nil {
		resp.Scopes = []string{"openid", "email", "profile"}
	}

	// Parse extra config from JSONB — expose group mapping as first-class fields
	if len(c.ExtraConfig) > 0 {
		_ = json.Unmarshal(c.ExtraConfig, &resp.ExtraConfig) // nolint:errcheck
		resp.GroupClaimName, resp.GroupMappings, resp.DefaultRole = c.GetGroupMappingConfig()
	}

	if c.CreatedBy.Valid {
		resp.CreatedBy = &c.CreatedBy.UUID
	}
	if c.UpdatedBy.Valid {
		resp.UpdatedBy = &c.UpdatedBy.UUID
	}

	return resp
}

// GetScopes parses and returns the scopes as a string slice
func (c *OIDCConfig) GetScopes() []string {
	var scopes []string
	if len(c.Scopes) > 0 {
		_ = json.Unmarshal(c.Scopes, &scopes) // nolint:errcheck
	}
	if len(scopes) == 0 {
		return []string{"openid", "email", "profile"}
	}
	return scopes
}

// SetupStatus represents the enhanced setup status response
type SetupStatus struct {
	SetupCompleted      bool           `json:"setup_completed"`
	StorageConfigured   bool           `json:"storage_configured"`
	OIDCConfigured      bool           `json:"oidc_configured"`
	AdminConfigured     bool           `json:"admin_configured"`
	SetupRequired       bool           `json:"setup_required"`
	StorageConfiguredAt *time.Time     `json:"storage_configured_at,omitempty"`
	AdminEmail          sql.NullString `json:"-"`
}

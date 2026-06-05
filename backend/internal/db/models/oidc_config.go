// Package models - oidc_config.go aliases the persisted OIDCConfig identity type
// from the shared module and keeps the registry's API/setup DTOs (request,
// response, LDAP, setup status) app-side. ToResponse becomes a free function
// because methods cannot be attached to an aliased type.
package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

// OIDCConfig holds OIDC provider configuration stored in the database.
type OIDCConfig = identitymodels.OIDCConfig

// OIDCGroupMapping maps a single IdP group claim value to an organization and role
// template. It mirrors the identity type but is defined locally so swagger can
// document it (swag cannot resolve type aliases into the external identity
// module). Convert with ToIdentityGroupMappings / fromIdentityGroupMappings.
type OIDCGroupMapping struct {
	Group        string `json:"group"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
}

// ToIdentityGroupMappings converts API/registry group mappings to the identity
// model type accepted by OIDCConfig.SetGroupMappingConfig.
func ToIdentityGroupMappings(in []OIDCGroupMapping) []identitymodels.OIDCGroupMapping {
	out := make([]identitymodels.OIDCGroupMapping, len(in))
	for i, m := range in {
		out[i] = identitymodels.OIDCGroupMapping{Group: m.Group, Organization: m.Organization, Role: m.Role}
	}
	return out
}

// fromIdentityGroupMappings converts identity group mappings to the local type.
func fromIdentityGroupMappings(in []identitymodels.OIDCGroupMapping) []OIDCGroupMapping {
	out := make([]OIDCGroupMapping, len(in))
	for i, m := range in {
		out[i] = OIDCGroupMapping{Group: m.Group, Organization: m.Organization, Role: m.Role}
	}
	return out
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

// LDAPConfigInput is used for configuring LDAP authentication via the setup wizard.
type LDAPConfigInput struct {
	Host               string `json:"host" binding:"required"`
	Port               int    `json:"port"`
	UseTLS             bool   `json:"use_tls"`
	StartTLS           bool   `json:"start_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	BindDN             string `json:"bind_dn" binding:"required"`
	BindPassword       string `json:"bind_password" binding:"required"`
	BaseDN             string `json:"base_dn" binding:"required"`
	UserFilter         string `json:"user_filter" binding:"required"`
	UserAttrEmail      string `json:"user_attr_email"`
	UserAttrName       string `json:"user_attr_name"`
	GroupBaseDN        string `json:"group_base_dn"`
	GroupFilter        string `json:"group_filter"`
	GroupMemberAttr    string `json:"group_member_attr"`
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

// OIDCConfigToResponse converts an OIDCConfig to a safe API response (no secrets).
func OIDCConfigToResponse(c *OIDCConfig) *OIDCConfigResponse {
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
		var mappings []identitymodels.OIDCGroupMapping
		resp.GroupClaimName, mappings, resp.DefaultRole = c.GetGroupMappingConfig()
		resp.GroupMappings = fromIdentityGroupMappings(mappings)
	}

	if c.CreatedBy.Valid {
		resp.CreatedBy = &c.CreatedBy.UUID
	}
	if c.UpdatedBy.Valid {
		resp.UpdatedBy = &c.UpdatedBy.UUID
	}

	return resp
}

// SetupStatus represents the enhanced setup status response
type SetupStatus struct {
	SetupCompleted      bool           `json:"setup_completed"`
	StorageConfigured   bool           `json:"storage_configured"`
	OIDCConfigured      bool           `json:"oidc_configured"`
	AdminConfigured     bool           `json:"admin_configured"`
	ScanningConfigured  bool           `json:"scanning_configured"`
	LDAPConfigured      bool           `json:"ldap_configured"`
	AuthMethod          string         `json:"auth_method"`
	SetupRequired       bool           `json:"setup_required"`
	PendingFeatureSetup bool           `json:"pending_feature_setup"`
	StorageConfiguredAt *time.Time     `json:"storage_configured_at,omitempty"`
	AdminEmail          sql.NullString `json:"-"`
}

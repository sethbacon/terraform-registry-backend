package admin

import "time"

// MessageResponse is returned by action endpoints that confirm success with a plain message.
// Used by delete, unlink, revoke, and similar operations.
type MessageResponse struct {
	Message string `json:"message"`
}

// RefreshResponse is returned by POST /api/v1/auth/refresh.
type RefreshResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// MeUserInfo contains the user fields returned by GET /api/v1/auth/me.
type MeUserInfo struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MeMembershipEntry describes one organisation membership in the /me response.
type MeMembershipEntry struct {
	OrganizationID          string    `json:"organization_id"`
	OrganizationName        string    `json:"organization_name"`
	RoleTemplateID          *string   `json:"role_template_id"`
	RoleTemplateName        *string   `json:"role_template_name"`
	RoleTemplateDisplayName *string   `json:"role_template_display_name"`
	RoleTemplateScopes      []string  `json:"role_template_scopes"`
	CreatedAt               time.Time `json:"created_at"`
}

// MeResponse is returned by GET /api/v1/auth/me.
type MeResponse struct {
	User          MeUserInfo          `json:"user"`
	Memberships   []MeMembershipEntry `json:"memberships"`
	AllowedScopes []string            `json:"allowed_scopes"`
	RoleTemplate  interface{}         `json:"role_template"`
}

// APIKeyItem represents a single API key in list/get responses.
type APIKeyItem struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	UserName    string     `json:"user_name"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	KeyPrefix   string     `json:"key_prefix"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ListAPIKeysResponse is returned by GET /api/v1/apikeys.
type ListAPIKeysResponse struct {
	Keys []APIKeyItem `json:"keys"`
}

// APIKeyResponse wraps a single API key for get/update responses.
type APIKeyResponse struct {
	Key APIKeyItem `json:"key"`
}

// ListMirrorConfigsResponse is returned by GET /api/v1/admin/mirrors.
type ListMirrorConfigsResponse struct {
	Mirrors interface{} `json:"mirrors"`
}

// TokenRefreshResponse is returned by POST /api/v1/scm-providers/{id}/oauth/refresh.
type TokenRefreshResponse struct {
	Message   string     `json:"message"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// SCMTokenStatusResponse is returned by GET /api/v1/scm-providers/{id}/oauth/token.
type SCMTokenStatusResponse struct {
	Connected   bool       `json:"connected"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	TokenType   string     `json:"token_type,omitempty"`
}

// OAuthAuthorizeResponse is returned by GET /api/v1/scm-providers/{id}/oauth/authorize
// when the provider uses standard OAuth (as opposed to PAT-based auth).
type OAuthAuthorizeResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// PATAuthorizeResponse is returned when the provider requires a Personal Access Token.
type PATAuthorizeResponse struct {
	AuthMethod string `json:"auth_method"`
	Message    string `json:"message"`
}

// ListRepositoriesResponse is returned by GET /api/v1/scm-providers/{id}/repositories.
type ListRepositoriesResponse struct {
	Repositories interface{} `json:"repositories"`
}

// ListTagsResponse is returned by GET /api/v1/scm-providers/{id}/repositories/{owner}/{repo}/tags.
type ListTagsResponse struct {
	Tags interface{} `json:"tags"`
}

// ListBranchesResponse is returned by GET /api/v1/scm-providers/{id}/repositories/{owner}/{repo}/branches.
type ListBranchesResponse struct {
	Branches interface{} `json:"branches"`
}

// PaginationMeta carries page / per_page / total counts used in paginated list responses.
type PaginationMeta struct {
	Page    int   `json:"page"`
	PerPage int   `json:"per_page"`
	Total   int64 `json:"total,omitempty"`
}

// UserItem is the shape of a user in list/get/create/update responses.
type UserItem struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListUsersResponse is returned by GET /api/v1/users and GET /api/v1/users/search.
type ListUsersResponse struct {
	Users      []UserItem     `json:"users"`
	Pagination PaginationMeta `json:"pagination"`
}

// UserWithOrgsResponse is returned by GET /api/v1/users/{id}.
type UserWithOrgsResponse struct {
	User          UserItem    `json:"user"`
	Organizations interface{} `json:"organizations"`
}

// UserResponse is returned by POST /api/v1/users and PUT /api/v1/users/{id}.
type UserResponse struct {
	User UserItem `json:"user"`
}

// UserMembershipsResponse is returned by GET /api/v1/users/{id}/memberships and GET /api/v1/users/me/memberships.
type UserMembershipsResponse struct {
	Memberships interface{} `json:"memberships"`
}

// ListOrganizationsResponse is returned by GET /api/v1/organizations and GET /api/v1/organizations/search.
type ListOrganizationsResponse struct {
	Organizations interface{}    `json:"organizations"`
	Pagination    PaginationMeta `json:"pagination"`
}

// OrganizationWithMembersResponse is returned by GET /api/v1/organizations/{id}.
type OrganizationWithMembersResponse struct {
	Organization interface{} `json:"organization"`
	Members      interface{} `json:"members"`
}

// OrganizationMembersResponse is returned by GET /api/v1/organizations/{id}/members.
type OrganizationMembersResponse struct {
	Members interface{} `json:"members"`
}

// OrganizationResponse is returned by POST and PUT /api/v1/organizations.
type OrganizationResponse struct {
	Organization interface{} `json:"organization"`
}

// MemberResponse is returned by POST and PUT /api/v1/organizations/{id}/members.
type MemberResponse struct {
	Member interface{} `json:"member"`
}

// DeleteTerraformMirrorResponse is returned by DELETE /api/v1/admin/terraform-mirrors/{id}.
type DeleteTerraformMirrorResponse struct {
	Message string `json:"message"`
	ID      string `json:"id"`
	Name    string `json:"name"`
}

// TerraformMirrorSyncResponse is returned by POST /api/v1/admin/terraform-mirrors/{id}/sync.
type TerraformMirrorSyncResponse struct {
	Message     string    `json:"message"`
	ConfigID    string    `json:"config_id"`
	TriggeredAt time.Time `json:"triggered_at"`
}

// DeleteTerraformVersionResponse is returned by DELETE /api/v1/admin/terraform-mirrors/{id}/versions/{version}.
type DeleteTerraformVersionResponse struct {
	Message string `json:"message"`
	Version string `json:"version"`
}

// WebhookEventsResponse is returned by GET /api/v1/admin/modules/{id}/scm/events.
type WebhookEventsResponse struct {
	Events interface{} `json:"events"`
}

// ActivateStorageConfigResponse is returned by POST /api/v1/storage/configs/{id}/activate.
type ActivateStorageConfigResponse struct {
	Message string      `json:"message"`
	Config  interface{} `json:"config"`
}

// StorageTestResponse is returned by POST /api/v1/storage/configs/test.
type StorageTestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ModuleVersionItem represents a version entry inside a module detail response.
type ModuleVersionItem struct {
	ID                 string      `json:"id"`
	Version            string      `json:"version"`
	DownloadCount      int64       `json:"download_count"`
	Deprecated         bool        `json:"deprecated"`
	DeprecatedAt       interface{} `json:"deprecated_at,omitempty"`
	DeprecationMessage interface{} `json:"deprecation_message,omitempty"`
	CreatedAt          time.Time   `json:"created_at"`
}

// ModuleDetailResponse is returned by GET /api/v1/modules/{namespace}/{name}/{system}.
type ModuleDetailResponse struct {
	ID            string              `json:"id"`
	Namespace     string              `json:"namespace"`
	Name          string              `json:"name"`
	System        string              `json:"system"`
	Description   string              `json:"description,omitempty"`
	Source        string              `json:"source,omitempty"`
	DownloadCount int64               `json:"download_count"`
	Versions      []ModuleVersionItem `json:"versions"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

// ProviderPlatformItem represents a platform entry inside a provider version.
type ProviderPlatformItem struct {
	ID            string `json:"id"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Filename      string `json:"filename"`
	Shasum        string `json:"shasum"`
	DownloadCount int64  `json:"download_count"`
}

// ProviderVersionItem represents a version entry inside a provider detail response.
type ProviderVersionItem struct {
	ID                 string                 `json:"id"`
	Version            string                 `json:"version"`
	Protocols          []string               `json:"protocols"`
	Platforms          []ProviderPlatformItem `json:"platforms"`
	Deprecated         bool                   `json:"deprecated"`
	DeprecatedAt       interface{}            `json:"deprecated_at,omitempty"`
	DeprecationMessage interface{}            `json:"deprecation_message,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
}

// ProviderDetailResponse is returned by GET /api/v1/providers/{namespace}/{type}.
type ProviderDetailResponse struct {
	ID          string                `json:"id"`
	Namespace   string                `json:"namespace"`
	Type        string                `json:"type"`
	Description string                `json:"description,omitempty"`
	Source      string                `json:"source,omitempty"`
	Versions    []ProviderVersionItem `json:"versions"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

// MirroredPlatformSummary describes a single platform entry in the ListMirroredProviders response.
type MirroredPlatformSummary struct {
	ID                string `json:"id"`
	ProviderVersionID string `json:"provider_version_id"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	Filename          string `json:"filename"`
	Shasum            string `json:"shasum"`
}

// MirroredVersionSummary describes a provider version with its platforms in the ListMirroredProviders response.
type MirroredVersionSummary struct {
	ID                 string                    `json:"id"`
	MirroredProviderID string                    `json:"mirrored_provider_id"`
	ProviderVersionID  string                    `json:"provider_version_id"`
	UpstreamVersion    string                    `json:"upstream_version"`
	SyncedAt           time.Time                 `json:"synced_at"`
	Platforms          []MirroredPlatformSummary `json:"platforms"`
}

// MirroredProviderSummary describes a provider with its versions in the ListMirroredProviders response.
type MirroredProviderSummary struct {
	ID                string                   `json:"id"`
	MirrorConfigID    string                   `json:"mirror_config_id"`
	ProviderID        string                   `json:"provider_id"`
	UpstreamNamespace string                   `json:"upstream_namespace"`
	UpstreamType      string                   `json:"upstream_type"`
	LastSyncedAt      time.Time                `json:"last_synced_at"`
	SyncEnabled       bool                     `json:"sync_enabled"`
	CreatedAt         time.Time                `json:"created_at"`
	Versions          []MirroredVersionSummary `json:"versions"`
}

// ListMirroredProvidersResponse is returned by GET /api/v1/admin/mirrors/{id}/providers.
type ListMirroredProvidersResponse struct {
	Providers []MirroredProviderSummary `json:"providers"`
}

// AuditLogResponse represents a single audit log entry in list or get responses.
type AuditLogResponse struct {
	ID             string                 `json:"id"`
	UserID         *string                `json:"user_id"`
	UserEmail      *string                `json:"user_email"`
	UserName       *string                `json:"user_name"`
	OrganizationID *string                `json:"organization_id"`
	Action         string                 `json:"action"`
	ResourceType   *string                `json:"resource_type"`
	ResourceID     *string                `json:"resource_id"`
	Metadata       map[string]interface{} `json:"metadata"`
	IPAddress      *string                `json:"ip_address"`
	CreatedAt      time.Time              `json:"created_at"`
}

// AuditLogListResponse is returned by GET /api/v1/admin/audit-logs.
type AuditLogListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Pagination PaginationMeta     `json:"pagination"`
}

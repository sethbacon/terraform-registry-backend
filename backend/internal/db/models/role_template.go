// Package models - role_template.go aliases the RoleTemplate type from the shared
// identity module and keeps the registry's predefined role→scope mapping. The
// role→scope mapping is the one piece of identity that is app-specific; the
// shared module is app-agnostic about scope contents.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

// RoleTemplate is a named set of RBAC scopes assignable to organization members.
type RoleTemplate = identitymodels.RoleTemplate

// PredefinedRoleTemplates returns the registry's default role templates.
func PredefinedRoleTemplates() []RoleTemplate {
	viewerDesc := "Read-only access to modules, providers, mirrors, organizations, and SCM configurations"
	publisherDesc := "Can upload and manage modules and providers"
	devOpsDesc := "Can manage SCM integrations and provider mirroring for CI/CD pipelines"
	adminDesc := "Full access to all registry features"
	userManagerDesc := "Can manage user accounts and memberships"
	auditorDesc := "Read-only access with audit log visibility for security and compliance review"
	orgOwnerDesc := "Full management of a single organization's modules, providers, mirrors, SCM integrations, and membership, without platform-wide admin privileges"
	orgProvisionerDesc := "Can provision new top-level organizations without platform-wide admin privileges"

	return []RoleTemplate{
		{
			Name:        "viewer",
			DisplayName: "Viewer",
			Description: &viewerDesc,
			Scopes:      []string{"modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read"},
			IsSystem:    true,
		},
		{
			Name:        "publisher",
			DisplayName: "Publisher",
			Description: &publisherDesc,
			Scopes:      []string{"modules:read", "modules:write", "providers:read", "providers:write", "organizations:read", "scm:read"},
			IsSystem:    true,
		},
		{
			Name:        "devops",
			DisplayName: "DevOps",
			Description: &devOpsDesc,
			Scopes:      []string{"modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "organizations:read", "scm:read", "scm:manage"},
			IsSystem:    true,
		},
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: &adminDesc,
			Scopes:      []string{"admin"},
			IsSystem:    true,
		},
		{
			Name:        "user_manager",
			DisplayName: "User Manager",
			Description: &userManagerDesc,
			Scopes:      []string{"users:read", "users:write", "organizations:read", "organizations:write", "api_keys:manage", "modules:read", "providers:read"},
			IsSystem:    true,
		},
		{
			Name:        "auditor",
			DisplayName: "Auditor",
			Description: &auditorDesc,
			Scopes:      []string{"modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read", "audit:read"},
			IsSystem:    true,
		},
		{
			Name:        "org_owner",
			DisplayName: "Organization Owner",
			Description: &orgOwnerDesc,
			Scopes:      []string{"organizations:write", "users:read", "api_keys:manage", "modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "scm:read", "scm:manage"},
			IsSystem:    true,
		},
		{
			Name:        "org_provisioner",
			DisplayName: "Organization Provisioner",
			Description: &orgProvisionerDesc,
			Scopes:      []string{"organizations:create", "organizations:read"},
			IsSystem:    true,
		},
	}
}

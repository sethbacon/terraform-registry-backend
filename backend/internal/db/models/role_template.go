// Package models - role_template.go aliases the RoleTemplate type from the shared
// identity module and keeps the registry's predefined role→scope mapping. The
// role→scope mapping is the one piece of identity that is app-specific; the
// shared module is app-agnostic about scope contents.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

// RoleTemplate is a named set of RBAC scopes assignable to organization members.
type RoleTemplate = identitymodels.RoleTemplate

// PredefinedRoleTemplates returns the registry's default role templates.
//
// THIS LIST AND THE MIGRATIONS ARE TWO STATEMENTS OF ONE POLICY, and they must
// not disagree. Registry says who may do what twice: here, and as SQL in
// migration 000001's seed plus every migration that has amended it since. Only
// one of the two is exercised in any given topology -- the migrations own the
// default one, this list owns the identity-schema cutover -- so a disagreement
// produces no error anywhere and simply changes what a role confers.
//
// BOTH SEEDS UPSERT THIS LIST WITH `scopes = EXCLUDED.scopes`, so whichever way
// the two drift, this list wins wherever it runs:
//
//   - repositories.SeedSystemRoleTemplates writes registry's own
//     `registry_role_templates`, which is what every authorization decision in
//     this application reads since terraform-suite-identity#206 phase 3b.
//   - repositories.SeedSharedIdentityRoleTemplates writes the shared
//     `role_templates`. Registry no longer reads it; the STATE MANAGER adopts
//     from it every role name it does not define itself (`devops` and `auditor`
//     among them), and it is the surface a rollback to the previous image reads.
//
// Issue #891 was that drift, in the direction that REMOVES authority: migration
// 000018 granted `scanning:read` to `devops` and `auditor`, this list never
// learned it, and every boot in the cutover topology took it back off both
// templates in both tables. The mirror-image drift -- a scope here that no
// migration ever granted -- would silently widen a role instead, which does not
// fail safe.
//
// internal/db/rolepolicy is the guard. It replays the role-template DML out of
// the migration files and a test diffs the result against this function in both
// directions, so a migration that changes a template's scopes without this list
// following cannot reach main. Nothing in it is a hand-written list of scopes:
// it derives them, so it covers the migration that lands tomorrow rather than
// the one that prompted it.
func PredefinedRoleTemplates() []RoleTemplate {
	viewerDesc := "Read-only access to modules, providers, mirrors, organizations, and SCM configurations"
	publisherDesc := "Can upload and manage modules and providers"
	devOpsDesc := "Can manage SCM integrations and provider mirroring for CI/CD pipelines"
	// The `admin` template NO LONGER CARRIES THE `admin` SCOPE (issue #766,
	// migration 000054). Platform-admin authority lives in the platform_admins
	// carrier and nowhere else; a role template that claimed it would confer
	// nothing (the auth middleware strips it) and would be refused by every
	// membership write.
	//
	// This list is not decoration: both seeds upsert it by name on boot in the
	// identity-schema cutover, so leaving `admin` here would put the scope back
	// on the template the migration just cleaned, on the next restart, for
	// exactly the deployments the migration could reach least well.
	//
	// The scopes are the `org_owner` set, matching what migration 000054 writes:
	// everything the template conferred except the platform-wide reach, so its
	// existing holders keep administering their organizations.
	adminDesc := "Full management of an organization's modules, providers, mirrors, SCM integrations, " +
		"and membership. Platform-wide administration is granted through POST /api/v1/admin/platform-admins (issue #766)"
	userManagerDesc := "Can manage user accounts and memberships"
	// `devops` and `auditor` carry `scanning:read` because migration 000018
	// granted it to both -- long before the identity-schema cutover existed -- and
	// this list did not follow (issue #891). It has to be stated here as well as
	// there, because in the cutover topology the seed, not the migration, is what
	// reaches the tables these roles are read from.
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
			Scopes:      []string{"modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "organizations:read", "scm:read", "scm:manage", "scanning:read"},
			IsSystem:    true,
		},
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: &adminDesc,
			Scopes: []string{"organizations:write", "users:read", "api_keys:manage", "modules:read", "modules:write",
				"providers:read", "providers:write", "mirrors:read", "mirrors:manage", "scm:read", "scm:manage"},
			IsSystem: true,
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
			Scopes:      []string{"modules:read", "providers:read", "mirrors:read", "organizations:read", "scm:read", "audit:read", "scanning:read"},
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

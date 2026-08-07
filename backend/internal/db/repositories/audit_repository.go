// Package repositories - audit_repository.go aliases the AuditRepository, its
// AuditFilters type and the mandatory OrgScope from the shared identity store.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

type (
	// AuditRepository handles audit log database operations.
	AuditRepository = identitystore.AuditRepository
	// AuditFilters narrows an audit log listing.
	AuditFilters = identitystore.AuditFilters
	// OrgScope is the MANDATORY tenant constraint on every accessor in the
	// shared identity store that reads or mutates an organization-owned row —
	// audit logs, API keys, organizations, memberships and users alike (it was
	// AuditScope, named for the single table it started on, before v0.25.0).
	// Aliased here alongside the repositories so handlers reach it the same way
	// they reach everything else in this layer; its zero value denies
	// everything (see the shared module's org_scope.go).
	OrgScope = identitystore.OrgScope
)

// NewAuditRepository constructs an AuditRepository over the given connection.
var NewAuditRepository = identitystore.NewAuditRepository

// Organization scope constructors, re-exported so no consumer has to import
// the identity store directly just to name its own tenancy.
var (
	// OrgScopeOrganizations limits an accessor to the given organizations.
	OrgScopeOrganizations = identitystore.OrgScopeOrganizations
	// OrgScopeOrganizationsAndUnowned additionally admits rows with no owning
	// organization. Not used by this registry — see the note on
	// AuditLogHandlers.auditScope for why NULL means "unattributed" here, and
	// tenantscope.Scope.Permits for the same contract on the registry's own
	// tables — but re-exported so the choice is visible next to the one that
	// was made.
	OrgScopeOrganizationsAndUnowned = identitystore.OrgScopeOrganizationsAndUnowned
	// OrgScopeAllOrganizations is the explicit, deliberate platform-wide access.
	OrgScopeAllOrganizations = identitystore.OrgScopeAllOrganizations
)

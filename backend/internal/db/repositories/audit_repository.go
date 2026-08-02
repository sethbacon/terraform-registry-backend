// Package repositories - audit_repository.go aliases the AuditRepository, its
// AuditFilters type and the mandatory AuditScope from the shared identity
// store.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

type (
	// AuditRepository handles audit log database operations.
	AuditRepository = identitystore.AuditRepository
	// AuditFilters narrows an audit log listing.
	AuditFilters = identitystore.AuditFilters
	// AuditScope is the MANDATORY tenant constraint on every audit-log read.
	// Aliased here alongside the repository so handlers reach it the same way
	// they reach everything else in this layer; its zero value denies
	// everything (see the shared module's audit_scope.go).
	AuditScope = identitystore.AuditScope
)

// NewAuditRepository constructs an AuditRepository over the given connection.
var NewAuditRepository = identitystore.NewAuditRepository

// Audit scope constructors, re-exported so no consumer has to import the
// identity store directly just to name its own tenancy.
var (
	// AuditScopeOrganizations limits a read to the given organizations.
	AuditScopeOrganizations = identitystore.AuditScopeOrganizations
	// AuditScopeOrganizationsAndUnowned additionally admits rows with no
	// owning organization. Not used by this registry — see the note on
	// AuditLogHandlers.auditScope for why NULL means "unattributed" here — but
	// re-exported so the choice is visible next to the one that was made.
	AuditScopeOrganizationsAndUnowned = identitystore.AuditScopeOrganizationsAndUnowned
	// AuditScopeAllOrganizations is the explicit, deliberate platform-wide read.
	AuditScopeAllOrganizations = identitystore.AuditScopeAllOrganizations
)

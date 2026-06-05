// Package repositories - audit_repository.go aliases the AuditRepository and its
// AuditFilters type from the shared identity store.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

type (
	// AuditRepository handles audit log database operations.
	AuditRepository = identitystore.AuditRepository
	// AuditFilters narrows an audit log listing.
	AuditFilters = identitystore.AuditFilters
)

// NewAuditRepository constructs an AuditRepository over the given connection.
var NewAuditRepository = identitystore.NewAuditRepository

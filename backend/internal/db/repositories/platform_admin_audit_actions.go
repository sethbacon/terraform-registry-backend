// platform_admin_audit_actions.go holds the audit vocabulary that migration
// 000052's constraint trigger pins.
//
// The trigger does not merely require *an* intent — it requires one naming this
// subject with THIS action ('platform_admin.granted' on an INSERT,
// 'platform_admin.revoked' on a DELETE), so that a revocation cannot be
// committed under a grant's record. A caller that spells the action differently
// does not get a wrong audit entry; it gets a failed COMMIT.
//
// That made the strings load-bearing across package boundaries the moment the
// carrier acquired callers outside internal/api/admin: the setup wizard's
// bootstrap grant (internal/api/setup) and the two lifecycle cleanups that
// retire a destroyed principal's grant (internal/api/admin/users.go and
// internal/services/user_service.go, issue #766). Three packages retyping a
// literal that only fails at COMMIT is the shape this file removes.
//
// They live in `repositories` rather than in internal/audit because that is
// where the rest of the carrier-mutation contract already is — AuditIntentWriter
// and ErrAuditIntentRequired, in audit_intent.go — and because every one of
// those callers already imports this package for the repository itself.
package repositories

const (
	// AuditActionPlatformAdminGranted is the action migration 000052's trigger
	// requires on an INSERT into platform_admins.
	AuditActionPlatformAdminGranted = "platform_admin.granted"

	// AuditActionPlatformAdminRevoked is the action it requires on a DELETE.
	AuditActionPlatformAdminRevoked = "platform_admin.revoked"

	// AuditResourcePlatformAdmin is the resource_type it matches on.
	AuditResourcePlatformAdmin = "platform_admin"
)

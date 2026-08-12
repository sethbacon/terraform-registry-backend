// platform_admin_repository.go reads the platform-admin carrier — the grant
// table that holds platform-admin authority outside `organization_members`
// (issue #766, migration 000051).
//
// Until this table existed the only carrier for the `admin` wildcard was a
// membership row pointing at an admin-bearing role template, which the org-less
// scope union promotes to platform-wide authority the moment it is held
// anywhere. This repository is the read side of the replacement.
//
// PER REQUEST, NOT IN THE TOKEN. The middleware calls this on every
// user-session request rather than freezing a `platform_admin` claim into the
// JWT. That is the same decision this estate reached for api_keys' frozen
// organization_id (#732) and frozen scopes (#733): a 24-hour session would
// otherwise carry the highest privilege in the product for up to 24 hours
// after it was revoked. One indexed read on a table with a handful of rows
// buys immediate revocation.
//
// The table lives on the registry's own (public-schema) connection, not the
// identity connection, so it works unchanged whether identity data is in the
// app's public schema, the shared identity schema, or a separate identity
// database — the same placement and the same reasoning as
// UserTokenRevocationRepository (issue #559 finding [9]).
//
// Grant and revoke are deliberately absent: PR 1 ships the carrier and the
// read path only. The management surface is PR 2.
package repositories

import (
	"context"
	"database/sql"
)

// PlatformAdminRepository reads the platform-admin carrier.
type PlatformAdminRepository struct {
	db *sql.DB
}

// NewPlatformAdminRepository constructs a PlatformAdminRepository over the
// registry's domain connection.
func NewPlatformAdminRepository(db *sql.DB) *PlatformAdminRepository {
	return &PlatformAdminRepository{db: db}
}

// IsPlatformAdmin reports whether the user holds platform-admin authority
// through the carrier.
//
// An empty userID answers false WITHOUT querying. Not a micro-optimisation:
// user_id is UUID, so an empty string reaches Postgres as an invalid-input
// error, and the caller — an authorization path — must not have to tell a
// malformed principal apart from a database fault. "No principal" is a clean
// no, and the fail-closed direction.
//
// Any other error is returned rather than swallowed. This is a GRANT-direction
// lookup, so a failure can only ever withhold authority, never widen it; the
// callers decide whether an unresolved answer aborts the request or merely
// leaves the caller unelevated.
func (r *PlatformAdminRepository) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	const query = `SELECT EXISTS(SELECT 1 FROM platform_admins WHERE user_id = $1)`
	var isAdmin bool
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}

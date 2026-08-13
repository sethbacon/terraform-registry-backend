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
// PR 2 (issue #766) adds the write side — List/Grant/Revoke — behind the
// management API in internal/api/admin/platform_admins.go. The read path above
// is unchanged by it.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Sentinels for the two carrier states a caller has to tell apart from a
// database fault. Returned as values, not as "zero rows and a nil error", so a
// handler cannot map a silent no-op onto a success.
var (
	// ErrAlreadyPlatformAdmin is returned by Grant when the user already holds
	// a carrier row. The existing row is left ALONE rather than overwritten:
	// granted_by/granted_at/note are the provenance this table exists to keep,
	// and a re-grant that rewrote them would erase who originally conferred the
	// highest privilege in the product.
	ErrAlreadyPlatformAdmin = errors.New("user already holds platform-admin")

	// ErrNotPlatformAdmin is returned by Revoke when there is no carrier row to
	// remove.
	ErrNotPlatformAdmin = errors.New("user does not hold platform-admin")
)

// PlatformAdminGrant is one row of the carrier.
type PlatformAdminGrant struct {
	UserID    string
	GrantedBy *string
	GrantedAt time.Time
	Note      *string
}

// PlatformAdminRepository reads and writes the platform-admin carrier.
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

// grantColumns is the projection every accessor below reads, in one place so
// the three scan sites cannot drift apart.
const grantColumns = `user_id, granted_by, granted_at, note`

func scanGrant(s interface{ Scan(...any) error }) (*PlatformAdminGrant, error) {
	g := &PlatformAdminGrant{}
	if err := s.Scan(&g.UserID, &g.GrantedBy, &g.GrantedAt, &g.Note); err != nil {
		return nil, err
	}
	return g, nil
}

// List returns every carrier row, oldest grant first.
//
// UNFILTERED, AND THAT IS THE POINT. A grant whose user no longer resolves is
// still returned: the caller (internal/api/admin/platform_admins.go) labels it
// rather than dropping it. Filtering here would make a live row invisible to
// the only surface that can remove it, which is the failure mode migration
// 000050 was written to clean up after on api_keys.
func (r *PlatformAdminRepository) List(ctx context.Context) ([]PlatformAdminGrant, error) {
	query := `SELECT ` + grantColumns + ` FROM platform_admins ORDER BY granted_at ASC, user_id ASC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grants := make([]PlatformAdminGrant, 0)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

// Grant records platform-admin authority for userID.
//
// Returns ErrAlreadyPlatformAdmin when the user already holds a carrier row —
// ON CONFLICT DO NOTHING, so the original provenance survives a re-grant. The
// caller turns that into a 409 rather than a silent success, because "already
// an admin" and "granted just now, by you" are different facts about who is
// accountable for the privilege.
//
// grantedBy is the acting principal, nil for a grant with no attributable
// actor (the backfill in migration 000051 writes its rows that way).
//
// IN A TRANSACTION, FOR THE AUDIT RECORD (issue #766, migration 000052). The
// insert is a single statement and needs no transaction of its own; it has one
// so that writeAuditIntent can enlist in it. The grant and the record of the
// grant then commit together or not at all — which is the whole point, because
// the audit destination is on a different connection and the previous design
// (mutate, then write the entry, then log the failure and report success)
// could produce a platform administrator nobody could account for.
//
// writeAuditIntent is MANDATORY: nil is refused with ErrAuditIntentRequired
// before anything is written. Migration 000052's deferred constraint trigger
// refuses the commit independently, so a caller that bypasses this repository
// entirely — including hand-written SQL — is held to the same rule.
func (r *PlatformAdminRepository) Grant(ctx context.Context, userID string, grantedBy, note *string, writeAuditIntent AuditIntentWriter) (*PlatformAdminGrant, error) {
	if writeAuditIntent == nil {
		return nil, ErrAuditIntentRequired
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	// Rolled back unconditionally; a Rollback after a successful Commit is a
	// no-op returning sql.ErrTxDone, which is why only the Commit error is
	// reported.
	defer func() { _ = tx.Rollback() }()

	query := `INSERT INTO platform_admins (user_id, granted_by, note)
	          VALUES ($1, $2, $3)
	          ON CONFLICT (user_id) DO NOTHING
	          RETURNING ` + grantColumns
	g, err := scanGrant(tx.QueryRowContext(ctx, query, userID, grantedBy, note))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyPlatformAdmin
	}
	if err != nil {
		return nil, err
	}

	// After the mutation, so the intent can describe what actually landed —
	// and before the commit, so a refusal here takes the grant with it.
	if err := writeAuditIntent(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return g, nil
}

// lockCarrier reads every grant inside tx under FOR UPDATE, separating the one
// addressed by userID (nil when there is none) from the ones that would remain
// after it is removed.
func lockCarrier(ctx context.Context, tx *sql.Tx, userID string) (*PlatformAdminGrant, []PlatformAdminGrant, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT `+grantColumns+` FROM platform_admins ORDER BY granted_at ASC, user_id ASC FOR UPDATE`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var target *PlatformAdminGrant
	var remaining []PlatformAdminGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, nil, err
		}
		if g.UserID == userID {
			target = g
			continue
		}
		remaining = append(remaining, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return target, remaining, nil
}

// Revoke removes userID's carrier row, but only if keepsAnAdmin accepts the
// grants that would REMAIN afterwards.
//
// GUARD platform-admin-last-standing (issue #766). A deployment that revokes
// its final platform administrator has no recovery path short of hand-written
// SQL against platform_admins — which is precisely the operation this API
// exists to replace. The predicate is the caller's because "an admin that
// remains" is not answerable from this table alone: a grant whose user no
// longer resolves is inert (both middlewares load the user BEFORE consulting
// the carrier, so a deleted user's row elevates nobody), and counting it would
// let the last REAL administrator revoke themselves against a count of two.
//
// UNDER A LOCK, NOT CHECK-THEN-DELETE. The read takes FOR UPDATE and the
// delete runs in the same transaction, so two administrators revoking each
// other concurrently serialise: the second one's read blocks, then sees a set
// with the first's row already gone. Without the lock both would see the other
// still present, both would pass the predicate, and the deployment would end
// with zero administrators — the exact outcome the guard exists to prevent,
// reachable by two well-formed requests.
//
// writeAuditIntent records the revocation in the SAME transaction as the
// delete (issue #766, migration 000052) and is MANDATORY — nil is refused with
// ErrAuditIntentRequired before the lock is taken. A revocation that could not
// be recorded is not performed.
//
// Returns ErrNotPlatformAdmin when there is no row to remove, the predicate's
// own error when it refuses, and the driver's error otherwise. Nothing is
// deleted in any of those cases.
func (r *PlatformAdminRepository) Revoke(ctx context.Context, userID string, keepsAnAdmin func(ctx context.Context, remaining []PlatformAdminGrant) error, writeAuditIntent AuditIntentWriter) (*PlatformAdminGrant, error) {
	if writeAuditIntent == nil {
		return nil, ErrAuditIntentRequired
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	// Rolled back unconditionally; a Rollback after a successful Commit is a
	// no-op returning sql.ErrTxDone, which is why the error is dropped here and
	// only the Commit error is reported.
	defer func() { _ = tx.Rollback() }()

	target, remaining, err := lockCarrier(ctx, tx, userID)
	if err != nil {
		return nil, err
	}

	if target == nil {
		return nil, ErrNotPlatformAdmin
	}
	if keepsAnAdmin != nil {
		if err := keepsAnAdmin(ctx, remaining); err != nil {
			return nil, err
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM platform_admins WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	// The row was present under FOR UPDATE moments ago, so zero rows here means
	// the lock did not hold what it is supposed to hold. Refusing to commit is
	// the only safe reading: reporting a revocation that did not happen would
	// leave an administrator the operator believes is gone.
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, fmt.Errorf("revoking platform-admin for %s removed %d rows, want 1", userID, affected)
	}
	// Inside the same transaction as the DELETE: a refusal here rolls the
	// revocation back rather than leaving an unrecorded loss of privilege.
	if err := writeAuditIntent(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return target, nil
}

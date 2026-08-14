// Package carriermutations is a FIXTURE, not shipped code. It exists so the
// carrier-mutation guard has something to find.
//
// It lives under testdata/, which the go tool ignores, so nothing here is
// compiled, vetted or linked into the binary — the guard parses it as source.
//
// WHY A FIXTURE IS NEEDED AT ALL. Before the platform-admin mechanism moved
// into the shared identity library, the repositories package contained the two
// carrier mutations itself and the guard asserted it had found at least two of
// them. It now contains none: Grant and Revoke are
// platformadmin.Carrier's. A scan that finds nothing proves nothing, so the
// non-vacuity assertion moved here — the guard is pointed at this file, and
// must report exactly the unaudited mutator below and not the audited one.
//
// PurgeAdmin is deliberately written in the idiom registry's own AST guard
// walked straight past: the SQL is a PACKAGE-LEVEL CONST rather than a literal
// inside the function body, which is exactly how the outbox INSERT was written
// in this repository. The library's scan resolves package-level constants and
// literal concatenation before matching, which is the difference between a
// guard and a guard-shaped test.
package carriermutations

import (
	"context"
	"database/sql"

	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// purgeAdminsSQL is the const-hoisted mutation. Concatenated as well as
// hoisted, because the guard has to fold both.
const purgeAdminsSQL = `DELETE FROM platform_admins ` + purgeAdminsPredicate

const purgeAdminsPredicate = `WHERE user_id = $1`

// grantAdminSQL is the audited mutation's statement, hoisted the same way.
const grantAdminSQL = `INSERT INTO platform_admins (user_id, granted_by, note)
	VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING`

type fixtureRepo struct {
	db *sql.DB
}

// PurgeAdmin is the finding: it mutates the carrier and takes no audit-intent
// writer, so the highest privilege in the product could change hands here with
// nothing recording it.
func (r *fixtureRepo) PurgeAdmin(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, purgeAdminsSQL, userID)
	return err
}

// GrantAdmin is the counterexample: same table, same const-hoisted idiom, but
// it takes the writer and runs it inside the mutation's own transaction. It
// must be COUNTED as a mutator and must NOT be reported.
func (r *fixtureRepo) GrantAdmin(ctx context.Context, userID string, writeAuditIntent platformadmin.AuditIntentWriter) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, grantAdminSQL, userID, nil, nil); err != nil {
		return err
	}
	if err := writeAuditIntent(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

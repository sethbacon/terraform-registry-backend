package repositories

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// uniqueViolation is Postgres's SQLSTATE for a unique or primary-key
// constraint violation.
const uniqueViolation = "23505"

// IsUniqueViolation reports whether err is Postgres refusing a duplicate row.
//
// WHY THIS EXISTS (issue #987). Every foreseeable duplicate in this API is
// handled by a pre-check -- read the row, answer 409 if it is already there --
// which gives the right answer in every non-racy case and is why a duplicate
// does not surface as a 500 here in ordinary use. But a pre-check is a
// time-of-check window: two concurrent adds both see "not present", both
// INSERT, and the loser gets a 23505 that nothing translated. It surfaced as a
// 500 with the constraint name in the log.
//
// The sibling app could fix its equivalent in one place because it funnels
// every internal fault through a single serverError helper. This API does not
// -- there are hundreds of direct StatusInternalServerError sites -- so a
// central translation has nowhere to live, and rewriting them all to close a
// race would not be proportionate. Instead the handlers that ALREADY have a
// 409 branch call this on the insert error and answer with the same 409 their
// pre-check would have given, which makes the pre-check a fast path rather
// than the only thing standing between a race and a 500.
//
// Driver-specific by necessity: the pool is opened with pgx/v5/stdlib, so a
// constraint violation arrives as *pgconn.PgError. errors.As unwraps, so a
// repository that wraps with %w is still recognised.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}

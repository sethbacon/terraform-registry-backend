package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// GUARD duplicate-insert-is-a-conflict (issue #987).
//
// The handlers that answer 409 on a duplicate depend on this predicate to tell
// "you lost an insert race" from "the database broke". A version of it that
// answers false for a real 23505 turns the race back into a 500; one that
// answers true for anything else turns a genuine fault into a cheerful 409.

func TestIsUniqueViolation(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"a unique violation", &pgconn.PgError{Code: "23505"}, true},
		{"wrapped, because repositories wrap with %w", fmt.Errorf("add member: %w", &pgconn.PgError{Code: "23505"}), true},
		{"wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &pgconn.PgError{Code: "23505"})), true},
		{"a foreign-key violation is not a duplicate", &pgconn.PgError{Code: "23503"}, false},
		{"a not-null violation is not a duplicate", &pgconn.PgError{Code: "23502"}, false},
		{"an ordinary error", errors.New("connection refused"), false},
		{"no rows", sql.ErrNoRows, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUniqueViolation(tc.err); got != tc.want {
				t.Fatalf("IsUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

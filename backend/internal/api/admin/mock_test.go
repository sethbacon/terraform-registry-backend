package admin

import (
	"database/sql"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/pgxparam"
)

// newSQLMock builds a mock that models the driver this module actually runs on.
//
// pgx encodes Go values itself, so an org-scope predicate binds its []string
// directly; sqlmock's default conversion accepts only the fixed driver.Value
// set and fails such a bind with "unsupported type []string, a slice of
// string". A bare sqlmock.New() therefore passes until the query under test
// happens to be a scoped one, which is the wrong moment to find out.
func newSQLMock() (*sql.DB, sqlmock.Sqlmock, error) {
	return sqlmock.New(sqlmock.ValueConverterOption(pgxparam.Converter{}))
}

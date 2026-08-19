package scim

import (
	"database/sql"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/pgxparam"
)

// newSQLMock builds a mock that models the driver this module actually runs on.
// See identity/pgxparam: pgx binds a []string directly, sqlmock's default
// conversion rejects it.
func newSQLMock() (*sql.DB, sqlmock.Sqlmock, error) {
	return sqlmock.New(sqlmock.ValueConverterOption(pgxparam.Converter{}))
}

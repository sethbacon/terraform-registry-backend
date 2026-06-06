package repositories

import "errors"

// errDB is a shared sentinel error used across the repository sqlmock tests to
// drive error paths (mock.ExpectQuery(...).WillReturnError(errDB)).
var errDB = errors.New("db error")

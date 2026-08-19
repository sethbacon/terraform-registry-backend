// Package pgxparam supplies the parameter conversion this module's database
// mocks need in order to model the driver it actually runs on.
//
// pgx implements driver.NamedValueChecker and encodes Go values itself, so a
// []string bound to `= ANY($1)` is handed to the driver untouched. So does
// lib/pq, which auto-wraps any slice via its own Array(). sqlmock does neither:
// it falls back to database/sql's default converter, which accepts only the
// fixed driver.Value set and rejects any slice other than []byte with
// "unsupported type []string, a slice of string".
//
// The mock was therefore never faithful to either real driver. That went
// unnoticed while lib/pq's Array() wrapper pre-encoded the slice to a string
// before it reached the mock; passing the slice directly, which is what both
// drivers want, makes the gap appear as a test failure rather than a silent
// difference in behaviour.
package pgxparam

import (
	"database/sql/driver"
	"reflect"
)

// Converter passes slices through and defers everything else to database/sql.
type Converter struct{}

// ConvertValue implements driver.ValueConverter.
func (Converter) ConvertValue(v any) (driver.Value, error) {
	// []byte is already a driver.Value and carries its own semantics; only
	// slices the default converter would reject are passed through.
	if _, ok := v.([]byte); !ok && v != nil {
		if reflect.TypeOf(v).Kind() == reflect.Slice {
			return v, nil
		}
	}
	return driver.DefaultParameterConverter.ConvertValue(v)
}

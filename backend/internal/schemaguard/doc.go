// Package schemaguard is test-only infrastructure. It holds the guard against
// the defect class behind issue #864: application SQL that depends on schema
// the running configuration will not have.
//
// There is no production code here on purpose — nothing in the server binary
// imports this package. Everything lives in _test.go files so the guard cannot
// drift into being a runtime dependency of the thing it inspects.
//
// Start at schema_demand_guard_test.go; the reusable analyzer and its own unit
// tests are in schema_demand_analyzer_test.go.
package schemaguard

// Package models — module_scan.go defines the ModuleScan record that tracks
// the status and results of a security scan for a module version.
package models

import (
	"encoding/json"
	"time"
)

// ModuleScan records the security scan lifecycle for a single module version.
// A pending record is created when a version is uploaded; the scanner job
// transitions it through scanning → clean|findings|error.
type ModuleScan struct {
	ID              string          `db:"id"                json:"id"`
	ModuleVersionID string          `db:"module_version_id" json:"module_version_id"`
	Scanner         string          `db:"scanner"           json:"scanner"`
	ScannerVersion  *string         `db:"scanner_version"   json:"scanner_version,omitempty"`
	ExpectedVersion *string         `db:"expected_version"  json:"expected_version,omitempty"`
	Status          string          `db:"status"            json:"status"` // pending, scanning, clean, findings, error
	ScannedAt       *time.Time      `db:"scanned_at"        json:"scanned_at,omitempty"`
	CriticalCount   int             `db:"critical_count"    json:"critical_count"`
	HighCount       int             `db:"high_count"        json:"high_count"`
	MediumCount     int             `db:"medium_count"      json:"medium_count"`
	LowCount        int             `db:"low_count"         json:"low_count"`
	RawResults      json.RawMessage `db:"raw_results"       json:"raw_results,omitempty" swaggertype:"object"` //nolint:tagliatelle
	ErrorMessage    *string         `db:"error_message"     json:"error_message,omitempty"`
	CreatedAt       time.Time       `db:"created_at"        json:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at"        json:"updated_at"`
}

// Package models - scanner_binary_version.go defines the ScannerBinaryVersion model
// backing the module security-scanner (trivy/terrascan/checkov) update workflow. Rows
// are discovered by a scheduled update-check job and participate in the generic
// version-approval workflow (type="scanner") alongside provider and terraform
// mirror versions.
package models

import (
	"time"

	"github.com/google/uuid"
)

// ScannerBinaryVersion represents a single discovered release of a module
// security-scanning tool binary. approval_status gates activation the same way
// it gates provider/terraform mirror versions; is_active marks the currently
// installed+running binary for its tool (at most one per tool).
type ScannerBinaryVersion struct {
	ID                uuid.UUID `json:"id" db:"id"`
	Tool              string    `json:"tool" db:"tool"`
	Version           string    `json:"version" db:"version"`
	SourceURL         *string   `json:"source_url,omitempty" db:"source_url"`
	Sha256            *string   `json:"sha256,omitempty" db:"sha256"`
	SignatureVerified bool      `json:"signature_verified" db:"signature_verified"`
	SignatureType     string    `json:"signature_type" db:"signature_type"`
	SyncStatus        string    `json:"sync_status" db:"sync_status"`
	ApprovalStatus    *string   `json:"approval_status,omitempty" db:"approval_status"` // NULL|pending_approval|approved|rejected
	IsActive          bool      `json:"is_active" db:"is_active"`
	BinaryPath        *string   `json:"binary_path,omitempty" db:"binary_path"`
	DiscoveredAt      time.Time `json:"discovered_at" db:"discovered_at"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

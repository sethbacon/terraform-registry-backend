// Package models — cve.go defines the data model for the CVE polling subsystem.
//
// The subsystem polls OSV.dev daily for security advisories that affect artifacts
// managed by this registry: Terraform/OpenTofu binary versions, hosted provider
// versions, and the configured scanner binary. Affected artifacts are stored as
// CVEAffectedTarget rows with a target_kind discriminator so all three artifact
// kinds can coexist in a single table with a uniform query interface.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CVESeverity is the normalised severity bucket derived from a CVSS v3 score.
type CVESeverity string

const (
	CVESeverityCritical CVESeverity = "critical"
	CVESeverityHigh     CVESeverity = "high"
	CVESeverityMedium   CVESeverity = "medium"
	CVESeverityLow      CVESeverity = "low"
	CVESeverityUnknown  CVESeverity = "unknown"
)

// CVETargetKind discriminates which type of artifact a CVEAffectedTarget refers to.
type CVETargetKind string

const (
	CVETargetKindBinary   CVETargetKind = "binary"
	CVETargetKindProvider CVETargetKind = "provider"
	CVETargetKindScanner  CVETargetKind = "scanner"
)

// CVEAdvisory is a single security advisory from OSV.dev.
// One advisory may affect many target artifacts (stored as CVEAffectedTarget rows).
type CVEAdvisory struct {
	ID          uuid.UUID   `json:"id"          db:"id"`
	Source      string      `json:"source"      db:"source"`    // "osv"
	SourceID    string      `json:"source_id"   db:"source_id"` // "GHSA-…" or "CVE-…"
	Severity    CVESeverity `json:"severity"    db:"severity"`
	Summary     string      `json:"summary"     db:"summary"`
	Details     string      `json:"details"     db:"details"`
	References  []string    `json:"references"  db:"-"`          // decoded from jsonb
	RefsJSON    []byte      `json:"-"           db:"references"` // raw db column
	PublishedAt *time.Time  `json:"published_at,omitempty" db:"published_at"`
	ModifiedAt  *time.Time  `json:"modified_at,omitempty"  db:"modified_at"`
	FetchedAt   time.Time   `json:"fetched_at"  db:"fetched_at"`
	WithdrawnAt *time.Time  `json:"withdrawn_at,omitempty" db:"withdrawn_at"`
	CreatedAt   time.Time   `json:"created_at"  db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"  db:"updated_at"`

	// Populated post-query — not stored in the advisories table.
	Targets []CVEAffectedTarget `json:"targets,omitempty" db:"-"`
}

// DecodeRefs populates the References slice from the raw RefsJSON column.
func (a *CVEAdvisory) DecodeRefs() {
	if len(a.RefsJSON) > 0 {
		_ = json.Unmarshal(a.RefsJSON, &a.References)
	}
}

// IsActive returns true when the advisory has not been withdrawn.
func (a *CVEAdvisory) IsActive() bool {
	return a.WithdrawnAt == nil
}

// CVEAffectedTarget links an advisory to a specific artifact version.
type CVEAffectedTarget struct {
	ID                 uuid.UUID     `json:"id"           db:"id"`
	AdvisoryID         uuid.UUID     `json:"advisory_id"  db:"advisory_id"`
	TargetKind         CVETargetKind `json:"target_kind"  db:"target_kind"`
	Fingerprint        string        `json:"-"            db:"fingerprint"`
	TargetRefJSON      []byte        `json:"-"            db:"target_ref"` // raw JSONB
	TargetRef          CVETargetRef  `json:"target_ref"   db:"-"`          // decoded
	TerraformVersionID *uuid.UUID    `json:"terraform_version_id,omitempty" db:"terraform_version_id"`
	ProviderVersionID  *uuid.UUID    `json:"provider_version_id,omitempty"  db:"provider_version_id"`
	CreatedAt          time.Time     `json:"created_at"   db:"created_at"`
}

// DecodeRef populates TargetRef from the raw TargetRefJSON column.
func (t *CVEAffectedTarget) DecodeRef() {
	if len(t.TargetRefJSON) > 0 {
		_ = json.Unmarshal(t.TargetRefJSON, &t.TargetRef)
	}
}

// CVETargetRef holds the kind-specific artifact identifiers.
// Only the fields relevant to the TargetKind are populated.
type CVETargetRef struct {
	// binary
	MirrorConfigID     string `json:"mirror_config_id,omitempty"`
	TerraformVersionID string `json:"terraform_version_id,omitempty"`
	Tool               string `json:"tool,omitempty"`    // "terraform" | "opentofu" | scanner name
	Version            string `json:"version,omitempty"` // semver

	// provider
	ProviderID        string `json:"provider_id,omitempty"`
	ProviderVersionID string `json:"provider_version_id,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	ProviderType      string `json:"type,omitempty"`
}

// Fingerprint returns a stable string that uniquely identifies this target ref
// within its kind. Used as the ON CONFLICT key in the DB.
func (r CVETargetRef) FingerprintFor(kind CVETargetKind) string {
	switch kind {
	case CVETargetKindBinary:
		return r.MirrorConfigID + ":" + r.TerraformVersionID
	case CVETargetKindProvider:
		return r.ProviderVersionID
	case CVETargetKindScanner:
		return r.Tool + ":" + r.Version
	default:
		return r.Tool + ":" + r.Version
	}
}

// CVEActiveAdvisoryResponse is the JSON shape returned by GET /api/v1/advisories/active.
type CVEActiveAdvisoryResponse struct {
	ID         uuid.UUID           `json:"id"`
	SourceID   string              `json:"source_id"`
	Severity   CVESeverity         `json:"severity"`
	Summary    string              `json:"summary"`
	References []string            `json:"references"`
	TargetKind CVETargetKind       `json:"target_kind"`
	Targets    []CVEAffectedTarget `json:"targets"`
}

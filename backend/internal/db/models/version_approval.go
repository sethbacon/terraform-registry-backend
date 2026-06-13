// Package models - version_approval.go defines the types backing the version
// approval gate for provider and terraform binary mirrors: the per-decision
// audit event row, the auto-approve rule configuration parsed from each
// mirror config's auto_approve_rules JSONB column, and the API DTOs the admin
// version-approvals endpoints return.
package models

import (
	"time"

	"github.com/google/uuid"
)

// Approval status values stored in the approval_status column on
// mirrored_provider_versions and terraform_versions. A NULL column (no
// constant here) means the version is not subject to approval.
const (
	VersionApprovalStatusPending  = "pending_approval"
	VersionApprovalStatusApproved = "approved"
	VersionApprovalStatusRejected = "rejected"
)

// Approval event action values stored in version_approval_events.action.
const (
	VersionApprovalActionAuto     = "auto_approved"
	VersionApprovalActionApproved = "approved"
	VersionApprovalActionRejected = "rejected"
)

// VersionApprovalType identifies which kind of mirrored version an approval
// row refers to.
const (
	VersionApprovalTypeProvider  = "provider"
	VersionApprovalTypeTerraform = "terraform"
)

// VersionApprovalEvent is one row of the version_approval_events audit table.
// Exactly one of MirroredProviderVersionID / TerraformVersionID is set.
type VersionApprovalEvent struct {
	ID                        uuid.UUID  `json:"id" db:"id"`
	MirroredProviderVersionID *uuid.UUID `json:"-" db:"mirrored_provider_version_id"`
	TerraformVersionID        *uuid.UUID `json:"-" db:"terraform_version_id"`
	Action                    string     `json:"action" db:"action"`
	PerformedBy               *uuid.UUID `json:"-" db:"performed_by"`
	PerformedByName           *string    `json:"performed_by_name,omitempty" db:"performed_by_name"`
	Notes                     *string    `json:"notes,omitempty" db:"notes"`
	AutoApproveRule           *string    `json:"auto_approve_rule,omitempty" db:"auto_approve_rule"`
	CreatedAt                 time.Time  `json:"created_at" db:"created_at"`
}

// AutoApproveRule is a single rule evaluated at sync time. Only the fields
// relevant to Type are populated.
type AutoApproveRule struct {
	Type       string `json:"type"`                 // patch_only | gpg_verified | semver_constraint | delay_hours
	Hours      *int   `json:"hours,omitempty"`      // delay_hours
	Constraint string `json:"constraint,omitempty"` // semver_constraint
}

// AutoApproveRules is the parsed form of a mirror config's auto_approve_rules
// JSONB column.
type AutoApproveRules struct {
	Rules []AutoApproveRule `json:"rules"`
	Mode  string            `json:"mode"` // "any" (first match wins) | "all" (all must match)
}

// VersionApproval is the API DTO returned by the admin version-approvals list
// endpoint. It flattens a mirrored provider version or terraform version into
// a uniform shape consumed by the frontend approvals page. ID is the version
// row's own UUID (mirrored_provider_versions.id or terraform_versions.id).
type VersionApproval struct {
	ID                uuid.UUID `json:"id" db:"id"`
	Type              string    `json:"type" db:"type"` // provider | terraform
	Version           string    `json:"version" db:"version"`
	ApprovalStatus    string    `json:"approval_status" db:"approval_status"`
	ProviderNamespace *string   `json:"provider_namespace,omitempty" db:"provider_namespace"`
	ProviderName      *string   `json:"provider_name,omitempty" db:"provider_name"`
	MirrorConfigName  string    `json:"mirror_config_name" db:"mirror_config_name"`
	MirrorConfigID    uuid.UUID `json:"mirror_config_id" db:"mirror_config_id"`
	GPGVerified       *bool     `json:"gpg_verified,omitempty" db:"gpg_verified"`
	ShasumVerified    *bool     `json:"shasum_verified,omitempty" db:"shasum_verified"`
	SyncedAt          time.Time `json:"synced_at" db:"synced_at"`
}

// VersionApprovalListResponse is the envelope for the list endpoint.
type VersionApprovalListResponse struct {
	Items []VersionApproval `json:"items"`
	Total int               `json:"total"`
}

// VersionApprovalBulkRequest is the body for the bulk approve/reject endpoints.
type VersionApprovalBulkRequest struct {
	IDs   []string `json:"ids" binding:"required,min=1"`
	Notes *string  `json:"notes,omitempty"`
}

// VersionApprovalBulkResponse reports the outcome of a bulk operation.
type VersionApprovalBulkResponse struct {
	Approved int      `json:"approved,omitempty"`
	Rejected int      `json:"rejected,omitempty"`
	Failures []string `json:"failures"`
}

// VersionApprovalActionRequest is the body for single approve/reject endpoints.
type VersionApprovalActionRequest struct {
	Notes *string `json:"notes,omitempty"`
}

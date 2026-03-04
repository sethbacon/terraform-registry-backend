// Package models - mirror_approval.go defines the MirrorApprovalRequest model for
// tracking pending, approved, and rejected requests to mirror providers or namespaces.
package models

import (
	"time"

	"github.com/google/uuid"
)

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
)

// MirrorApprovalRequest represents a request to mirror a specific provider or namespace
type MirrorApprovalRequest struct {
	ID             uuid.UUID  `db:"id" json:"id"`
	MirrorConfigID uuid.UUID  `db:"mirror_config_id" json:"mirror_config_id"`
	OrganizationID *uuid.UUID `db:"organization_id" json:"organization_id,omitempty"`
	RequestedBy    *uuid.UUID `db:"requested_by" json:"requested_by,omitempty"`

	// What is being requested
	ProviderNamespace string  `db:"provider_namespace" json:"provider_namespace"`
	ProviderName      *string `db:"provider_name" json:"provider_name,omitempty"` // NULL means entire namespace

	// Request details
	Reason string         `db:"reason" json:"reason,omitempty"`
	Status ApprovalStatus `db:"status" json:"status"`

	// Approval details
	ReviewedBy  *uuid.UUID `db:"reviewed_by" json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time `db:"reviewed_at" json:"reviewed_at,omitempty"`
	ReviewNotes *string    `db:"review_notes" json:"review_notes,omitempty"`

	// Auto-approval
	AutoApproved bool `db:"auto_approved" json:"auto_approved"`

	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
	ExpiresAt *time.Time `db:"expires_at" json:"expires_at,omitempty"`

	// Joined fields (not in DB)
	RequestedByName string `db:"-" json:"requested_by_name,omitempty"`
	ReviewedByName  string `db:"-" json:"reviewed_by_name,omitempty"`
	MirrorName      string `db:"-" json:"mirror_name,omitempty"`
}

// IsExpired checks if the approval has expired
func (m *MirrorApprovalRequest) IsExpired() bool {
	if m.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*m.ExpiresAt)
}

// IsValid checks if the approval is valid (approved and not expired)
func (m *MirrorApprovalRequest) IsValid() bool {
	return m.Status == ApprovalStatusApproved && !m.IsExpired()
}

// Package models - mirror_policy.go defines the MirrorPolicy model for allow/deny rules
// that govern which upstream registries, namespaces, and providers may be mirrored.
package models

import (
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// PolicyType represents the type of mirror policy
type PolicyType string

const (
	PolicyTypeAllow PolicyType = "allow"
	PolicyTypeDeny  PolicyType = "deny"
)

// MirrorPolicy represents a policy for controlling mirror operations
type MirrorPolicy struct {
	ID             uuid.UUID  `db:"id" json:"id"`
	OrganizationID *uuid.UUID `db:"organization_id" json:"organization_id,omitempty"` // NULL = global policy
	Name           string     `db:"name" json:"name"`
	Description    *string    `db:"description" json:"description,omitempty"`

	// Policy type
	PolicyType PolicyType `db:"policy_type" json:"policy_type"`

	// What this policy applies to (supports wildcards)
	UpstreamRegistry *string `db:"upstream_registry" json:"upstream_registry,omitempty"` // NULL = all registries
	NamespacePattern *string `db:"namespace_pattern" json:"namespace_pattern,omitempty"` // e.g., "hashicorp", "*"
	ProviderPattern  *string `db:"provider_pattern" json:"provider_pattern,omitempty"`   // e.g., "aws", "*"

	// Policy settings
	Priority         int  `db:"priority" json:"priority"`
	IsActive         bool `db:"is_active" json:"is_active"`
	RequiresApproval bool `db:"requires_approval" json:"requires_approval"`

	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`

	// Joined fields (not in DB)
	OrganizationName string `db:"-" json:"organization_name,omitempty"`
	CreatedByName    string `db:"-" json:"created_by_name,omitempty"`
}

// Matches checks if this policy matches the given provider
func (p *MirrorPolicy) Matches(registry, namespace, provider string) bool {
	// Check registry match
	if p.UpstreamRegistry != nil && *p.UpstreamRegistry != "" {
		if *p.UpstreamRegistry != registry {
			return false
		}
	}

	// Check namespace match (supports wildcards)
	if p.NamespacePattern != nil && *p.NamespacePattern != "" {
		matched, _ := filepath.Match(*p.NamespacePattern, namespace)
		if !matched && *p.NamespacePattern != "*" {
			return false
		}
	}

	// Check provider match (supports wildcards)
	if p.ProviderPattern != nil && *p.ProviderPattern != "" {
		matched, _ := filepath.Match(*p.ProviderPattern, provider)
		if !matched && *p.ProviderPattern != "*" {
			return false
		}
	}

	return true
}

// PolicyEvaluationResult represents the result of evaluating policies
type PolicyEvaluationResult struct {
	Allowed          bool          `json:"allowed"`
	RequiresApproval bool          `json:"requires_approval"`
	MatchedPolicy    *MirrorPolicy `json:"matched_policy,omitempty"`
	Reason           string        `json:"reason"`
}

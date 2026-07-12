// Package models - namespace_claim.go defines the namespace-to-organization
// ownership binding used for object-level authorization on module and provider
// mutations (issue #555, CWE-639).
package models

import "time"

// NamespaceClaim binds a module/provider namespace to its owning organization.
// A namespace is claimed by the organization that first publishes into it;
// every subsequent mutation of artifacts in that namespace must come from a
// principal with write access in the owning organization (or an admin).
type NamespaceClaim struct {
	Namespace      string    `json:"namespace"`
	OrganizationID string    `json:"organization_id"`
	ClaimedBy      *string   `json:"claimed_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

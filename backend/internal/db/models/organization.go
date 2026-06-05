// Package models - organization.go aliases the Organization type from the shared
// identity module. The registry's per-org IdP binding (idp_type/idp_name) is part
// of the canonical identity model.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

// Organization represents an organization/namespace (tenant).
type Organization = identitymodels.Organization

// Package models - audit_log.go aliases the AuditLog type from the shared
// identity module.
package models

import identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"

// AuditLog represents an audit log entry for tracking user actions.
type AuditLog = identitymodels.AuditLog

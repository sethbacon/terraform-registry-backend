// Package auth - scopes.go defines permission scope constants for all registry resources
// and provides HasScope, HasAnyScope, and HasAllScopes helper functions for scope checking.
package auth

import (
	"errors"
	"fmt"
)

// Scope represents a permission/scope type
type Scope string

const (
	// Module scopes
	ScopeModulesRead  Scope = "modules:read"
	ScopeModulesWrite Scope = "modules:write"

	// Provider scopes
	ScopeProvidersRead  Scope = "providers:read"
	ScopeProvidersWrite Scope = "providers:write"

	// Mirror scopes (for provider network mirroring)
	ScopeMirrorsRead   Scope = "mirrors:read"   // View mirror configurations and sync status
	ScopeMirrorsManage Scope = "mirrors:manage" // Create, update, delete mirrors and trigger syncs

	// User management scopes
	ScopeUsersRead  Scope = "users:read"
	ScopeUsersWrite Scope = "users:write"

	// Organization management scopes
	ScopeOrganizationsRead  Scope = "organizations:read"  // View organizations and members
	ScopeOrganizationsWrite Scope = "organizations:write" // Create, update, delete organizations and manage members

	// SCM provider management scopes
	ScopeSCMRead   Scope = "scm:read"   // View SCM provider configurations
	ScopeSCMManage Scope = "scm:manage" // Create, update, delete SCM providers and manage OAuth

	// API key management scopes
	ScopeAPIKeysManage Scope = "api_keys:manage"

	// Audit log scopes
	ScopeAuditRead Scope = "audit:read"

	// Admin scope (wildcard - all permissions)
	ScopeAdmin Scope = "admin"
)

// AllScopes returns all valid scopes
func AllScopes() []Scope {
	return []Scope{
		ScopeModulesRead,
		ScopeModulesWrite,
		ScopeProvidersRead,
		ScopeProvidersWrite,
		ScopeMirrorsRead,
		ScopeMirrorsManage,
		ScopeUsersRead,
		ScopeUsersWrite,
		ScopeOrganizationsRead,
		ScopeOrganizationsWrite,
		ScopeSCMRead,
		ScopeSCMManage,
		ScopeAPIKeysManage,
		ScopeAuditRead,
		ScopeAdmin,
	}
}

// ValidScopes returns a map of valid scope strings
func ValidScopes() map[string]bool {
	validScopes := make(map[string]bool)
	for _, scope := range AllScopes() {
		validScopes[string(scope)] = true
	}
	return validScopes
}

// ValidateScopes checks if all provided scopes are valid
func ValidateScopes(scopes []string) error {
	validScopes := ValidScopes()

	for _, scope := range scopes {
		if !validScopes[scope] {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}

	return nil
}

// HasScope checks if a user has a required scope
// Supports wildcard admin scope
func HasScope(userScopes []string, required Scope) bool {
	requiredStr := string(required)

	for _, scope := range userScopes {
		// Check for exact match
		if scope == requiredStr {
			return true
		}

		// Check for admin wildcard
		if scope == string(ScopeAdmin) {
			return true
		}

		// Check for wildcard read permissions
		// If user has write/manage permission, they also have read permission
		if required == ScopeModulesRead && scope == string(ScopeModulesWrite) {
			return true
		}
		if required == ScopeProvidersRead && scope == string(ScopeProvidersWrite) {
			return true
		}
		if required == ScopeUsersRead && scope == string(ScopeUsersWrite) {
			return true
		}
		if required == ScopeMirrorsRead && scope == string(ScopeMirrorsManage) {
			return true
		}
		if required == ScopeOrganizationsRead && scope == string(ScopeOrganizationsWrite) {
			return true
		}
		if required == ScopeSCMRead && scope == string(ScopeSCMManage) {
			return true
		}
	}

	return false
}

// HasAnyScope checks if a user has at least one of the required scopes
func HasAnyScope(userScopes []string, requiredScopes []Scope) bool {
	for _, required := range requiredScopes {
		if HasScope(userScopes, required) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if a user has all of the required scopes
func HasAllScopes(userScopes []string, requiredScopes []Scope) bool {
	for _, required := range requiredScopes {
		if !HasScope(userScopes, required) {
			return false
		}
	}
	return true
}

// GetDefaultScopes returns default scopes for a new API key
func GetDefaultScopes() []string {
	return []string{
		string(ScopeModulesRead),
		string(ScopeProvidersRead),
	}
}

// GetAdminScopes returns all scopes including admin
func GetAdminScopes() []string {
	scopes := make([]string, 0)
	for _, scope := range AllScopes() {
		scopes = append(scopes, string(scope))
	}
	return scopes
}

// ValidateScopeString validates a single scope string
func ValidateScopeString(scope string) error {
	validScopes := ValidScopes()
	if !validScopes[scope] {
		return errors.New("invalid scope")
	}
	return nil
}

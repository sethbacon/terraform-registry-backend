// Package auth - scopes.go defines permission scope constants for all registry resources
// and provides HasScope, HasAnyScope, and HasAllScopes helper functions for scope checking.
// The generic scope-checking logic (wildcard admin + write-implies-read) and the
// identity-core scope constants are owned by the shared identity module; the
// registry-specific scopes and their read/write pairs are injected here.
package auth

import (
	"errors"
	"fmt"

	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
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

	// SCM provider management scopes
	ScopeSCMRead   Scope = "scm:read"   // View SCM provider configurations
	ScopeSCMManage Scope = "scm:manage" // Create, update, delete SCM providers and manage OAuth

	// Security scanning scopes
	ScopeScanningRead Scope = "scanning:read" // View scan results, config, and stats

	// SCIM provisioning scopes
	ScopeSCIMProvision Scope = "scim:provision" // SCIM 2.0 user/group provisioning

	// Identity-core scopes (values defined in the shared identity module)
	ScopeUsersRead          Scope = identityauth.ScopeUsersRead
	ScopeUsersWrite         Scope = identityauth.ScopeUsersWrite
	ScopeOrganizationsRead  Scope = identityauth.ScopeOrganizationsRead
	ScopeOrganizationsWrite Scope = identityauth.ScopeOrganizationsWrite
	ScopeAPIKeysManage      Scope = identityauth.ScopeAPIKeysManage
	ScopeAuditRead          Scope = identityauth.ScopeAuditRead
	ScopeAdmin              Scope = identityauth.ScopeAdmin
)

// readWritePairs maps read scopes to the write/manage scope that implies them.
// If a user holds the write/manage scope, they implicitly have the read scope.
var readWritePairs = identityauth.ReadWritePairs{
	string(ScopeModulesRead):       string(ScopeModulesWrite),
	string(ScopeProvidersRead):     string(ScopeProvidersWrite),
	string(ScopeUsersRead):         string(ScopeUsersWrite),
	string(ScopeMirrorsRead):       string(ScopeMirrorsManage),
	string(ScopeOrganizationsRead): string(ScopeOrganizationsWrite),
	string(ScopeSCMRead):           string(ScopeSCMManage),
}

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
		ScopeScanningRead,
		ScopeSCIMProvision,
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

// HasScope checks if a user has a required scope.
// Supports wildcard admin scope and write-implies-read logic.
func HasScope(userScopes []string, required Scope) bool {
	return identityauth.HasScope(userScopes, string(required), readWritePairs)
}

// HasAnyScope checks if a user has at least one of the required scopes
func HasAnyScope(userScopes []string, requiredScopes []Scope) bool {
	strs := make([]string, len(requiredScopes))
	for i, s := range requiredScopes {
		strs[i] = string(s)
	}
	return identityauth.HasAnyScope(userScopes, strs, readWritePairs)
}

// HasAllScopes checks if a user has all of the required scopes.
// An empty requirement is vacuously satisfied (the registry's established
// contract); the shared module treats an empty list as unsatisfied, so that
// case is handled here before delegating.
func HasAllScopes(userScopes []string, requiredScopes []Scope) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	strs := make([]string, len(requiredScopes))
	for i, s := range requiredScopes {
		strs[i] = string(s)
	}
	return identityauth.HasAllScopes(userScopes, strs, readWritePairs)
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

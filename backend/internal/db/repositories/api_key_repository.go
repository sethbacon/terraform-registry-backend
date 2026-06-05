// Package repositories - api_key_repository.go aliases the APIKeyRepository from
// the shared identity store.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

// APIKeyRepository handles API key database operations.
type APIKeyRepository = identitystore.APIKeyRepository

// NewAPIKeyRepository constructs an APIKeyRepository over the given connection.
var NewAPIKeyRepository = identitystore.NewAPIKeyRepository

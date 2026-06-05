// Package repositories - token_repository.go aliases the TokenRepository (JWT
// revocation over revoked_tokens) from the shared identity store.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

// TokenRepository handles JWT revocation database operations.
type TokenRepository = identitystore.TokenRepository

// NewTokenRepository constructs a TokenRepository over the given connection.
var NewTokenRepository = identitystore.NewTokenRepository

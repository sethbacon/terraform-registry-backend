// Package repositories - user_repository.go aliases the UserRepository from the
// shared identity store. The constructor is re-exported so existing call sites
// (repositories.NewUserRepository) are unchanged. The active schema is determined
// by the connection passed in.
package repositories

import identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

// UserRepository handles user database operations.
type UserRepository = identitystore.UserRepository

// NewUserRepository constructs a UserRepository over the given connection.
var NewUserRepository = identitystore.NewUserRepository

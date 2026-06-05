// Package auth - apikey.go delegates API key generation and validation to the
// shared identity/auth package so all suite apps share one implementation.
package auth

import (
	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
)

const (
	// APIKeyLength is the length of the random part of the API key in bytes.
	APIKeyLength = identityauth.APIKeyLength

	// DisplayPrefixLength is the number of characters to show in displays and
	// used as the lookup prefix for stored keys.
	DisplayPrefixLength = identityauth.DisplayPrefixLength

	// BcryptCost is the cost factor for bcrypt hashing.
	BcryptCost = identityauth.BcryptCost
)

// GenerateAPIKey creates a new random API key with the given prefix.
// Returns: full key (to show once), bcrypt hash (to store), display prefix.
func GenerateAPIKey(prefix string) (key string, hash string, displayPrefix string, err error) {
	return identityauth.GenerateAPIKey(prefix)
}

// ValidateAPIKey checks if a provided key matches the stored hash.
func ValidateAPIKey(providedKey, storedHash string) bool {
	return identityauth.ValidateAPIKey(providedKey, storedHash)
}

// ExtractAPIKeyFromHeader extracts the API key from an Authorization header.
// Expected format: "Bearer tfr_abc123xyz...".
func ExtractAPIKeyFromHeader(header string) (string, error) {
	return identityauth.ExtractAPIKeyFromHeader(header)
}

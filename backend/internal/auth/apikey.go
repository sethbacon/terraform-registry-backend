// Package auth provides authentication primitives for the registry, including API key generation/validation and JWT creation/verification.
// Two authentication methods are supported: JWTs (issued on OIDC/username login, stateless verification) and API keys (long-lived tokens with bcrypt hashing).
// See internal/middleware/auth.go for the request-time authentication logic that uses these primitives.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// APIKeyLength is the length of the random part of the API key in bytes
	APIKeyLength = 32

	// DisplayPrefixLength is the number of characters to show in displays
	DisplayPrefixLength = 10

	// BcryptCost is the cost factor for bcrypt hashing
	BcryptCost = 12
)

// GenerateAPIKey creates a new random API key with the given prefix
// Returns: full key (to show once), bcrypt hash (to store), display prefix
func GenerateAPIKey(prefix string) (key string, hash string, displayPrefix string, err error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyLength)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 (URL-safe)
	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Construct full key: prefix_randomPart
	fullKey := fmt.Sprintf("%s_%s", prefix, randomPart)

	// Hash the full key with bcrypt
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(fullKey), BcryptCost)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to hash API key: %w", err)
	}

	// Generate display prefix (first N characters of full key)
	displayPrefixStr := fullKey
	if len(fullKey) > DisplayPrefixLength {
		displayPrefixStr = fullKey[:DisplayPrefixLength]
	}

	return fullKey, string(hashBytes), displayPrefixStr, nil
}

// ValidateAPIKey checks if a provided key matches the stored hash
func ValidateAPIKey(providedKey, storedHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(providedKey))
	return err == nil
}

// ExtractAPIKeyFromHeader extracts the API key from an Authorization header
// Expected format: "Bearer tfr_abc123xyz..."
func ExtractAPIKeyFromHeader(header string) (string, error) {
	if header == "" {
		return "", errors.New("authorization header is empty")
	}

	// Check if it starts with "Bearer "
	if !strings.HasPrefix(header, "Bearer ") {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	// Extract the key (remove "Bearer " prefix)
	key := strings.TrimPrefix(header, "Bearer ")
	key = strings.TrimSpace(key)

	if key == "" {
		return "", errors.New("API key is empty after Bearer prefix")
	}

	return key, nil
}

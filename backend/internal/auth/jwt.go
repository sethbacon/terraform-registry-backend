// Package auth - jwt.go handles JWT token creation, signing, and verification
// using a shared secret, including lazy secret initialization and claims parsing.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	// jwtSecret holds the validated JWT secret
	jwtSecret     string
	jwtSecretOnce sync.Once
	jwtSecretErr  error
)

// Claims represents the JWT claims structure
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Scopes []string `json:"scopes,omitempty"`
	JTI    string   `json:"jti"`
	jwt.RegisteredClaims
}

// isDevMode checks if we're in development mode (duplicated here to avoid import cycle)
func isDevMode() bool {
	devMode := os.Getenv("DEV_MODE")
	nodeEnv := os.Getenv("NODE_ENV")

	return devMode == "true" || devMode == "1" ||
		nodeEnv == "development"
}

// generateRandomSecret creates a cryptographically secure random secret.
// Returns an error instead of a predictable fallback if the CSPRNG fails.
func generateRandomSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random JWT secret: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateJWTSecret checks that the JWT secret is properly configured.
// In production, this will fail if TFR_JWT_SECRET is not set.
// In dev mode, it will generate a random secret and log a warning.
// Call this at application startup.
func ValidateJWTSecret() error {
	jwtSecretOnce.Do(func() {
		secret := os.Getenv("TFR_JWT_SECRET")

		if secret == "" {
			if isDevMode() {
				// In dev mode, generate a random ephemeral secret. This is
				// acceptable because it resets on every restart — the only
				// consequence is that sessions don't persist across restarts.
				randomSecret, err := generateRandomSecret()
				if err != nil {
					jwtSecretErr = err
					return
				}
				jwtSecret = randomSecret
				log.Printf("WARNING: TFR_JWT_SECRET not set. Using auto-generated secret for development.")
				log.Printf("WARNING: Sessions will not persist across restarts. Set TFR_JWT_SECRET for persistent sessions.")
			} else {
				// In production, fail fast
				jwtSecretErr = errors.New("SECURITY ERROR: TFR_JWT_SECRET environment variable is required in production. " +
					"Generate a secure secret with: openssl rand -hex 32")
			}
			return
		}

		// Validate secret length (minimum 32 characters recommended)
		if len(secret) < 32 {
			log.Printf("WARNING: TFR_JWT_SECRET is shorter than recommended 32 characters. Consider using a longer secret.")
		}

		jwtSecret = secret
	})

	return jwtSecretErr
}

// GetJWTSecret retrieves the validated JWT secret.
// Panics if ValidateJWTSecret() hasn't been called or failed.
func GetJWTSecret() string {
	if jwtSecret == "" {
		// If ValidateJWTSecret wasn't called, try to validate now
		if err := ValidateJWTSecret(); err != nil {
			panic(err)
		}
	}
	return jwtSecret
}

// GenerateJWT creates a JWT token for an authenticated user.
// Scopes are embedded in the token so the auth middleware can authorize
// requests without a database round-trip on every request.
func GenerateJWT(userID, email string, scopes []string, expiresIn time.Duration) (string, error) {
	if expiresIn == 0 {
		expiresIn = 1 * time.Hour // Default to 1 hour
	}

	claims := &Claims{
		UserID: userID,
		Email:  email,
		Scopes: scopes,
		JTI:    uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "terraform-registry",
			Subject:   userID,
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := GetJWTSecret()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT parses and validates a JWT token
func ValidateJWT(tokenString string) (*Claims, error) {
	secret := GetJWTSecret()

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	return claims, nil
}

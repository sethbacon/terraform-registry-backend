// Package auth - jwt.go handles JWT token creation, signing, and verification
// using a shared secret, including lazy secret initialization and claims parsing.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	// jwtSecret holds the validated JWT secret
	jwtSecret     string
	jwtSecretOnce sync.Once
	jwtSecretErr  error

	// jwtSecretPtr is the atomically-swappable signing key used when
	// TFR_JWT_SECRET_FILE is configured.  When non-nil, GenerateJWT and
	// ValidateJWT use this instead of the static jwtSecret.
	jwtSecretPtr atomic.Pointer[[]byte]

	// jwtPreviousSecretPtr holds the previous signing key during the overlap
	// period of a key rotation.  ValidateJWT tries the current key first,
	// then falls back to this key if verification fails.
	jwtPreviousSecretPtr atomic.Pointer[[]byte]
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
	// If a file-watched secret is active, use that
	if ptr := jwtSecretPtr.Load(); ptr != nil {
		return string(*ptr)
	}
	if jwtSecret == "" {
		// If ValidateJWTSecret wasn't called, try to validate now
		if err := ValidateJWTSecret(); err != nil {
			panic(err)
		}
	}
	return jwtSecret
}

// StartJWTSecretFileWatch begins watching the file at secretFilePath for
// changes.  When the file is modified, the signing key is atomically swapped.
// The previous key is kept for overlapDuration to allow in-flight tokens
// signed with the old key to still validate.
//
// This function should be called once at startup when TFR_JWT_SECRET_FILE is set.
// It returns a stop function that should be called during shutdown.
func StartJWTSecretFileWatch(secretFilePath string, overlapDuration time.Duration) (stop func(), err error) {
	if overlapDuration <= 0 {
		overlapDuration = 5 * time.Minute
	}

	// Read the initial secret
	data, err := os.ReadFile(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT secret file %q: %w", secretFilePath, err)
	}
	secret := trimSecretBytes(data)
	jwtSecretPtr.Store(&secret)
	slog.Info("JWT secret loaded from file", "path", secretFilePath, "length", len(secret))

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	if err := watcher.Add(secretFilePath); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch JWT secret file %q: %w", secretFilePath, err)
	}

	stopCh := make(chan struct{})

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					newData, readErr := os.ReadFile(secretFilePath)
					if readErr != nil {
						slog.Error("failed to read updated JWT secret file", "path", secretFilePath, "error", readErr)
						continue
					}
					newSecret := trimSecretBytes(newData)
					if len(newSecret) == 0 {
						slog.Warn("JWT secret file is empty after update, keeping previous secret", "path", secretFilePath)
						continue
					}

					// Save current as previous for the overlap period
					current := jwtSecretPtr.Load()
					if current != nil {
						jwtPreviousSecretPtr.Store(current)
						// Schedule clearing the previous secret after the overlap
						time.AfterFunc(overlapDuration, func() {
							jwtPreviousSecretPtr.Store(nil)
							slog.Info("JWT previous secret cleared after overlap period")
						})
					}

					jwtSecretPtr.Store(&newSecret)
					slog.Info("JWT secret reloaded from file", "path", secretFilePath, "length", len(newSecret))
				}
			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("JWT secret file watcher error", "error", watchErr)
			case <-stopCh:
				watcher.Close()
				return
			}
		}
	}()

	return func() { close(stopCh) }, nil
}

// trimSecretBytes removes trailing newlines and spaces from a secret read from a file.
func trimSecretBytes(data []byte) []byte {
	// Trim trailing whitespace/newlines
	end := len(data)
	for end > 0 && (data[end-1] == '\n' || data[end-1] == '\r' || data[end-1] == ' ' || data[end-1] == '\t') {
		end--
	}
	result := make([]byte, end)
	copy(result, data[:end])
	return result
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

// ValidateJWT parses and validates a JWT token.
// When a previous key is available (during key rotation overlap), validation
// tries the current key first, then falls back to the previous key.
func ValidateJWT(tokenString string) (*Claims, error) {
	secret := GetJWTSecret()

	claims, err := validateJWTWithSecret(tokenString, secret)
	if err == nil {
		return claims, nil
	}

	// Try previous secret during overlap period
	if prevPtr := jwtPreviousSecretPtr.Load(); prevPtr != nil {
		prevClaims, prevErr := validateJWTWithSecret(tokenString, string(*prevPtr))
		if prevErr == nil {
			return prevClaims, nil
		}
	}

	return nil, err
}

// validateJWTWithSecret validates a JWT token against a specific secret.
func validateJWTWithSecret(tokenString, secret string) (*Claims, error) {
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

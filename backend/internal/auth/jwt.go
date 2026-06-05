// Package auth - jwt.go resolves the JWT signing secret (from the environment or
// a watched file) and delegates token creation/validation to the shared identity
// TokenManager. The TokenManager owns signing, validation, JTI stamping and the
// previous-key overlap during rotation; this file keeps the registry-specific
// secret resolution and the fsnotify file watch that drives rotation.
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
	"time"

	"github.com/fsnotify/fsnotify"

	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// jwtIssuer stamps the iss claim on tokens this service generates.
const jwtIssuer = "terraform-registry"

// Claims is the suite identity JWT claims type, re-exported so existing call
// sites keep referring to auth.Claims. It carries a JTI used for revocation.
type Claims = identityauth.Claims

var (
	// jwtSecret holds the current effective signing secret (env or file). It is
	// kept in sync with the TokenManager's current secret so GetJWTSecret can
	// report it for diagnostics and tests.
	jwtSecret     string
	jwtSecretOnce sync.Once
	jwtSecretErr  error

	// tokenManager performs the actual signing/validation. Constructed once the
	// secret is resolved; the file watch swaps its secret via RotateSecret.
	tokenManager *identityauth.TokenManager
)

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

// ValidateJWTSecret checks that the JWT secret is properly configured and
// constructs the shared TokenManager. In production it fails if TFR_JWT_SECRET
// is not set; in dev mode it generates a random ephemeral secret and warns.
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
				return
			}
		} else {
			// Validate secret length (minimum 32 characters recommended)
			if len(secret) < 32 {
				log.Printf("WARNING: TFR_JWT_SECRET is shorter than recommended 32 characters. Consider using a longer secret.")
			}
			jwtSecret = secret
		}

		tokenManager = identityauth.NewTokenManager(jwtSecret, jwtIssuer)
	})

	return jwtSecretErr
}

// GetJWTSecret retrieves the current effective JWT secret, validating lazily if
// ValidateJWTSecret has not been called.
func GetJWTSecret() string {
	if jwtSecret == "" {
		if err := ValidateJWTSecret(); err != nil {
			panic(err)
		}
	}
	return jwtSecret
}

// GenerateJWT creates a JWT for an authenticated user, delegating to the shared
// identity TokenManager. Scopes are embedded so the auth middleware can
// authorize without a database round-trip; a unique JTI is stamped for revocation.
func GenerateJWT(userID, email string, scopes []string, expiresIn time.Duration) (string, error) {
	_ = GetJWTSecret() // ensure the secret is validated and the TokenManager exists
	return tokenManager.Generate(userID, email, scopes, expiresIn)
}

// ValidateJWT parses and validates a JWT via the shared identity TokenManager.
// During a key rotation overlap the TokenManager also tries the previous secret.
func ValidateJWT(tokenString string) (*Claims, error) {
	_ = GetJWTSecret()
	return tokenManager.Validate(tokenString)
}

// StartJWTSecretFileWatch begins watching the file at secretFilePath for changes.
// When the file is modified, the signing secret is rotated on the TokenManager;
// the previous key remains valid for overlapDuration so in-flight tokens signed
// with the old key still validate.
//
// Call this once at startup when TFR_JWT_SECRET_FILE is set. It returns a stop
// function that should be called during shutdown.
func StartJWTSecretFileWatch(secretFilePath string, overlapDuration time.Duration) (stop func(), err error) {
	if overlapDuration <= 0 {
		overlapDuration = 5 * time.Minute
	}

	// Ensure the TokenManager exists (constructed from the env/dev secret).
	_ = GetJWTSecret()

	// Read the initial secret and make the file the source of truth. The env
	// secret is dropped as a valid previous key (no tokens were signed with it
	// before the file loaded).
	data, err := os.ReadFile(secretFilePath) // #nosec G304 -- path comes from server config, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT secret file %q: %w", secretFilePath, err)
	}
	secret := trimSecretBytes(data)
	tokenManager.RotateSecret(secret)
	tokenManager.ClearPreviousSecret()
	jwtSecret = string(secret)
	slog.Info("JWT secret loaded from file", "path", secretFilePath, "length", len(secret))

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	if err := watcher.Add(secretFilePath); err != nil {
		watcher.Close() // #nosec G104 -- cleanup during error return; main error is returned below
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
					newData, readErr := os.ReadFile(secretFilePath) // #nosec G304 -- path comes from server config, not user input
					if readErr != nil {
						slog.Error("failed to read updated JWT secret file", "path", secretFilePath, "error", readErr)
						continue
					}
					newSecret := trimSecretBytes(newData)
					if len(newSecret) == 0 {
						slog.Warn("JWT secret file is empty after update, keeping previous secret", "path", secretFilePath)
						continue
					}

					// Skip if unchanged (fsnotify may fire multiple events per write).
					if string(newSecret) == jwtSecret {
						continue
					}

					// Rotate: the outgoing secret stays valid for the overlap window.
					tokenManager.RotateSecret(newSecret)
					jwtSecret = string(newSecret)
					time.AfterFunc(overlapDuration, func() {
						tokenManager.ClearPreviousSecret()
						slog.Info("JWT previous secret cleared after overlap period")
					})
					slog.Info("JWT secret reloaded from file", "path", secretFilePath, "length", len(newSecret))
				}
			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("JWT secret file watcher error", "error", watchErr)
			case <-stopCh:
				watcher.Close() // #nosec G104 -- best-effort cleanup on shutdown
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

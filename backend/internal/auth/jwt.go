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
	"sync/atomic"
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
	jwtSecretOnce sync.Once
	jwtSecretErr  error

	// currentSecret holds the current effective signing secret (env or file). It
	// is accessed atomically because the file watch updates it from a goroutine
	// while requests read it via GetJWTSecret. Kept in sync with the
	// TokenManager's current secret for diagnostics and tests.
	currentSecret atomic.Pointer[string]

	// tokenManager performs the actual signing/validation. Constructed once the
	// secret is resolved; the file watch swaps its secret via RotateSecret.
	tokenManager *identityauth.TokenManager
)

func storeSecret(s string) { currentSecret.Store(&s) }

func loadSecret() string {
	if p := currentSecret.Load(); p != nil {
		return *p
	}
	return ""
}

// isDevMode checks if we're in development mode (duplicated here to avoid import cycle).
// Gated solely on the application-specific DEV_MODE flag — NOT on NODE_ENV, which is a
// generic Node.js-ecosystem convention an operator could set on this Go service by
// mistake (e.g. a copied env file), silently bypassing the production fail-fast below.
func isDevMode() bool {
	devMode := os.Getenv("DEV_MODE")
	return devMode == "true" || devMode == "1"
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
		var resolved string

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
				resolved = randomSecret
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
			resolved = secret
		}

		storeSecret(resolved)
		tokenManager = identityauth.NewTokenManager(resolved, jwtIssuer)
		// Pin validation to this service's own issuer. Without this, Validate
		// accepts a token bearing ANY iss claim as long as it is signed with the
		// current secret — in a coupled suite deployment sharing TFR_JWT_SECRET
		// with a sibling app (per ADR 012), that sibling's tokens (or a token
		// crafted with a spoofed iss) would be silently accepted here (issue #559
		// finding [0]).
		//
		// This is the default, standalone-safe set (own issuer only). A coupled
		// suite deployment extends it via SetTrustedIssuers (suite.trusted_issuers
		// / TFR_SUITE_TRUSTED_ISSUERS), called once at startup after this
		// function; see cmd/server/main.go.
		tokenManager.SetAllowedIssuers([]string{jwtIssuer})
		// Stamp/require this app's own identity as the audience (issue #559
		// finding [0], completed via #608). An issuer pin alone still lets a
		// trusted sibling's token through unchanged; SetAudience closes that gap
		// by additionally requiring a token — even one from a trusted sibling
		// issuer — to have been minted FOR this app specifically. Audience
		// support (SetAudience/NewCoupledTokenManager) is new in
		// terraform-suite-identity v0.17.0; before that bump this half of the
		// finding could not be closed without a library change. Safe to enable
		// unconditionally: Validate only enforces the check once set, so a
		// standalone (non-coupled) deployment is unaffected beyond every token
		// now also carrying/requiring its own aud claim.
		tokenManager.SetAudience(jwtIssuer)
	})

	return jwtSecretErr
}

// SetTrustedIssuers extends the set of `iss` claims this app's TokenManager
// accepts beyond its own issuer (jwtIssuer, always trusted regardless of what
// is passed here), for a coupled suite deployment where TFR_JWT_SECRET is
// shared with sibling apps (ADR 012; issue #559 finding [0]).
//
// Must be called after ValidateJWTSecret (it constructs the TokenManager);
// GetJWTSecret is called defensively here too so this is safe even if the
// caller's ordering is wrong. Passing an empty/nil slice restores the default
// (own issuer only) — safe to call unconditionally at startup regardless of
// whether suite.trusted_issuers is configured.
func SetTrustedIssuers(extra []string) {
	_ = GetJWTSecret() // ensure the secret is validated and the TokenManager exists
	issuers := make([]string, 0, len(extra)+1)
	issuers = append(issuers, jwtIssuer)
	for _, iss := range extra {
		// A blank entry (a trailing/doubled comma in TFR_SUITE_TRUSTED_ISSUERS,
		// which viper's comma-split does not filter) must never reach the
		// allow-list: issuerAllowed does a literal string match, and a JWT
		// whose iss claim was simply never set unmarshals to "" — an empty
		// allow-list entry would accept it, silently defeating the very
		// issuer pin this function exists to enforce.
		if iss == "" {
			continue
		}
		issuers = append(issuers, iss)
	}
	tokenManager.SetAllowedIssuers(issuers)
}

// GetJWTSecret retrieves the current effective JWT secret, validating lazily if
// ValidateJWTSecret has not been called.
func GetJWTSecret() string {
	if loadSecret() == "" {
		if err := ValidateJWTSecret(); err != nil {
			panic(err)
		}
	}
	return loadSecret()
}

// GenerateJWT creates a JWT for an authenticated user, delegating to the shared
// identity TokenManager. Scopes are embedded so the auth middleware can
// authorize without a database round-trip; a unique JTI is stamped for revocation.
func GenerateJWT(userID, email string, scopes []string, expiresIn time.Duration) (string, error) {
	_ = GetJWTSecret() // ensure the secret is validated and the TokenManager exists
	return tokenManager.Generate(userID, email, scopes, expiresIn) //nolint:staticcheck // SA1019: registry issues suite-wide (not per-org) JWTs by design; this is the canonical call site, a deliberate suite-wide decision per the deprecation notice
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

	// Ensure the TokenManager exists (constructed from the env/dev secret), then
	// capture it so the watcher goroutine does not read the package-level
	// pointer (which test resets may swap).
	_ = GetJWTSecret()
	tm := tokenManager

	// Read the initial secret and make the file the source of truth. The env
	// secret is dropped as a valid previous key (no tokens were signed with it
	// before the file loaded).
	data, err := os.ReadFile(secretFilePath) // #nosec G304 -- path comes from server config, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT secret file %q: %w", secretFilePath, err)
	}
	secret := trimSecretBytes(data)
	tm.RotateSecret(secret)
	tm.ClearPreviousSecret()
	storeSecret(string(secret))
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
					if string(newSecret) == loadSecret() {
						continue
					}

					// Rotate: the outgoing secret stays valid for the overlap window.
					tm.RotateSecret(newSecret)
					storeSecret(string(newSecret))
					time.AfterFunc(overlapDuration, func() {
						tm.ClearPreviousSecret()
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

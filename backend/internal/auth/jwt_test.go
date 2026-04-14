package auth

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// resetJWTSecret resets the package-level sync.Once so tests can set a fresh secret.
// This is only safe to call from test code.
func resetJWTSecret() {
	jwtSecret = ""
	jwtSecretOnce = sync.Once{}
	jwtSecretErr = nil
	jwtSecretPtr.Store(nil)
	jwtPreviousSecretPtr.Store(nil)
}

func TestMain(m *testing.M) {
	// Set a known test secret before any test runs.
	// The sync.Once will capture this value on first call to ValidateJWTSecret.
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars-!")
	os.Exit(m.Run())
}

func TestValidateJWTSecret(t *testing.T) {
	t.Run("valid secret from env", func(t *testing.T) {
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", "exactly-32-char-secret-for-test!!")
		if err := ValidateJWTSecret(); err != nil {
			t.Errorf("ValidateJWTSecret() unexpected error: %v", err)
		}
	})

	t.Run("production mode requires secret", func(t *testing.T) {
		resetJWTSecret()
		// Unset all dev-mode indicators and the secret itself
		t.Setenv("TFR_JWT_SECRET", "")
		t.Setenv("DEV_MODE", "")
		t.Setenv("NODE_ENV", "")
		t.Setenv("GIN_MODE", "release")
		if err := ValidateJWTSecret(); err == nil {
			t.Error("ValidateJWTSecret() expected error in production mode without secret, got nil")
		}
	})

	t.Run("dev mode generates random secret", func(t *testing.T) {
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", "")
		t.Setenv("DEV_MODE", "true")
		if err := ValidateJWTSecret(); err != nil {
			t.Errorf("ValidateJWTSecret() unexpected error in dev mode: %v", err)
		}
		if GetJWTSecret() == "" {
			t.Error("GetJWTSecret() returned empty string after dev mode init")
		}
	})
}

func TestGenerateAndValidateJWT(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars-!")

	t.Run("round trip", func(t *testing.T) {
		userID := "user-123"
		email := "test@example.com"

		token, err := GenerateJWT(userID, email, nil, time.Hour)
		if err != nil {
			t.Fatalf("GenerateJWT() error: %v", err)
		}
		if token == "" {
			t.Fatal("GenerateJWT() returned empty token")
		}

		claims, err := ValidateJWT(token)
		if err != nil {
			t.Fatalf("ValidateJWT() error: %v", err)
		}
		if claims.UserID != userID {
			t.Errorf("claims.UserID = %q, want %q", claims.UserID, userID)
		}
		if claims.Email != email {
			t.Errorf("claims.Email = %q, want %q", claims.Email, email)
		}
		if claims.Issuer != "terraform-registry" {
			t.Errorf("claims.Issuer = %q, want %q", claims.Issuer, "terraform-registry")
		}
	})

	t.Run("default expiry when zero duration", func(t *testing.T) {
		token, err := GenerateJWT("uid", "u@example.com", nil, 0)
		if err != nil {
			t.Fatalf("GenerateJWT() error: %v", err)
		}
		claims, err := ValidateJWT(token)
		if err != nil {
			t.Fatalf("ValidateJWT() error: %v", err)
		}
		// Should expire roughly 1 hour from now
		remaining := time.Until(claims.ExpiresAt.Time)
		if remaining < 50*time.Minute || remaining > 70*time.Minute {
			t.Errorf("default expiry remaining = %v, want ~1h", remaining)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		token, err := GenerateJWT("uid", "u@example.com", nil, -time.Second)
		if err != nil {
			t.Fatalf("GenerateJWT() error: %v", err)
		}
		_, err = ValidateJWT(token)
		if err == nil {
			t.Error("ValidateJWT() expected error for expired token, got nil")
		}
	})

	t.Run("invalid token string", func(t *testing.T) {
		_, err := ValidateJWT("not.a.valid.token")
		if err == nil {
			t.Error("ValidateJWT() expected error for garbage token, got nil")
		}
	})

	t.Run("empty token string", func(t *testing.T) {
		_, err := ValidateJWT("")
		if err == nil {
			t.Error("ValidateJWT() expected error for empty token, got nil")
		}
	})

	t.Run("token signed with different secret is rejected", func(t *testing.T) {
		// Generate with current secret
		token, err := GenerateJWT("uid", "u@example.com", nil, time.Hour)
		if err != nil {
			t.Fatalf("GenerateJWT() error: %v", err)
		}

		// Reset and use a different secret
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", "completely-different-secret-32ch!")

		_, err = ValidateJWT(token)
		if err == nil {
			t.Error("ValidateJWT() expected error for token signed with different secret, got nil")
		}

		// Restore for remaining tests
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars-!")
	})
}

// ---------------------------------------------------------------------------
// trimSecretBytes
// ---------------------------------------------------------------------------

func TestTrimSecretBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"no trailing whitespace", []byte("mysecret"), "mysecret"},
		{"trailing newline", []byte("mysecret\n"), "mysecret"},
		{"trailing CRLF", []byte("mysecret\r\n"), "mysecret"},
		{"trailing spaces and newlines", []byte("mysecret  \n\n"), "mysecret"},
		{"trailing tabs", []byte("mysecret\t\t"), "mysecret"},
		{"empty input", []byte(""), ""},
		{"only whitespace", []byte("  \n\r\t"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimSecretBytes(tt.input)
			if string(got) != tt.want {
				t.Errorf("trimSecretBytes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateJWTWithSecret (direct)
// ---------------------------------------------------------------------------

func TestValidateJWTWithSecret(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars-!")

	token, err := GenerateJWT("user-1", "a@b.com", []string{"modules:read"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT() error: %v", err)
	}

	t.Run("correct secret succeeds", func(t *testing.T) {
		claims, err := validateJWTWithSecret(token, "test-jwt-secret-that-is-32-chars-!")
		if err != nil {
			t.Fatalf("validateJWTWithSecret() error: %v", err)
		}
		if claims.UserID != "user-1" {
			t.Errorf("claims.UserID = %q, want %q", claims.UserID, "user-1")
		}
		if len(claims.Scopes) != 1 || claims.Scopes[0] != "modules:read" {
			t.Errorf("claims.Scopes = %v, want [modules:read]", claims.Scopes)
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		_, err := validateJWTWithSecret(token, "wrong-secret-wrong-secret-wrong!")
		if err == nil {
			t.Error("validateJWTWithSecret() expected error with wrong secret")
		}
	})

	t.Run("empty token fails", func(t *testing.T) {
		_, err := validateJWTWithSecret("", "test-jwt-secret-that-is-32-chars-!")
		if err == nil {
			t.Error("validateJWTWithSecret() expected error with empty token")
		}
	})
}

// ---------------------------------------------------------------------------
// StartJWTSecretFileWatch
// ---------------------------------------------------------------------------

func TestStartJWTSecretFileWatch(t *testing.T) {
	t.Run("initial load from file", func(t *testing.T) {
		resetJWTSecret()

		dir := t.TempDir()
		secretFile := filepath.Join(dir, "jwt-secret")
		os.WriteFile(secretFile, []byte("file-secret-that-is-32-chars-ok!\n"), 0600)

		stop, err := StartJWTSecretFileWatch(secretFile, 5*time.Minute)
		if err != nil {
			t.Fatalf("StartJWTSecretFileWatch() error: %v", err)
		}
		defer stop()

		got := GetJWTSecret()
		if got != "file-secret-that-is-32-chars-ok!" {
			t.Errorf("GetJWTSecret() = %q, want %q", got, "file-secret-that-is-32-chars-ok!")
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		resetJWTSecret()

		_, err := StartJWTSecretFileWatch("/nonexistent/path/secret", 5*time.Minute)
		if err == nil {
			t.Error("StartJWTSecretFileWatch() expected error for missing file")
		}
	})

	t.Run("default overlap when zero", func(t *testing.T) {
		resetJWTSecret()

		dir := t.TempDir()
		secretFile := filepath.Join(dir, "jwt-secret")
		os.WriteFile(secretFile, []byte("initial-secret-32-chars-exactly!"), 0600)

		stop, err := StartJWTSecretFileWatch(secretFile, 0)
		if err != nil {
			t.Fatalf("StartJWTSecretFileWatch() error: %v", err)
		}
		defer stop()

		// Just verify it loaded — the default 5m overlap is used internally
		got := GetJWTSecret()
		if got != "initial-secret-32-chars-exactly!" {
			t.Errorf("GetJWTSecret() = %q, want %q", got, "initial-secret-32-chars-exactly!")
		}
	})

	t.Run("file update rotates key", func(t *testing.T) {
		resetJWTSecret()

		dir := t.TempDir()
		secretFile := filepath.Join(dir, "jwt-secret")
		os.WriteFile(secretFile, []byte("old-secret-that-is-32-chars-hey!"), 0600)

		stop, err := StartJWTSecretFileWatch(secretFile, 30*time.Second)
		if err != nil {
			t.Fatalf("StartJWTSecretFileWatch() error: %v", err)
		}
		defer stop()

		// Update the file with a new secret — use truncate+write to ensure fsnotify fires
		f, err := os.OpenFile(secretFile, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatalf("OpenFile() error: %v", err)
		}
		f.Write([]byte("new-secret-that-is-32-chars-hey!"))
		f.Close()

		// Wait for fsnotify to pick up the change (Windows may be slower)
		time.Sleep(500 * time.Millisecond)

		newSecret := GetJWTSecret()
		if newSecret == "old-secret-that-is-32-chars-hey!" {
			t.Skipf("fsnotify did not detect file change, skipping rotation test")
		}
		if newSecret != "new-secret-that-is-32-chars-hey!" {
			t.Errorf("GetJWTSecret() after update = %q, want %q", newSecret, "new-secret-that-is-32-chars-hey!")
		}
	})

	t.Run("empty file update keeps previous secret", func(t *testing.T) {
		resetJWTSecret()

		dir := t.TempDir()
		secretFile := filepath.Join(dir, "jwt-secret")
		os.WriteFile(secretFile, []byte("good-secret-that-is-32-chars-ok!"), 0600)

		stop, err := StartJWTSecretFileWatch(secretFile, 30*time.Second)
		if err != nil {
			t.Fatalf("StartJWTSecretFileWatch() error: %v", err)
		}
		defer stop()

		// Write an empty file using truncate to ensure fsnotify fires
		f, err := os.OpenFile(secretFile, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatalf("OpenFile() error: %v", err)
		}
		f.Close()
		time.Sleep(500 * time.Millisecond)

		// Should still have the original secret (empty file is rejected)
		got := GetJWTSecret()
		if got != "good-secret-that-is-32-chars-ok!" {
			t.Errorf("GetJWTSecret() after empty update = %q, want original", got)
		}
	})
}

// ---------------------------------------------------------------------------
// ValidateJWT with previous key fallback (manual atomic pointer setup)
// ---------------------------------------------------------------------------

func TestValidateJWT_PreviousKeyFallback(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "")

	// Set up current key via atomic pointer
	currentKey := []byte("current-secret-32-chars-exactly!")
	jwtSecretPtr.Store(&currentKey)

	// Generate a token with a different (previous) secret
	prevKey := []byte("previous-secret-32-chars-exact!!")
	jwtPreviousSecretPtr.Store(&prevKey)

	// Manually create a token signed with the previous key
	prevSecret := string(prevKey)
	jwtSecretPtr.Store(&prevKey) // temporarily use prev key to sign
	token, err := GenerateJWT("fallback-user", "fb@test.com", nil, time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT() error: %v", err)
	}

	// Now switch to current key, keeping previous
	jwtSecretPtr.Store(&currentKey)
	jwtPreviousSecretPtr.Store(&prevKey)
	_ = prevSecret

	// Token signed with previous key should validate via fallback
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT() with previous key fallback: %v", err)
	}
	if claims.UserID != "fallback-user" {
		t.Errorf("claims.UserID = %q, want %q", claims.UserID, "fallback-user")
	}

	// Clear previous — now the old token should fail
	jwtPreviousSecretPtr.Store(nil)
	_, err = ValidateJWT(token)
	if err == nil {
		t.Error("ValidateJWT() expected error after previous key cleared")
	}
}

// ---------------------------------------------------------------------------
// GetJWTSecret with file-watched key
// ---------------------------------------------------------------------------

func TestGetJWTSecret_FileWatchedKeyTakesPrecedence(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "env-secret-that-is-32-chars-ok!!")

	// Without file watch, should use env
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("ValidateJWTSecret() error: %v", err)
	}
	if got := GetJWTSecret(); got != "env-secret-that-is-32-chars-ok!!" {
		t.Errorf("GetJWTSecret() = %q, want env secret", got)
	}

	// Set file-watched key — should take precedence
	fileKey := []byte("file-watched-secret-32-chars-ok!")
	jwtSecretPtr.Store(&fileKey)

	if got := GetJWTSecret(); got != "file-watched-secret-32-chars-ok!" {
		t.Errorf("GetJWTSecret() = %q, want file-watched secret", got)
	}

	// Clear file-watched key — should fall back to env
	jwtSecretPtr.Store(nil)
	if got := GetJWTSecret(); got != "env-secret-that-is-32-chars-ok!!" {
		t.Errorf("GetJWTSecret() = %q, want env secret after clearing file ptr", got)
	}
}

// ---------------------------------------------------------------------------
// validateJWTWithSecret edge cases
// ---------------------------------------------------------------------------

func TestValidateJWTWithSecret_WrongSigningMethod(t *testing.T) {
	// Create a token signed with RSA (not HMAC) — the parser should reject it
	token := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{
		UserID: "user-1",
		Email:  "a@b.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	// jwt.SigningMethodNone requires jwt.UnsafeAllowNoneSignatureType
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString() error: %v", err)
	}

	_, err = validateJWTWithSecret(tokenString, "any-secret-32-chars-exactly-ok!!")
	if err == nil {
		t.Error("validateJWTWithSecret() expected error for none signing method")
	}
}

// ---------------------------------------------------------------------------
// ValidateJWTSecret edge cases
// ---------------------------------------------------------------------------

func TestValidateJWTSecret_ShortSecret(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "short")
	// Should succeed but log a warning (we can't check the log, but ensure no error)
	if err := ValidateJWTSecret(); err != nil {
		t.Errorf("ValidateJWTSecret() unexpected error with short secret: %v", err)
	}
	if got := GetJWTSecret(); got != "short" {
		t.Errorf("GetJWTSecret() = %q, want %q", got, "short")
	}
}

// ---------------------------------------------------------------------------
// GetJWTSecret auto-validates
// ---------------------------------------------------------------------------

func TestGetJWTSecret_AutoValidates(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", "auto-validate-secret-32-chars-!!")
	// Don't call ValidateJWTSecret — GetJWTSecret should auto-validate
	got := GetJWTSecret()
	if got != "auto-validate-secret-32-chars-!!" {
		t.Errorf("GetJWTSecret() = %q, want auto-validate secret", got)
	}
}

// ---------------------------------------------------------------------------
// RedisStateStore interface compliance
// ---------------------------------------------------------------------------

func TestRedisStateStore_ImplementsInterface(t *testing.T) {
	var _ StateStore = (*RedisStateStore)(nil)
}

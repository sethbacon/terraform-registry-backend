package auth

import (
	"os"
	"sync"
	"testing"
	"time"
)

// resetJWTSecret resets the package-level sync.Once so tests can set a fresh secret.
// This is only safe to call from test code.
func resetJWTSecret() {
	jwtSecret = ""
	jwtSecretOnce = sync.Once{}
	jwtSecretErr = nil
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

		token, err := GenerateJWT(userID, email, time.Hour)
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
		token, err := GenerateJWT("uid", "u@example.com", 0)
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
		token, err := GenerateJWT("uid", "u@example.com", -time.Second)
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
		token, err := GenerateJWT("uid", "u@example.com", time.Hour)
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

package auth

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// resetJWTSecret resets the package-level sync.Once so tests can set a fresh secret.
// This is only safe to call from test code.
func resetJWTSecret() {
	currentSecret.Store(nil)
	jwtSecretOnce = sync.Once{}
	jwtSecretErr = nil
	tokenManager = nil
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
// SetTrustedIssuers (issue #559 finding [0])
// ---------------------------------------------------------------------------

func TestSetTrustedIssuers(t *testing.T) {
	resetJWTSecret()
	secret := "test-jwt-secret-that-is-32-chars-!"
	t.Setenv("TFR_JWT_SECRET", secret)
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("ValidateJWTSecret: %v", err)
	}
	// Restore the default (own-issuer-only) trust set once this test's
	// sub-tests are done, so later tests in the package aren't affected by
	// the shared package-level tokenManager.
	t.Cleanup(func() { SetTrustedIssuers(nil) })

	// A token signed with the SAME secret but a different issuer — simulating
	// a sibling app in a coupled suite deployment sharing TFR_JWT_SECRET
	// (ADR 012). The sibling also stamps this app's own identity as the
	// audience, as terraform-suite-identity's coupled-suite guidance directs a
	// well-behaved sibling to do when minting a token meant to be honored here
	// — see TestValidateJWT_AudienceEnforced below for the cases where it does
	// not (or audiences it for itself instead).
	siblingTM := identityauth.NewTokenManager(secret, "terraform-state-manager")
	siblingTM.SetAudience(jwtIssuer)
	siblingToken, err := siblingTM.Generate("user-1", "user1@example.com", nil, time.Hour)
	if err != nil {
		t.Fatalf("sibling Generate: %v", err)
	}

	t.Run("foreign issuer rejected by default", func(t *testing.T) {
		if _, err := ValidateJWT(siblingToken); err == nil {
			t.Error("expected an error validating a token from an untrusted issuer")
		}
	})

	t.Run("foreign issuer accepted once trusted", func(t *testing.T) {
		SetTrustedIssuers([]string{"terraform-state-manager"})
		t.Cleanup(func() { SetTrustedIssuers(nil) })

		claims, err := ValidateJWT(siblingToken)
		if err != nil {
			t.Fatalf("expected the sibling token to validate once trusted: %v", err)
		}
		if claims.UserID != "user-1" {
			t.Errorf("UserID = %q, want user-1", claims.UserID)
		}
	})

	t.Run("own issuer always trusted regardless of extra list", func(t *testing.T) {
		// Deliberately omit this app's own issuer from the extra list — it must
		// remain trusted regardless, since SetTrustedIssuers always adds it.
		SetTrustedIssuers([]string{"some-other-app"})
		t.Cleanup(func() { SetTrustedIssuers(nil) })

		ownToken, err := GenerateJWT("user-2", "user2@example.com", nil, time.Hour)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		if _, err := ValidateJWT(ownToken); err != nil {
			t.Errorf("own-issuer token should always validate: %v", err)
		}
	})

	t.Run("nil restores default (own issuer only)", func(t *testing.T) {
		SetTrustedIssuers([]string{"terraform-state-manager"})
		SetTrustedIssuers(nil)

		if _, err := ValidateJWT(siblingToken); err == nil {
			t.Error("expected sibling token to be rejected again after SetTrustedIssuers(nil)")
		}
	})

	// A blank entry -- e.g. from a trailing/doubled comma in
	// TFR_SUITE_TRUSTED_ISSUERS, which viper's comma-split does not filter --
	// must never reach the allow-list. issuerAllowed does a literal string
	// match, and a JWT whose iss claim was simply never set unmarshals to "";
	// an empty allow-list entry would accept such a token, silently defeating
	// the issuer pin entirely.
	t.Run("blank entry in extra list is filtered, not trusted", func(t *testing.T) {
		SetTrustedIssuers([]string{"terraform-state-manager", ""})
		t.Cleanup(func() { SetTrustedIssuers(nil) })

		noIssuerTM := identityauth.NewTokenManager(secret, "")
		noIssuerToken, err := noIssuerTM.Generate("attacker", "attacker@example.com", []string{"admin"}, time.Hour)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if _, err := ValidateJWT(noIssuerToken); err == nil {
			t.Error("a token with an empty iss claim must never validate, even with a blank entry in the trusted-issuers list")
		}

		// The real (non-blank) entry alongside it must still work.
		if _, err := ValidateJWT(siblingToken); err != nil {
			t.Errorf("legitimate sibling issuer should still be trusted: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Audience enforcement (issue #559 finding [0], completed via #608)
// ---------------------------------------------------------------------------

// TestValidateJWT_AudienceEnforced confirms ValidateJWTSecret now also stamps
// and requires this app's own audience, closing the half of #559 finding [0]
// that SetAllowedIssuers alone left open: a trusted sibling issuer is no
// longer sufficient on its own — the token must also have been minted FOR
// this app.
func TestValidateJWT_AudienceEnforced(t *testing.T) {
	resetJWTSecret()
	secret := "test-jwt-secret-that-is-32-chars-!"
	t.Setenv("TFR_JWT_SECRET", secret)
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("ValidateJWTSecret: %v", err)
	}
	t.Cleanup(func() { SetTrustedIssuers(nil) })
	SetTrustedIssuers([]string{"terraform-state-manager"})
	t.Cleanup(func() { SetTrustedIssuers(nil) })

	t.Run("own token carries own audience and validates", func(t *testing.T) {
		token, err := GenerateJWT("user-1", "user1@example.com", nil, time.Hour)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		if _, err := ValidateJWT(token); err != nil {
			t.Errorf("own token with own audience should validate: %v", err)
		}
	})

	t.Run("trusted issuer but no audience claim is rejected", func(t *testing.T) {
		// The sibling's issuer is trusted (see SetTrustedIssuers above), but this
		// token never had an audience stamped — simulating a sibling that has not
		// (yet) adopted SetAudience. Trusting the issuer must not be enough on
		// its own.
		siblingTM := identityauth.NewTokenManager(secret, "terraform-state-manager")
		token, err := siblingTM.Generate("attacker-or-unaware-sibling", "x@example.com", []string{"admin"}, time.Hour)
		if err != nil {
			t.Fatalf("sibling Generate: %v", err)
		}
		if _, err := ValidateJWT(token); err == nil {
			t.Error("a trusted-issuer token with no audience claim must be rejected once this app requires an audience")
		}
	})

	t.Run("trusted issuer but wrong audience is rejected", func(t *testing.T) {
		// The sibling stamps ITS OWN identity as the audience (i.e. mints a
		// normal token for its own use), not this app's — this must not validate
		// here even though the issuer is trusted and the secret matches.
		siblingTM := identityauth.NewTokenManager(secret, "terraform-state-manager")
		siblingTM.SetAudience("terraform-state-manager")
		token, err := siblingTM.Generate("user-1", "user1@example.com", nil, time.Hour)
		if err != nil {
			t.Fatalf("sibling Generate: %v", err)
		}
		if _, err := ValidateJWT(token); err == nil {
			t.Error("a trusted-issuer token audienced for a different app must be rejected")
		}
	})

	t.Run("trusted issuer and correct audience validates", func(t *testing.T) {
		siblingTM := identityauth.NewTokenManager(secret, "terraform-state-manager")
		siblingTM.SetAudience(jwtIssuer)
		token, err := siblingTM.Generate("user-1", "user1@example.com", nil, time.Hour)
		if err != nil {
			t.Fatalf("sibling Generate: %v", err)
		}
		if _, err := ValidateJWT(token); err != nil {
			t.Errorf("a trusted-issuer token correctly audienced for this app should validate: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// RedisStateStore interface compliance
// ---------------------------------------------------------------------------

func TestRedisStateStore_ImplementsInterface(t *testing.T) {
	var _ StateStore = (*RedisStateStore)(nil)
}

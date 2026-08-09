package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Issue #759 — three paths install an HS256 signing key; only one checked
// anything.
//
//	TFR_JWT_SECRET at startup       warned on length, failed closed on entropy
//	TFR_JWT_SECRET_FILE at startup  NO check at all — not even for emptiness
//	TFR_JWT_SECRET_FILE on rotation emptiness only
//
// The file path is the one docs/secrets-rotation.md RECOMMENDS, so the
// recommended route bypassed the fail-closed entropy check added in #742/#809
// entirely, and a whitespace-only file installed an empty HMAC key — under
// which every forged token verifies.
//
// The length half mattered on its own: the documented 32-character minimum was
// a log.Printf, and the entropy heuristic does not stand in for it. "admin123"
// and "hunter2!" are 8 characters with 8 distinct bytes, so they clear entropy
// comfortably. Both booted a production server.

// weakSecrets are rejected by the shared gate. Each names why, so a future
// change that lets one through says what it broke.
var weakSecrets = []struct{ secret, why string }{
	{"", "empty — an empty HMAC key validates every forged token"},
	{"   \n\t ", "whitespace only — trims to empty"},
	{"short", "5 chars"},
	{"admin123", "8 chars, 8 distinct bytes: passes the entropy heuristic"},
	{"hunter2!", "8 chars, passes entropy"},
	{"0123456789abcdef", "16 chars, passes entropy"},
	{strings.Repeat("a", 64), "long but a single repeated byte"},
}

// strongSecret is CSPRNG-shaped and 64 hex characters, the documented form.
const strongSecret = "9f8c2e1a7b4d6053e2c9a8f1b7d403e6c5a2f9b8d1e7c4a0396b2d5f8e1c7a4b"

func TestValidateJWTSecretStrength_RejectsWeakSecrets(t *testing.T) {
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
	for _, tc := range weakSecrets {
		t.Run(tc.why, func(t *testing.T) {
			if err := validateJWTSecretStrength(trimSecretBytes([]byte(tc.secret))); err == nil {
				t.Errorf("accepted %q (%s)", tc.secret, tc.why)
			}
		})
	}
}

func TestValidateJWTSecretStrength_AcceptsAStrongSecret(t *testing.T) {
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
	if err := validateJWTSecretStrength([]byte(strongSecret)); err != nil {
		t.Errorf("rejected a 64-character CSPRNG-shaped secret: %v", err)
	}
}

// TestValidateJWTSecretStrength_EmptyIsNeverOverridable — the opt-out exists so
// an existing deployment can restart once and rotate. It must not extend to an
// empty key, which no deployment can have a legitimate reason to run with.
func TestValidateJWTSecretStrength_EmptyIsNeverOverridable(t *testing.T) {
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "true")
	if err := validateJWTSecretStrength([]byte("")); err == nil {
		t.Error("the override accepted an EMPTY secret")
	}
	// The override does apply to short/weak, which is its purpose.
	if err := validateJWTSecretStrength([]byte("short")); err != nil {
		t.Errorf("the override should permit a weak (non-empty) secret for rotation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TFR_JWT_SECRET_FILE — the path that had no validation at all
// ---------------------------------------------------------------------------

func writeSecretFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwt.key")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestStartJWTSecretFileWatch_RejectsAWeakInitialSecret is the core regression.
//
// Returning an error is what makes cmd/server/main.go fail the boot instead of
// serving with a key that validates forged tokens.
func TestStartJWTSecretFileWatch_RejectsAWeakInitialSecret(t *testing.T) {
	for _, tc := range weakSecrets {
		t.Run(tc.why, func(t *testing.T) {
			resetJWTSecret()
			t.Setenv("TFR_JWT_SECRET", strongSecret)
			t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
			if err := ValidateJWTSecret(); err != nil {
				t.Fatalf("setup: %v", err)
			}

			stop, err := StartJWTSecretFileWatch(writeSecretFile(t, tc.secret), time.Minute)
			if err == nil {
				if stop != nil {
					stop()
				}
				t.Fatalf("a secret file containing %q (%s) was installed as the signing key",
					tc.secret, tc.why)
			}

			// And the previously-valid env secret must survive: a rejected file
			// must not leave the server with no usable key.
			if got := GetJWTSecret(); got != strongSecret {
				t.Errorf("after rejecting the file, GetJWTSecret() = %q, want the env secret", got)
			}
		})
	}
}

func TestStartJWTSecretFileWatch_AcceptsAStrongInitialSecret(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", strongSecret)
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	fileSecret := "1a2b3c4d5e6f70819273645566778899aabbccddeeff00112233445566778899"
	stop, err := StartJWTSecretFileWatch(writeSecretFile(t, fileSecret), time.Minute)
	if err != nil {
		t.Fatalf("a strong secret file was rejected: %v", err)
	}
	defer stop()

	if got := GetJWTSecret(); got != fileSecret {
		t.Errorf("GetJWTSecret() = %q, want the file secret to be in force", got)
	}
}

// TestStartJWTSecretFileWatch_TrailingNewlineIsFine — the common shape of a
// Kubernetes secret mount. A gate that rejected this would be turned off.
func TestStartJWTSecretFileWatch_TrailingNewlineIsFine(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", strongSecret)
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	fileSecret := "1a2b3c4d5e6f70819273645566778899aabbccddeeff00112233445566778899"
	stop, err := StartJWTSecretFileWatch(writeSecretFile(t, fileSecret+"\n"), time.Minute)
	if err != nil {
		t.Fatalf("a secret file with a trailing newline was rejected: %v", err)
	}
	defer stop()

	if got := GetJWTSecret(); got != fileSecret {
		t.Errorf("GetJWTSecret() = %q, want the trimmed file secret", got)
	}
}

// TestJWTSecretStrength_AppliesToEveryInstallPath is the class guard.
//
// The defect was not that one check was wrong — it was that three code paths
// installed a signing key and only one of them validated it. This asserts the
// shared gate is reachable from each, so a fourth path added later without it
// is the odd one out rather than the norm.
func TestJWTSecretStrength_AppliesToEveryInstallPath(t *testing.T) {
	const weak = "admin123" // passes entropy, fails length: the case a warning let through

	t.Run("env at startup", func(t *testing.T) {
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", weak)
		t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
		err := ValidateJWTSecret()
		if err == nil {
			t.Fatal("an 8-character TFR_JWT_SECRET booted the server")
		}
		if !strings.Contains(err.Error(), "TFR_JWT_SECRET") {
			t.Errorf("error should name the source, got: %v", err)
		}
	})

	t.Run("file at startup", func(t *testing.T) {
		resetJWTSecret()
		t.Setenv("TFR_JWT_SECRET", strongSecret)
		t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
		if err := ValidateJWTSecret(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		stop, err := StartJWTSecretFileWatch(writeSecretFile(t, weak), time.Minute)
		if err == nil {
			if stop != nil {
				stop()
			}
			t.Fatal("an 8-character secret FILE was installed as the signing key")
		}
	})
}

// TestJWTSecretFileRotation_RejectsAWeakUpdate covers the third install path.
//
// Unlike the startup paths, a bad rotation must NOT take the process down — the
// server is already serving. It keeps the previous secret and logs, matching
// the shape the empty-file case already had. Before this, the branch checked
// emptiness only, so rotating to "admin123" was installed silently.
func TestJWTSecretFileRotation_RejectsAWeakUpdate(t *testing.T) {
	resetJWTSecret()
	t.Setenv("TFR_JWT_SECRET", strongSecret)
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "")
	if err := ValidateJWTSecret(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	good := "1a2b3c4d5e6f70819273645566778899aabbccddeeff00112233445566778899"
	path := writeSecretFile(t, good)
	stop, err := StartJWTSecretFileWatch(path, time.Minute)
	if err != nil {
		t.Fatalf("StartJWTSecretFileWatch: %v", err)
	}
	defer stop()
	if got := GetJWTSecret(); got != good {
		t.Fatalf("setup: GetJWTSecret() = %q, want the file secret", got)
	}

	// Rotate to a secret that passes the entropy heuristic but is far too
	// short — the exact case the old emptiness-only check let through.
	if err := os.WriteFile(path, []byte("admin123"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Give the watcher time to observe and reject. Poll rather than sleep once,
	// so the test fails on the assertion rather than flaking on timing; if the
	// weak secret is ever installed, it is installed quickly.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if GetJWTSecret() == "admin123" {
			t.Fatal("a weak secret was installed by file rotation; the previous secret " +
				"must be kept and the update rejected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := GetJWTSecret(); got != good {
		t.Errorf("after a rejected rotation, GetJWTSecret() = %q, want the previous secret %q",
			got, good)
	}
}

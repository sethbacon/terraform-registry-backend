package mirror

import (
	"os"
	"testing"
)

// TestMain installs a JWT secret before any test runs.
//
// The mirror hands Terraform a local-storage download URL, which is now signed
// (#973) with a key derived from the JWT secret. Without one GetURL fails closed
// and the handler 500s rather than emitting an unsigned URL -- correct
// behaviour, but it needs a secret here to exercise the success path.
// auth.ValidateJWTSecret is sync.Once-guarded, so this has to happen before the
// first test rather than inside one.
func TestMain(m *testing.M) {
	if os.Getenv("TFR_JWT_SECRET") == "" {
		_ = os.Setenv("TFR_JWT_SECRET", "test-secret-for-url-signing-0123456789abcdef")
	}
	os.Exit(m.Run())
}

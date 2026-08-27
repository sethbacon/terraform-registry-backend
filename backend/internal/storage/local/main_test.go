package local

import (
	"os"
	"testing"
)

// TestMain installs a JWT secret before any test runs.
//
// GetURL now signs its output (#973) and derives the signing key from the JWT
// secret. auth.ValidateJWTSecret is sync.Once-guarded, so the value has to be in
// the environment before the FIRST test touches it -- t.Setenv inside one test
// would fix that test and leave the rest of the package depending on run order.
func TestMain(m *testing.M) {
	if os.Getenv("TFR_JWT_SECRET") == "" {
		_ = os.Setenv("TFR_JWT_SECRET", "test-secret-for-url-signing-0123456789abcdef")
	}
	os.Exit(m.Run())
}

package modules

import (
	"os"
	"testing"
)

// TestMain installs a JWT secret before any test runs.
//
// GET /v1/files/*filepath now requires a signature (#973), derived from the JWT
// secret. auth.ValidateJWTSecret is sync.Once-guarded, so the value must be in
// the environment before the FIRST test touches it -- t.Setenv inside a single
// test would leave the rest of the package dependent on run order.
func TestMain(m *testing.M) {
	if os.Getenv("TFR_JWT_SECRET") == "" {
		_ = os.Setenv("TFR_JWT_SECRET", "test-secret-for-url-signing-0123456789abcdef")
	}
	os.Exit(m.Run())
}

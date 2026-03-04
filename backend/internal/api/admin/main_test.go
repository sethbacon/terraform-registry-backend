package admin

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Set JWT secret for tests that exercise GenerateJWT (e.g., RefreshHandler success path)
	os.Setenv("TFR_JWT_SECRET", "test-admin-jwt-secret-that-is-32chars!!")
	os.Exit(m.Run())
}

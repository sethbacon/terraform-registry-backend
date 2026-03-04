package middleware

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")
	os.Exit(m.Run())
}

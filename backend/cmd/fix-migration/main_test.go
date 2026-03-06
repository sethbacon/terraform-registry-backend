package main

import (
	"os"
	"testing"
)

func TestEnv_ReturnsEnvVar(t *testing.T) {
	t.Setenv("TFR_DATABASE_HOST", "db.internal")
	if got := env("TFR_DATABASE_HOST", "localhost"); got != "db.internal" {
		t.Errorf("want 'db.internal', got %q", got)
	}
}

func TestEnv_ReturnsFallbackWhenMissing(t *testing.T) {
	os.Unsetenv("TFR_DATABASE_HOST")
	if got := env("TFR_DATABASE_HOST", "localhost"); got != "localhost" {
		t.Errorf("want fallback 'localhost', got %q", got)
	}
}

func TestEnv_ReturnsFallbackWhenEmpty(t *testing.T) {
	t.Setenv("TFR_DATABASE_HOST", "")
	if got := env("TFR_DATABASE_HOST", "localhost"); got != "localhost" {
		t.Errorf("want fallback 'localhost' for empty env var, got %q", got)
	}
}

func TestEnv_DefaultPort(t *testing.T) {
	os.Unsetenv("TFR_DATABASE_PORT")
	if got := env("TFR_DATABASE_PORT", "5432"); got != "5432" {
		t.Errorf("want default port '5432', got %q", got)
	}
}

func TestEnv_OverridePort(t *testing.T) {
	t.Setenv("TFR_DATABASE_PORT", "5433")
	if got := env("TFR_DATABASE_PORT", "5432"); got != "5433" {
		t.Errorf("want '5433', got %q", got)
	}
}

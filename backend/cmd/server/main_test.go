package main

import "testing"

func TestDevModeFromEnv(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"false": false,
		"0":     false,
		"":      false,
		"yes":   false,
	}
	for raw, want := range cases {
		if got := devModeFromEnv(raw); got != want {
			t.Errorf("devModeFromEnv(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestIsProductionLoggingLevel(t *testing.T) {
	cases := map[string]bool{
		"warn":  true,
		"error": true,
		"info":  false,
		"debug": false,
		"":      false,
	}
	for level, want := range cases {
		if got := isProductionLoggingLevel(level); got != want {
			t.Errorf("isProductionLoggingLevel(%q) = %v, want %v", level, got, want)
		}
	}
}

// TestDevModeProductionGuard_RefusesProductionCombination is the core
// assertion for issue #559 findings [5]/[11]: DEV_MODE together with a
// production-level logging.level must refuse to start.
func TestDevModeProductionGuard_RefusesProductionCombination(t *testing.T) {
	for _, level := range []string{"warn", "error"} {
		if err := devModeProductionGuard(true, level); err == nil {
			t.Errorf("devModeProductionGuard(true, %q) = nil, want an error", level)
		}
	}
}

func TestDevModeProductionGuard_AllowsDevCombination(t *testing.T) {
	for _, level := range []string{"debug", "info", ""} {
		if err := devModeProductionGuard(true, level); err != nil {
			t.Errorf("devModeProductionGuard(true, %q) = %v, want nil", level, err)
		}
	}
}

func TestDevModeProductionGuard_AllowsProductionWithoutDevMode(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", "debug"} {
		if err := devModeProductionGuard(false, level); err != nil {
			t.Errorf("devModeProductionGuard(false, %q) = %v, want nil", level, err)
		}
	}
}

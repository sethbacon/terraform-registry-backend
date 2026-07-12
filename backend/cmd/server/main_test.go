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

// TestDevModeProductionGuard_RefusesNonDebugWithoutConfirmation is the core
// assertion for issue #559 findings [5]/[11]: DEV_MODE together with any
// logging.level other than "debug" must refuse to start unless explicitly
// confirmed non-production. "info" -- this repo's own config default, and
// what its dev/test compose stacks actually run at -- is deliberately
// included: it is NOT a safe default to allow, since it is indistinguishable
// from a plausible, deliberate production choice (an earlier version of this
// guard only blocked "warn"/"error" and so let the overwhelmingly common
// misconfiguration -- DEV_MODE=true at the "info" default -- straight
// through).
func TestDevModeProductionGuard_RefusesNonDebugWithoutConfirmation(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", ""} {
		if err := devModeProductionGuard(true, level, false); err == nil {
			t.Errorf("devModeProductionGuard(true, %q, false) = nil, want an error", level)
		}
	}
}

func TestDevModeProductionGuard_AllowsDebugWithoutConfirmation(t *testing.T) {
	if err := devModeProductionGuard(true, "debug", false); err != nil {
		t.Errorf("devModeProductionGuard(true, \"debug\", false) = %v, want nil", err)
	}
}

func TestDevModeProductionGuard_AllowsNonDebugWithExplicitConfirmation(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", "", "debug"} {
		if err := devModeProductionGuard(true, level, true); err != nil {
			t.Errorf("devModeProductionGuard(true, %q, true) = %v, want nil", level, err)
		}
	}
}

func TestDevModeProductionGuard_AllowsProductionWithoutDevMode(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", "debug"} {
		if err := devModeProductionGuard(false, level, false); err != nil {
			t.Errorf("devModeProductionGuard(false, %q, false) = %v, want nil", level, err)
		}
	}
}

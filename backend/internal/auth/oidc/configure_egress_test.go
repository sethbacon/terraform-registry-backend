package oidc

import (
	"strings"
	"testing"
)

// ConfigureEgress must reject a malformed allow-list rather than installing a
// partial guard. Both directions are asserted: a bad entry errors AND leaves
// the previously-installed guard in place, so a typo in a config reload cannot
// silently widen egress by replacing a good guard with nothing.
func TestConfigureEgress_RejectsMalformedEntryAndKeepsThePriorGuard(t *testing.T) {
	if err := ConfigureEgress([]string{"keycloak", "10.0.0.0/8"}); err != nil {
		t.Fatalf("a valid allow-list was refused: %v", err)
	}
	installed := egressGuard.Load()
	if installed == nil {
		t.Fatal("a valid allow-list installed no guard")
	}

	err := ConfigureEgress([]string{"10.0.0.0/999"})
	if err == nil {
		t.Fatal("a malformed CIDR was accepted; an unparseable allow-list must fail loudly at startup rather than yield a guard nobody can reason about")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/999") {
		t.Fatalf("error = %q, want it to name the offending entry", err)
	}
	if got := egressGuard.Load(); got != installed {
		t.Fatal("a failed reconfiguration replaced the installed guard; the previous policy must survive a bad reload")
	}
}

// An empty allow-list is meaningful, not a no-op: it installs the strict default
// policy. Asserted so a future "skip when empty" optimisation cannot quietly
// leave the guard unset.
func TestConfigureEgress_EmptyAllowlistStillInstallsAGuard(t *testing.T) {
	egressGuard.Store(nil)
	if err := ConfigureEgress(nil); err != nil {
		t.Fatalf("empty allow-list refused: %v", err)
	}
	if egressGuard.Load() == nil {
		t.Fatal("empty allow-list installed no guard; nil means unguarded at the call sites, which is the opposite of the intent")
	}
}

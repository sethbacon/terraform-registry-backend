package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// encryptionKeyPreflightResult (issue #560 consistency: `upgrade preflight`
// surfaces the same fail-closed entropy signal the server itself enforces at
// startup, see router.go's shouldRejectLowEntropyEncryptionKey)
// ---------------------------------------------------------------------------

func TestEncryptionKeyPreflightResult(t *testing.T) {
	// Same low/high-entropy fixtures used by router_test.go's
	// TestShouldRejectLowEntropyEncryptionKey, for consistency.
	lowEntropyKey := "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	highEntropyKey := "3f7a9c1e5b2d8046f1a7c3e9b5d2084f"

	tests := []struct {
		name            string
		encKey          string
		overrideAllowed bool
		wantStatus      string
		wantMsgContains string
	}{
		{
			name:            "empty key -> fail",
			encKey:          "",
			overrideAllowed: false,
			wantStatus:      "fail",
			wantMsgContains: "ENCRYPTION_KEY environment variable not set",
		},
		{
			name:            "low entropy, no override -> warn about refusing to start",
			encKey:          lowEntropyKey,
			overrideAllowed: false,
			wantStatus:      "warn",
			wantMsgContains: "will refuse to start",
		},
		{
			name:            "low entropy, override allowed -> warn that override is in use",
			encKey:          lowEntropyKey,
			overrideAllowed: true,
			wantStatus:      "warn",
			wantMsgContains: "override is set so the server will still start",
		},
		{
			name:            "high entropy -> ok",
			encKey:          highEntropyKey,
			overrideAllowed: false,
			wantStatus:      "ok",
			wantMsgContains: "Present",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := encryptionKeyPreflightResult(tc.encKey, tc.overrideAllowed)
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tc.wantStatus)
			}
			if !strings.Contains(got.Message, tc.wantMsgContains) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, tc.wantMsgContains)
			}
		})
	}
}

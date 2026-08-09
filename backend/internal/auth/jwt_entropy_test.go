package auth

import "testing"

// Issue #742: TFR_JWT_SECRET and ENCRYPTION_KEY run through the same entropy
// heuristic, but only ENCRYPTION_KEY refused to boot. The asymmetry was
// backwards -- a weak ENCRYPTION_KEY exposes stored tokens and needs prior
// database access; a weak TFR_JWT_SECRET is an HS256 signing key, so guessing it
// mints a token with any scope, from outside, with no prior access.
func TestShouldRejectLowEntropyJWTSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		override bool
		want     bool
	}{
		{"repeated character padded to length is rejected", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, true},
		{"a CSPRNG-shaped secret is accepted", "9f2b7c1ad4e60835bb19fe4c7a0d3e51c8ab62f70d94e13a5c6f80b2d7e41a93", false, false},
		{"the override lets a weak secret through, once", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, false},
		{"the override does not weaken a strong secret", "9f2b7c1ad4e60835bb19fe4c7a0d3e51c8ab62f70d94e13a5c6f80b2d7e41a93", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRejectLowEntropyJWTSecret([]byte(tt.secret), tt.override); got != tt.want {
				t.Errorf("shouldRejectLowEntropyJWTSecret(%q, override=%v) = %v, want %v",
					tt.secret, tt.override, got, tt.want)
			}
		})
	}
}

// The opt-out must be OFF unless explicitly set to "true" -- an env var that
// enables on any non-empty value is one a stray "false" turns on.
func TestAllowLowEntropyJWTSecretDefaultsOff(t *testing.T) {
	for _, v := range []string{"", "false", "0", "yes", "TRUE"} {
		t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", v)
		if allowLowEntropyJWTSecret() {
			t.Errorf("value %q should not enable the override", v)
		}
	}
	t.Setenv("TFR_ALLOW_LOW_ENTROPY_JWT_SECRET", "true")
	if !allowLowEntropyJWTSecret() {
		t.Error(`"true" should enable the override`)
	}
}

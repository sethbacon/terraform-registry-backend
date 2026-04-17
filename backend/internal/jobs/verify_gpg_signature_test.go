package jobs

import "testing"

// verifyGPGSignature is a thin adapter over validation.VerifyProviderSignature.
// The underlying verification is covered extensively in the validation package;
// here we only verify the adapter correctly copies the three result fields.

func TestVerifyGPGSignature_InvalidInputs(t *testing.T) {
	// Empty content + empty signature + empty keys → Verified=false, Error set.
	result := verifyGPGSignature(nil, nil, nil)
	if result == nil {
		t.Fatal("verifyGPGSignature returned nil")
	}
	if result.Verified {
		t.Error("expected Verified=false for empty inputs")
	}
	// KeyID should be empty for invalid input.
	if result.KeyID != "" {
		t.Errorf("KeyID = %q, want empty", result.KeyID)
	}
}

func TestVerifyGPGSignature_NonSenseKeys(t *testing.T) {
	// Providing garbage keys should not panic and should return Verified=false.
	result := verifyGPGSignature([]byte("some content"), []byte("some sig"), []string{"not a real key"})
	if result == nil {
		t.Fatal("verifyGPGSignature returned nil")
	}
	if result.Verified {
		t.Error("expected Verified=false when no valid key was provided")
	}
}

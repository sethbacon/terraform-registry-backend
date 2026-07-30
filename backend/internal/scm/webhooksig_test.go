package scm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func computeTestHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyHMACSHA256Signature_Valid(t *testing.T) {
	payload := []byte(`{"event":"push"}`)
	secret := "mysecret"
	sig := computeTestHMAC(payload, secret)

	if !VerifyHMACSHA256Signature(payload, sig, secret) {
		t.Error("expected true for a valid signature with matching secret")
	}
}

func TestVerifyHMACSHA256Signature_ValidWithoutPrefix(t *testing.T) {
	payload := []byte(`{"event":"push"}`)
	secret := "mysecret"
	sig := computeTestHMAC(payload, secret)
	sig = sig[len("sha256="):] // strip the prefix; the helper must accept both forms

	if !VerifyHMACSHA256Signature(payload, sig, secret) {
		t.Error("expected true for a valid signature without the sha256= prefix")
	}
}

func TestVerifyHMACSHA256Signature_WrongSecret(t *testing.T) {
	payload := []byte("hello")
	sig := computeTestHMAC(payload, "mysecret")

	// Negative test: an attacker without the shared secret cannot forge a
	// valid signature.
	if VerifyHMACSHA256Signature(payload, sig, "wrongsecret") {
		t.Error("expected false when secret does not match")
	}
}

func TestVerifyHMACSHA256Signature_TamperedPayload(t *testing.T) {
	secret := "mysecret"
	sig := computeTestHMAC([]byte("original"), secret)

	if VerifyHMACSHA256Signature([]byte("tampered"), sig, secret) {
		t.Error("expected false when payload does not match the signed payload")
	}
}

func TestVerifyHMACSHA256Signature_InvalidHex(t *testing.T) {
	if VerifyHMACSHA256Signature([]byte("payload"), "sha256=not-hex!!", "secret") {
		t.Error("expected false for a non-hex signature")
	}
}

// TestVerifyHMACSHA256Signature_EmptySecretRejected pins the fail-closed
// policy this helper unifies GitHub and Bitbucket Data Center onto: an
// unconfigured secret means the signature cannot be verified, so the
// delivery must be rejected rather than accepted unconditionally.
func TestVerifyHMACSHA256Signature_EmptySecretRejected(t *testing.T) {
	if VerifyHMACSHA256Signature([]byte("payload"), "sha256=anything", "") {
		t.Error("expected false when no secret is configured (fail closed)")
	}
}

func TestVerifyHMACSHA256Signature_EmptySignatureRejected(t *testing.T) {
	if VerifyHMACSHA256Signature([]byte("payload"), "", "secret") {
		t.Error("expected false when no signature header is present")
	}
}

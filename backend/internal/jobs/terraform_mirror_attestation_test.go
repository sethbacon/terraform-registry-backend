// terraform_mirror_attestation_test.go tests the sync job's GitHub Artifact
// Attestation wiring: the config -> verifier decision (attestationVerifierForConfig)
// and the per-platform verify + graceful-degrade wrapper (verifyBinaryAttestation).
// Both are pure/hermetic seams — the real HTTP + Sigstore trust-root flow lives
// in internal/mirror and is covered there; a stubAttestationVerifier here lets
// the found / not-found / unavailable / failed branches be exercised without
// live network access.
package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// ---------------------------------------------------------------------------
// attestationVerifierForConfig
// ---------------------------------------------------------------------------

func TestAttestationVerifierForConfig_FlagOff_NoAttempt(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{
		Tool:                    "opa",
		UpstreamURL:             "https://github.com/open-policy-agent/opa",
		VerifyGitHubAttestation: false,
	}
	if v := attestationVerifierForConfig(cfg); v != nil {
		t.Errorf("expected nil verifier when flag is off, got %v", v)
	}
}

func TestAttestationVerifierForConfig_NonGitHubUpstream_NoAttempt(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{
		Tool:                    "terraform",
		UpstreamURL:             "https://releases.hashicorp.com",
		VerifyGitHubAttestation: true,
	}
	if v := attestationVerifierForConfig(cfg); v != nil {
		t.Errorf("expected nil verifier for non-GitHub upstream even with flag on, got %v", v)
	}
}

func TestAttestationVerifierForConfig_FlagOn_GitHubUpstream_Attempted(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{
		Tool:                    "opa",
		UpstreamURL:             "https://github.com/open-policy-agent/opa",
		VerifyGitHubAttestation: true,
	}
	v := attestationVerifierForConfig(cfg)
	if v == nil {
		t.Fatal("expected non-nil verifier when flag is on and upstream is GitHub-hosted")
	}
}

func TestAttestationVerifierForConfig_InvalidUpstream_NoAttempt(t *testing.T) {
	// A github.com URL that ParseGitHubOwnerRepo can't split into owner/repo
	// (e.g. missing the repo segment) must degrade to nil, not panic.
	cfg := &models.TerraformMirrorConfig{
		Tool:                    "opa",
		UpstreamURL:             "https://github.com/",
		VerifyGitHubAttestation: true,
	}
	if v := attestationVerifierForConfig(cfg); v != nil {
		t.Errorf("expected nil verifier for unparseable GitHub URL, got %v", v)
	}
}

// ---------------------------------------------------------------------------
// verifyBinaryAttestation
// ---------------------------------------------------------------------------

// stubAttestationVerifier is a test double for the attestationVerifier seam.
// It records whether VerifyBinaryAttestation was called so tests can assert
// the "flag off / digest unknown" fast paths never attempt verification.
type stubAttestationVerifier struct {
	err    error
	called bool
}

func (s *stubAttestationVerifier) VerifyBinaryAttestation(_ context.Context, _ string) error {
	s.called = true
	return s.err
}

func TestVerifyBinaryAttestation_NilVerifier_NoAttempt(t *testing.T) {
	if got := verifyBinaryAttestation(context.Background(), nil, "1.18.0", "linux", "amd64", "deadbeef"); got {
		t.Error("expected false for nil verifier")
	}
}

func TestVerifyBinaryAttestation_EmptyDigest_NoAttempt(t *testing.T) {
	stub := &stubAttestationVerifier{}
	if got := verifyBinaryAttestation(context.Background(), stub, "1.18.0", "linux", "amd64", ""); got {
		t.Error("expected false for empty digest")
	}
	if stub.called {
		t.Error("expected VerifyBinaryAttestation not to be called for an empty digest")
	}
}

func TestVerifyBinaryAttestation_Present_ReturnsTrue(t *testing.T) {
	// Flag on, attestation present and verified against the pinned identity:
	// the attestation_verified column should be set to true.
	stub := &stubAttestationVerifier{err: nil}
	if got := verifyBinaryAttestation(context.Background(), stub, "1.18.0", "linux", "amd64", "deadbeef"); !got {
		t.Error("expected true when verification succeeds")
	}
	if !stub.called {
		t.Error("expected VerifyBinaryAttestation to be called")
	}
}

func TestVerifyBinaryAttestation_Absent_GracefulFalse(t *testing.T) {
	// Flag on, but this (older) release predates GitHub attestations —
	// must degrade gracefully to checksum-only rather than failing the sync.
	stub := &stubAttestationVerifier{err: mirror.ErrAttestationNotFound}
	if got := verifyBinaryAttestation(context.Background(), stub, "1.10.0", "linux", "amd64", "deadbeef"); got {
		t.Error("expected false (graceful degrade) when no attestation exists")
	}
}

func TestVerifyBinaryAttestation_Unavailable_GracefulFalse(t *testing.T) {
	// Network/API unavailable (air-gapped, rate-limited) must also degrade
	// gracefully, logged as a warning, never a hard failure.
	stub := &stubAttestationVerifier{err: mirror.ErrAttestationUnavailable}
	if got := verifyBinaryAttestation(context.Background(), stub, "1.18.0", "linux", "amd64", "deadbeef"); got {
		t.Error("expected false (graceful degrade) when attestation API is unavailable")
	}
}

func TestVerifyBinaryAttestation_VerificationFailed_False(t *testing.T) {
	// A definitive verification failure (wrong identity, tampered artifact)
	// still returns false rather than panicking or propagating — the platform
	// sync continues on checksum-only, but the column is not set to true.
	stub := &stubAttestationVerifier{err: errors.New("sigstore bundle verification failed: certificate identity mismatch")}
	if got := verifyBinaryAttestation(context.Background(), stub, "1.18.0", "linux", "amd64", "deadbeef"); got {
		t.Error("expected false when verification definitively fails")
	}
}

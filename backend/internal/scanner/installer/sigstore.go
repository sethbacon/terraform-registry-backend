package installer

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// errTrustRootUnavailable is returned (wrapped) by verifySigstoreBundle when the
// Sigstore public-good trusted root cannot be loaded via TUF — e.g. no outbound
// network access in an air-gapped deployment. This is an infrastructure failure,
// not a signature mismatch: callers must never treat it as a verification failure,
// since the mandatory SHA256 checksum check still applies independently.
var errTrustRootUnavailable = errors.New("sigstore trusted root unavailable")

var (
	trustedRootOnce sync.Once
	trustedRoot     *root.TrustedRoot
	trustedRootErr  error
)

// loadTrustedRoot lazily fetches and caches the Sigstore public-good trusted root via
// TUF. The fetch happens at most once per process (sync.Once); a failure is cached too,
// so a single offline/air-gapped attempt does not retry TUF on every subsequent install.
func loadTrustedRoot() (*root.TrustedRoot, error) {
	trustedRootOnce.Do(func() {
		client, err := tuf.New(tuf.DefaultOptions())
		if err != nil {
			trustedRootErr = fmt.Errorf("create TUF client: %w", err)
			return
		}
		rootJSON, err := client.GetTarget("trusted_root.json")
		if err != nil {
			trustedRootErr = fmt.Errorf("fetch trusted_root.json: %w", err)
			return
		}
		trustedRoot, trustedRootErr = root.NewTrustedRootFromJSON(rootJSON)
	})
	return trustedRoot, trustedRootErr
}

// verifySigstoreBundle verifies that artifact was signed by a cosign keyless-signing
// Sigstore bundle (bundleJSON, the "new-bundle-format" produced by `cosign sign-blob
// --bundle`), and that the bundle's Fulcio certificate was issued for the given
// identity (Subject Alternative Name, an exact match) by the given OIDC issuer (also
// an exact match).
//
// It returns nil on a successful verification, the sentinel errTrustRootUnavailable
// (via errors.Is) when the Sigstore trust root/TUF infrastructure can't be loaded —
// callers should treat that as infra-tolerant and fall back to SHA256-only — or any
// other non-nil error on a definitive signature or identity verification failure.
func verifySigstoreBundle(bundleJSON, artifact []byte, identity, issuer string) error {
	tr, err := loadTrustedRoot()
	if err != nil {
		return fmt.Errorf("%w: %v", errTrustRootUnavailable, err)
	}

	verifier, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("build sigstore verifier: %w", err)
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("parse sigstore bundle: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		return fmt.Errorf("build certificate identity: %w", err)
	}

	if _, err := verifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(artifact)),
		verify.WithCertificateIdentity(certID),
	)); err != nil {
		return fmt.Errorf("sigstore bundle verification failed: %w", err)
	}
	return nil
}

// sigstoreVerify is a package var so tests can inject a fake verifier without needing
// a real Sigstore bundle/trust root (network access, time-bound certs).
var sigstoreVerify = verifySigstoreBundle

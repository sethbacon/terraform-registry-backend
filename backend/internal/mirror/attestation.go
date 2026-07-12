// Package mirror - attestation.go verifies GitHub Artifact Attestations for
// release binaries of GitHub-hosted upstreams.
//
// Some upstreams (OPA is the canonical case — see unsignedUpstreamTools in
// signing.go) publish no GPG signature at all, only per-file SHA-256 checksums.
// Recent OPA releases (v1.18.0+) do, however, carry an out-of-band GitHub
// Artifact Attestation: a Sigstore/Fulcio-signed in-toto statement with the
// predicate type https://in-toto.io/attestation/release/v0.2, served from
// GitHub's attestation API by artifact digest (it is NOT a release asset and
// NOT SLSA build provenance). Verifying it is the only signature-based
// authenticity check those binaries can have on top of bare checksums.
//
// Security model — a mere "an attestation exists" check proves nothing, so
// verification enforces a pinned signer identity end to end:
//
//  1. The Sigstore bundle must verify against the Sigstore public-good trust
//     root (certificate chain, transparency log, observer timestamps).
//  2. The Fulcio certificate's OIDC issuer must be exactly
//     https://token.actions.githubusercontent.com (GitHub Actions).
//  3. The certificate's SubjectAlternativeName (the signing workflow ref) must
//     live under https://github.com/{owner}/{repo}/ — i.e. the workflow that
//     signed the attestation belongs to the upstream repository itself.
//  4. When the certificate carries the Fulcio SourceRepositoryURI extension
//     (GitHub-Actions-issued certificates always do), it must equal
//     https://github.com/{owner}/{repo} exactly (defense in depth over 3).
//  5. The verified in-toto statement's predicate type must be the GitHub
//     release attestation predicate.
//  6. The statement's subject digest must match the downloaded binary's
//     SHA-256 (enforced by the sigstore-go artifact-digest policy).
//
// The trusted root comes from the Sigstore public-good TUF repository (same
// lazy, once-per-process flow as internal/scanner/installer). In air-gapped
// deployments that fetch fails; callers receive ErrAttestationUnavailable and
// must degrade gracefully to checksum-only verification — never treat an
// infrastructure failure as a signature mismatch.
package mirror

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// GitHubActionsOIDCIssuer is the only OIDC issuer accepted for GitHub Artifact
// Attestations: certificates issued to GitHub Actions workflow identities.
const GitHubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

// GitHubReleaseAttestationPredicateType is the in-toto predicate type GitHub
// attaches to release attestations (immutable-releases feature). Note this is
// deliberately NOT the SLSA provenance predicate — the default provenance
// lookup 404s for OPA releases.
const GitHubReleaseAttestationPredicateType = "https://in-toto.io/attestation/release/v0.2"

// ErrAttestationNotFound indicates the upstream repository has no release
// attestation for the given digest — expected for releases published before
// the repository enabled attestations. Callers degrade to checksum-only.
var ErrAttestationNotFound = errors.New("no release attestation found for digest")

// ErrAttestationUnavailable indicates attestation verification could not run
// at all: the GitHub attestation API or the Sigstore TUF trust root is
// unreachable (rate-limited, air-gapped deployment, upstream outage). This is
// an infrastructure failure, not a signature mismatch — callers must degrade
// gracefully to checksum-only verification with a logged warning.
var ErrAttestationUnavailable = errors.New("attestation verification unavailable")

// ----- Trusted root (Sigstore public-good, via TUF) --------------------------

var (
	attestationTrustRootMu        sync.Mutex
	attestationTrustRoot          *root.TrustedRoot
	attestationTrustRootErr       error
	attestationTrustRootFetchedAt time.Time
)

// attestationTrustRootRetryCooldown bounds how often a FAILED trust-root
// fetch is retried. A successful fetch is cached permanently (trust roots are
// long-lived; there is no reason to ever re-fetch a good one). A failure is
// cached only for this long, not forever: a transient network blip (a rate
// limit, a momentary outage) must not permanently disable attestation
// verification for the life of the server process. A deployment that is
// persistently unable to reach the TUF CDN (e.g. genuinely air-gapped)
// settles into "retry at most once per cooldown" instead of hammering the
// network on every sync.
const attestationTrustRootRetryCooldown = time.Hour

// publicGoodTrustedMaterial fetches and caches the Sigstore public-good
// trusted root via TUF (embedded initial root, updates from the Sigstore TUF
// CDN). There is deliberately no stale-root fallback beyond sigstore-go's own
// TUF cache handling: verifying against an unverifiable root would be weaker
// than the documented checksum-only degradation.
// coverage:skip:integration-only — fetches the real Sigstore public-good trusted root over the network via TUF; no fixture/fake TUF mirror exists to exercise this hermetically.
func publicGoodTrustedMaterial() (root.TrustedMaterial, error) {
	attestationTrustRootMu.Lock()
	defer attestationTrustRootMu.Unlock()

	if attestationTrustRoot != nil {
		return attestationTrustRoot, nil
	}
	if attestationTrustRootErr != nil && time.Since(attestationTrustRootFetchedAt) < attestationTrustRootRetryCooldown {
		return nil, attestationTrustRootErr
	}

	// DisableLocalCache lets the TUF client work on a read-only root
	// filesystem (e.g. Kubernetes readOnlyRootFilesystem: true), matching
	// the scanner installer's Sigstore flow.
	opts := tuf.DefaultOptions()
	opts.DisableLocalCache = true
	client, err := tuf.New(opts)
	if err != nil {
		attestationTrustRootErr = fmt.Errorf("create TUF client: %w", err)
		attestationTrustRootFetchedAt = time.Now()
		return nil, attestationTrustRootErr
	}
	rootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		attestationTrustRootErr = fmt.Errorf("fetch trusted_root.json: %w", err)
		attestationTrustRootFetchedAt = time.Now()
		return nil, attestationTrustRootErr
	}
	attestationTrustRoot, attestationTrustRootErr = root.NewTrustedRootFromJSON(rootJSON)
	attestationTrustRootFetchedAt = time.Now()
	return attestationTrustRoot, attestationTrustRootErr
}

// ----- Verifier ---------------------------------------------------------------

// GitHubAttestationVerifier fetches GitHub Artifact Attestation bundles for an
// artifact digest and verifies them against a pinned signer identity derived
// from the upstream repository (see the package comment for the exact pins).
type GitHubAttestationVerifier struct {
	Owner string
	Repo  string

	// HTTPClient talks to the GitHub attestation API.
	HTTPClient *http.Client
	// APIToken is an optional GitHub token (read from GITHUB_TOKEN by the
	// constructor). Unauthenticated requests work for public repositories but
	// share the 60 req/hour anonymous rate limit.
	APIToken string // #nosec G117 -- configuration field for GitHub API authentication, not a hardcoded credential
	// APIBaseURL defaults to https://api.github.com; overridable in tests.
	APIBaseURL string

	// trustedMaterial supplies the Sigstore trusted material bundles are
	// verified against. Defaults to the cached public-good TUF root;
	// overridable in tests (VirtualSigstore).
	trustedMaterial func() (root.TrustedMaterial, error)
	// verifierOptions are the sigstore-go verifier requirements. The default
	// matches the public-good instance GitHub uses for public repositories:
	// embedded SCT, one transparency-log entry, one observer timestamp.
	verifierOptions []verify.VerifierOption
}

// NewGitHubAttestationVerifier builds a verifier for the repository referenced
// by a GitHub upstream URL (same URL formats ParseGitHubOwnerRepo accepts).
func NewGitHubAttestationVerifier(upstreamURL string) (*GitHubAttestationVerifier, error) {
	owner, repo, err := ParseGitHubOwnerRepo(upstreamURL)
	if err != nil {
		return nil, err
	}
	return &GitHubAttestationVerifier{
		Owner:      owner,
		Repo:       repo,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		APIToken:   os.Getenv("GITHUB_TOKEN"),
		APIBaseURL: "https://api.github.com",

		trustedMaterial: publicGoodTrustedMaterial,
		verifierOptions: []verify.VerifierOption{
			verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1),
		},
	}, nil
}

// VerifyBinaryAttestation fetches the release attestation(s) for the given
// artifact SHA-256 (lowercase hex) and verifies at least one against the
// pinned signer identity. Returns nil on success, ErrAttestationNotFound when
// the repository has none for this digest, ErrAttestationUnavailable when the
// attestation API or Sigstore trust root cannot be reached, and any other
// error on a definitive verification failure.
func (v *GitHubAttestationVerifier) VerifyBinaryAttestation(ctx context.Context, sha256Hex string) error {
	trusted, err := v.trustedMaterial()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestationUnavailable, err)
	}

	bundles, err := v.fetchAttestationBundles(ctx, sha256Hex)
	if err != nil {
		return err
	}

	// A digest can carry multiple attestations (e.g. re-runs); any one that
	// verifies against the pinned identity is sufficient.
	var lastErr error
	for _, b := range bundles {
		if verifyErr := verifyAttestationEntity(b, trusted, v.verifierOptions, v.Owner, v.Repo, sha256Hex); verifyErr != nil {
			lastErr = verifyErr
			continue
		}
		return nil
	}
	return lastErr
}

// gitHubAttestationsResponse is the subset of the GitHub attestation API
// response consumed here: GET /repos/{owner}/{repo}/attestations/sha256:<hex>.
type gitHubAttestationsResponse struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

// fetchAttestationBundles retrieves and parses the Sigstore bundles GitHub has
// stored for the given artifact digest, pre-filtered server-side to the
// release predicate type (the filter is a convenience only — the predicate is
// re-checked from the cryptographically verified statement, never trusted from
// the API).
func (v *GitHubAttestationVerifier) fetchAttestationBundles(ctx context.Context, sha256Hex string) ([]*bundle.Bundle, error) {
	baseURL := v.APIBaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s?predicate_type=%s",
		baseURL, v.Owner, v.Repo, strings.ToLower(sha256Hex),
		url.QueryEscape(GitHubReleaseAttestationPredicateType))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation API request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if v.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+v.APIToken)
	}

	resp, err := v.HTTPClient.Do(req) // #nosec G704 -- URL derived from admin-configured upstream
	if err != nil {
		return nil, fmt.Errorf("%w: attestation API request failed: %v", ErrAttestationUnavailable, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through to decode
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrAttestationNotFound
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: attestation API returned %d: %s", ErrAttestationUnavailable, resp.StatusCode, string(body))
	}

	var parsed gitHubAttestationsResponse
	// Bundles embed certificates and tlog entries; 4 MB comfortably bounds a
	// page of them while still capping a misbehaving upstream.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("failed to decode attestation API response: %w", err)
	}

	bundles := make([]*bundle.Bundle, 0, len(parsed.Attestations))
	for _, att := range parsed.Attestations {
		if len(att.Bundle) == 0 {
			continue
		}
		var b bundle.Bundle
		if err := b.UnmarshalJSON(att.Bundle); err != nil {
			// A malformed bundle among well-formed ones must not mask the
			// verifiable ones; skip it.
			continue
		}
		bundles = append(bundles, &b)
	}
	if len(bundles) == 0 {
		return nil, ErrAttestationNotFound
	}
	return bundles, nil
}

// verifyAttestationEntity verifies one Sigstore signed entity against the
// pinned identity for owner/repo and the artifact digest. Split from
// VerifyBinaryAttestation so tests can drive it with synthetic bundles from a
// test CA without the GitHub API or the live trust root.
func verifyAttestationEntity(
	entity verify.SignedEntity,
	trusted root.TrustedMaterial,
	opts []verify.VerifierOption,
	owner, repo, sha256Hex string,
) error {
	digest, err := hex.DecodeString(sha256Hex)
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("invalid sha256 digest %q", sha256Hex)
	}

	verifier, err := verify.NewVerifier(trusted, opts...)
	if err != nil {
		return fmt.Errorf("build sigstore verifier: %w", err)
	}

	// Identity pin: exact GitHub Actions OIDC issuer + the signing workflow
	// identity (SAN) anchored under the upstream repository. The trailing "/"
	// in the pattern prevents prefix-crafting (owner/repo must be a full path
	// segment: "…/opa/…" cannot be satisfied by "…/opa-evil/…").
	certID, err := verify.NewShortCertificateIdentity(GitHubActionsOIDCIssuer, "", "", sanRegexForRepo(owner, repo))
	if err != nil {
		return fmt.Errorf("build certificate identity: %w", err)
	}

	result, err := verifier.Verify(entity, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return fmt.Errorf("sigstore attestation verification failed: %w", err)
	}

	return checkAttestationResult(result, owner, repo)
}

// sanRegexForRepo returns the anchored, case-insensitive pattern the Fulcio
// certificate's SubjectAlternativeName (the signing workflow ref, e.g.
// https://github.com/open-policy-agent/opa/.github/workflows/post-tag.yaml@refs/tags/v1.18.0)
// must match: any workflow belonging to the upstream repository. The exact
// workflow filename is deliberately not pinned — upstreams rename release
// workflows, and the repository boundary is the trust boundary.
func sanRegexForRepo(owner, repo string) string {
	return "(?i)^https://github\\.com/" + regexp.QuoteMeta(owner) + "/" + regexp.QuoteMeta(repo) + "/"
}

// checkAttestationResult enforces the pins that live in the verified content
// rather than the verification policy: the release predicate type and the
// Fulcio SourceRepositoryURI extension. Pure function over the sigstore-go
// verification result so identity-pinning edge cases are unit-testable.
func checkAttestationResult(result *verify.VerificationResult, owner, repo string) error {
	if result == nil || result.Statement == nil {
		return errors.New("attestation bundle carries no in-toto statement")
	}
	if result.Statement.PredicateType != GitHubReleaseAttestationPredicateType {
		return fmt.Errorf("unexpected predicate type %q (want %q)",
			result.Statement.PredicateType, GitHubReleaseAttestationPredicateType)
	}
	if result.Signature == nil || result.Signature.Certificate == nil {
		return errors.New("attestation verification result carries no certificate summary")
	}
	// Defense in depth over the SAN pin: Fulcio stamps the source repository
	// into a dedicated certificate extension for GitHub-Actions-issued
	// certificates. When present it must name the upstream repository exactly.
	// (Synthetic test-CA certificates may omit the extension; the SAN pin
	// enforced by the verification policy above still binds the repository.)
	wantRepoURI := "https://github.com/" + owner + "/" + repo
	if uri := strings.TrimSuffix(result.Signature.Certificate.SourceRepositoryURI, "/"); uri != "" && !strings.EqualFold(uri, wantRepoURI) {
		return fmt.Errorf("certificate SourceRepositoryURI %q does not match pinned repository %q", uri, wantRepoURI)
	}
	return nil
}

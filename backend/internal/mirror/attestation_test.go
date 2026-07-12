package mirror

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	sgdata "github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ---------------------------------------------------------------------------
// Test fixtures — a synthetic Sigstore bundle signed by an in-process test CA
// (sigstore-go's pkg/testing/ca.VirtualSigstore), asserting the identity
// pinning enforced by verifyAttestationEntity / checkAttestationResult.
// ---------------------------------------------------------------------------

const (
	testOwner    = "open-policy-agent"
	testRepo     = "opa"
	testWorkflow = "https://github.com/" + testOwner + "/" + testRepo + "/.github/workflows/release.yml@refs/tags/v1.18.0"
)

// testVerifierOpts mirrors production's requirement of >=1 transparency log
// entry, but substitutes WithIntegratedTimestamps for WithSignedCertificateTimestamps:
// VirtualSigstore-generated leaf certs carry no embedded SCT (there is no real
// CT log involved), so requiring one would fail every synthetic-bundle test
// regardless of identity pinning. The identity/predicate/digest checks under
// test here are orthogonal to the SCT requirement.
func testVerifierOpts() []verify.VerifierOption {
	return []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	}
}

// buildReleaseStatement returns an in-toto statement JSON body (the DSSE
// envelope payload) for one binary, with the given predicate type and
// subject digest.
func buildReleaseStatement(t *testing.T, predicateType, sha256Hex string) []byte {
	t.Helper()
	stmt := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]interface{}{
			{
				"name":   "opa_linux_amd64",
				"digest": map[string]string{"sha256": sha256Hex},
			},
		},
		"predicateType": predicateType,
		"predicate":     map[string]interface{}{},
	}
	body, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return body
}

// attestFor builds a fresh VirtualSigstore (acting as both the signer and the
// trusted material) and produces a SignedEntity for the given identity/issuer
// pair and release statement.
func attestFor(t *testing.T, identity, issuer, predicateType, sha256Hex string) (*ca.VirtualSigstore, verify.SignedEntity) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, err := vs.Attest(identity, issuer, buildReleaseStatement(t, predicateType, sha256Hex))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	return vs, entity
}

// validDigest is a syntactically valid 64-hex-char (32-byte) sha256 digest
// used as the "downloaded file's" digest across these tests.
var validDigest = strings.Repeat("cafebabe", 8)

// ---------------------------------------------------------------------------
// verifyAttestationEntity — the core identity-pinning gate
// ---------------------------------------------------------------------------

func TestVerifyAttestationEntity_Success(t *testing.T) {
	vs, entity := attestFor(t, testWorkflow, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)

	if err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, validDigest); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestVerifyAttestationEntity_WrongIssuer_Rejected(t *testing.T) {
	// Signed by a Fulcio-shaped cert, but the OIDC issuer is not GitHub Actions
	// (e.g. a different, attacker-controlled or unrelated CI provider).
	vs, entity := attestFor(t, testWorkflow, "https://ci.attacker.example.com", GitHubReleaseAttestationPredicateType, validDigest)

	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, validDigest)
	if err == nil {
		t.Fatal("expected error for wrong OIDC issuer, got nil")
	}
}

func TestVerifyAttestationEntity_WrongRepo_Rejected(t *testing.T) {
	// A same-prefix, different repository name ("opa-evil" is not "opa"). This
	// must NOT be accepted as open-policy-agent/opa — the SAN pin anchors on
	// the full "/owner/repo/" path segment, not a prefix match.
	craftedIdentity := "https://github.com/open-policy-agent/opa-evil/.github/workflows/release.yml@refs/tags/v1.18.0"
	vs, entity := attestFor(t, craftedIdentity, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)

	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, validDigest)
	if err == nil {
		t.Fatal("expected error for crafted repo name (opa-evil vs opa), got nil")
	}
}

func TestVerifyAttestationEntity_WrongOwner_Rejected(t *testing.T) {
	craftedIdentity := "https://github.com/some-other-org/opa/.github/workflows/release.yml@refs/tags/v1.18.0"
	vs, entity := attestFor(t, craftedIdentity, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)

	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, validDigest)
	if err == nil {
		t.Fatal("expected error for wrong owner, got nil")
	}
}

func TestVerifyAttestationEntity_WrongPredicateType_Rejected(t *testing.T) {
	// A different (e.g. SLSA provenance) predicate type must not satisfy the
	// GitHub release-attestation check, even though the signer identity and
	// digest binding are otherwise perfectly valid.
	vs, entity := attestFor(t, testWorkflow, GitHubActionsOIDCIssuer, "https://slsa.dev/provenance/v1", validDigest)

	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, validDigest)
	if err == nil {
		t.Fatal("expected error for wrong predicate type, got nil")
	}
	if !strings.Contains(err.Error(), "predicate type") {
		t.Errorf("expected predicate-type error, got: %v", err)
	}
}

func TestVerifyAttestationEntity_DigestMismatch_Rejected(t *testing.T) {
	// The statement asserts a different digest than the one we downloaded —
	// this must never verify, even with a perfectly valid identity.
	vs, entity := attestFor(t, testWorkflow, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)

	otherDigest := strings.Repeat("00", 32)
	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, otherDigest)
	if err == nil {
		t.Fatal("expected error for digest mismatch, got nil")
	}
}

func TestVerifyAttestationEntity_InvalidDigestHex_Rejected(t *testing.T) {
	vs, entity := attestFor(t, testWorkflow, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)

	err := verifyAttestationEntity(entity, vs, testVerifierOpts(), testOwner, testRepo, "not-hex")
	if err == nil {
		t.Fatal("expected error for invalid digest hex, got nil")
	}
}

func TestVerifyAttestationEntity_DifferentTrustRoot_Rejected(t *testing.T) {
	// Signed by one VirtualSigstore instance but verified against a different
	// one's trust material — the certificate chain must not validate.
	vs1, entity := attestFor(t, testWorkflow, GitHubActionsOIDCIssuer, GitHubReleaseAttestationPredicateType, validDigest)
	vs2, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	_ = vs1

	err = verifyAttestationEntity(entity, vs2, testVerifierOpts(), testOwner, testRepo, validDigest)
	if err == nil {
		t.Fatal("expected error verifying against an unrelated trust root, got nil")
	}
}

// ---------------------------------------------------------------------------
// checkAttestationResult — the post-Verify pins that live in verified content
// rather than the verification policy (predicate type, SourceRepositoryURI
// defense-in-depth over the SAN pin already enforced by the policy).
// ---------------------------------------------------------------------------

func TestCheckAttestationResult_NilResult(t *testing.T) {
	if err := checkAttestationResult(nil, testOwner, testRepo); err == nil {
		t.Fatal("expected error for nil result")
	}
}

func TestCheckAttestationResult_NilStatement(t *testing.T) {
	result := &verify.VerificationResult{}
	if err := checkAttestationResult(result, testOwner, testRepo); err == nil {
		t.Fatal("expected error for nil statement")
	}
}

func TestCheckAttestationResult_NilSignature(t *testing.T) {
	result := &verify.VerificationResult{
		Statement: validStatement(t),
	}
	if err := checkAttestationResult(result, testOwner, testRepo); err == nil {
		t.Fatal("expected error for nil signature")
	}
}

func TestCheckAttestationResult_SourceRepositoryURIMismatch_Rejected(t *testing.T) {
	result := &verify.VerificationResult{
		Statement: validStatement(t),
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{
				Extensions: certificate.Extensions{SourceRepositoryURI: "https://github.com/evil/repo"},
			},
		},
	}
	err := checkAttestationResult(result, testOwner, testRepo)
	if err == nil {
		t.Fatal("expected error for SourceRepositoryURI mismatch")
	}
	if !strings.Contains(err.Error(), "SourceRepositoryURI") {
		t.Errorf("expected SourceRepositoryURI error, got: %v", err)
	}
}

func TestCheckAttestationResult_SourceRepositoryURIMatch_Accepted(t *testing.T) {
	result := &verify.VerificationResult{
		Statement: validStatement(t),
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{
				Extensions: certificate.Extensions{SourceRepositoryURI: "https://github.com/" + testOwner + "/" + testRepo},
			},
		},
	}
	if err := checkAttestationResult(result, testOwner, testRepo); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestCheckAttestationResult_SourceRepositoryURITrailingSlash_Accepted(t *testing.T) {
	result := &verify.VerificationResult{
		Statement: validStatement(t),
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{
				Extensions: certificate.Extensions{SourceRepositoryURI: "https://github.com/" + testOwner + "/" + testRepo + "/"},
			},
		},
	}
	if err := checkAttestationResult(result, testOwner, testRepo); err != nil {
		t.Fatalf("expected success with trailing slash normalised, got: %v", err)
	}
}

func TestCheckAttestationResult_EmptySourceRepositoryURI_Accepted(t *testing.T) {
	// Synthetic test-CA certificates (and, in principle, any Fulcio cert
	// lacking the extension) omit SourceRepositoryURI; the SAN pin enforced by
	// the verification policy already binds the repository, so an absent
	// extension is not itself a failure.
	result := &verify.VerificationResult{
		Statement: validStatement(t),
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{},
		},
	}
	if err := checkAttestationResult(result, testOwner, testRepo); err != nil {
		t.Fatalf("expected success with empty SourceRepositoryURI, got: %v", err)
	}
}

func TestCheckAttestationResult_WrongPredicateType(t *testing.T) {
	result := &verify.VerificationResult{
		Statement: statementWithPredicate(t, "https://slsa.dev/provenance/v1"),
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{},
		},
	}
	err := checkAttestationResult(result, testOwner, testRepo)
	if err == nil {
		t.Fatal("expected error for wrong predicate type")
	}
}

// ---------------------------------------------------------------------------
// sanRegexForRepo
// ---------------------------------------------------------------------------

func TestSanRegexForRepo(t *testing.T) {
	re := regexp.MustCompile(sanRegexForRepo(testOwner, testRepo))

	cases := []struct {
		name  string
		san   string
		match bool
	}{
		{"exact workflow", testWorkflow, true},
		{"case-insensitive host", "https://GITHUB.COM/" + testOwner + "/" + testRepo + "/.github/workflows/x.yml@refs/tags/v1", true},
		{"crafted repo prefix", "https://github.com/" + testOwner + "/" + testRepo + "-evil/.github/workflows/x.yml@refs/tags/v1", false},
		{"crafted owner prefix", "https://github.com/" + testOwner + "-evil/" + testRepo + "/.github/workflows/x.yml@refs/tags/v1", false},
		{"wrong owner", "https://github.com/someone-else/" + testRepo + "/.github/workflows/x.yml@refs/tags/v1", false},
		{"bare repo no trailing segment", "https://github.com/" + testOwner + "/" + testRepo, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := re.MatchString(tc.san); got != tc.match {
				t.Errorf("MatchString(%q) = %v, want %v", tc.san, got, tc.match)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitHubAttestationVerifier — HTTP layer (fetch + graceful degradation)
// ---------------------------------------------------------------------------

func TestNewGitHubAttestationVerifier_Success(t *testing.T) {
	v, err := NewGitHubAttestationVerifier("https://github.com/" + testOwner + "/" + testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Owner != testOwner || v.Repo != testRepo {
		t.Errorf("Owner/Repo = %s/%s, want %s/%s", v.Owner, v.Repo, testOwner, testRepo)
	}
}

func TestNewGitHubAttestationVerifier_InvalidURL(t *testing.T) {
	if _, err := NewGitHubAttestationVerifier("not-a-url"); err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestVerifyBinaryAttestation_TrustRootUnavailable(t *testing.T) {
	called := false
	v := &GitHubAttestationVerifier{
		Owner:      testOwner,
		Repo:       testRepo,
		HTTPClient: http.DefaultClient,
		APIBaseURL: "http://unused.invalid",
		trustedMaterial: func() (root.TrustedMaterial, error) {
			called = true
			return nil, errors.New("no network")
		},
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("expected ErrAttestationUnavailable, got %v", err)
	}
	if !called {
		t.Fatal("expected trustedMaterial() to be consulted before any HTTP call")
	}
}

func TestVerifyBinaryAttestation_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	vs, _ := ca.NewVirtualSigstore()
	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL,
		trustedMaterial: func() (root.TrustedMaterial, error) { return vs, nil },
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("expected ErrAttestationNotFound, got %v", err)
	}
}

func TestVerifyBinaryAttestation_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer ts.Close()

	vs, _ := ca.NewVirtualSigstore()
	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL,
		trustedMaterial: func() (root.TrustedMaterial, error) { return vs, nil },
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("expected ErrAttestationUnavailable, got %v", err)
	}
}

func TestVerifyBinaryAttestation_NetworkUnreachable(t *testing.T) {
	vs, _ := ca.NewVirtualSigstore()
	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient:      &http.Client{Transport: failingTransport{}},
		APIBaseURL:      "http://127.0.0.1:1", // nothing listens here
		trustedMaterial: func() (root.TrustedMaterial, error) { return vs, nil },
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("expected ErrAttestationUnavailable, got %v", err)
	}
}

func TestVerifyBinaryAttestation_EmptyAttestationsList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attestations":[]}`))
	}))
	defer ts.Close()

	vs, _ := ca.NewVirtualSigstore()
	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL,
		trustedMaterial: func() (root.TrustedMaterial, error) { return vs, nil },
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("expected ErrAttestationNotFound, got %v", err)
	}
}

func TestVerifyBinaryAttestation_MalformedBundleSkipped(t *testing.T) {
	// A single, unparsable bundle entry must degrade to "not found" rather
	// than a hard error — a malformed record from upstream shouldn't crash
	// the sync job.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attestations":[{"bundle":{"not":"a valid bundle"}}]}`))
	}))
	defer ts.Close()

	vs, _ := ca.NewVirtualSigstore()
	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL,
		trustedMaterial: func() (root.TrustedMaterial, error) { return vs, nil },
	}

	err := v.VerifyBinaryAttestation(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("expected ErrAttestationNotFound for malformed bundle, got %v", err)
	}
}

// TestFetchAttestationBundles_ParsesValidBundle exercises the HTTP/JSON
// extraction path (URL construction, auth header, unwrapping the
// attestations[].bundle envelope) against a real, schema-valid Sigstore
// bundle fixture shipped by sigstore-go. The fixture is signed by an
// unrelated identity/trust root, so it is used only to prove the plumbing
// parses a genuine bundle correctly — cryptographic identity pinning is
// covered by the VirtualSigstore-based tests above.
func TestFetchAttestationBundles_ParsesValidBundle(t *testing.T) {
	fixture := sgdata.Bundle(t, "dsse.sigstore.json")
	raw, err := fixture.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal fixture bundle: %v", err)
	}

	var gotPath, gotQuery, gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"attestations": []map[string]json.RawMessage{
				{"bundle": raw},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL, APIToken: "test-token",
	}

	bundles, err := v.fetchAttestationBundles(context.Background(), validDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(bundles))
	}

	wantPath := "/repos/" + testOwner + "/" + testRepo + "/attestations/sha256:" + validDigest
	if gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
	if !strings.Contains(gotQuery, "predicate_type=") {
		t.Errorf("expected predicate_type query param, got %q", gotQuery)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want Bearer test-token", gotAuth)
	}
}

func TestFetchAttestationBundles_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var gotAuth string
	sawAuth := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, sawAuth = r.Header.Get("Authorization"), r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	v := &GitHubAttestationVerifier{
		Owner: testOwner, Repo: testRepo,
		HTTPClient: ts.Client(), APIBaseURL: ts.URL, // APIToken left empty
	}

	_, err := v.fetchAttestationBundles(context.Background(), validDigest)
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("expected ErrAttestationNotFound, got %v", err)
	}
	if sawAuth {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

// failingTransport always fails the round trip, simulating a network that is
// entirely unreachable (e.g. an air-gapped deployment with no route to the
// internet), as opposed to a server that responds with an error status.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}

// validStatement returns a well-formed release-attestation statement for the
// pinned digest, used by the checkAttestationResult tests that construct a
// verify.VerificationResult directly rather than running a full Verify().
func validStatement(t *testing.T) *in_toto.Statement {
	t.Helper()
	return statementWithPredicate(t, GitHubReleaseAttestationPredicateType)
}

func statementWithPredicate(t *testing.T, predicateType string) *in_toto.Statement {
	t.Helper()
	stmt := &in_toto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: predicateType,
	}
	return stmt
}

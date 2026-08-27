package urlsign

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withSecret swaps the root secret for the duration of a test.
func withSecret(t *testing.T, secret string) {
	t.Helper()
	prev := secretSource
	secretSource = func() (string, error) { return secret, nil }
	t.Cleanup(func() { secretSource = prev })
}

const testSecret = "a-test-secret-with-enough-entropy-0123456789"

func TestSignedURLVerifies(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)

	exp, sig, err := Sign("modules/acme/vpc/aws/1.0.0.tar.gz", 15*time.Minute, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify("modules/acme/vpc/aws/1.0.0.tar.gz", exp, sig, now); err != nil {
		t.Errorf("a freshly signed URL did not verify: %v", err)
	}
}

// TestSignatureIsBoundToThePath is the property the whole issue turns on.
//
// GET /v1/files/*filepath serves whatever key it is handed. If the MAC did not
// cover the path, one legitimate 15-minute download URL would authorise every
// object in storage for those 15 minutes.
func TestSignatureIsBoundToThePath(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)

	exp, sig, err := Sign("modules/acme/vpc/aws/1.0.0.tar.gz", 15*time.Minute, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for _, other := range []string{
		"modules/acme/vpc/aws/1.0.1.tar.gz",
		"modules/other/vpc/aws/1.0.0.tar.gz",
		"terraform-binaries/1.9.5/linux/amd64/terraform_1.9.5_linux_amd64.zip",
		"modules/acme/vpc/aws/1.0.0.tar.gz.bak",
		// A prefix and an extension of the signed key: a length-unaware
		// construction ("path"+"expires" concatenated) would let these collide.
		"modules/acme/vpc/aws/1.0.0.tar.g",
		"modules/acme/vpc/aws/1.0.0.tar.gzz",
	} {
		if err := Verify(other, exp, sig, now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("signature for the target also authorised %q: got %v, want ErrBadSignature", other, err)
		}
	}
}

// TestSigningInputIsUnambiguous — the length prefix is load-bearing.
//
// Without it the signing input is just the path followed by the expiry, and
// those two concatenations collide: path "x1" with expiry 700000900 and path "x"
// with expiry 1700000900 both render as "x1700000900". A caller holding a
// legitimate URL for one object could then replay its signature against a
// DIFFERENT object at a different expiry.
//
// This is the case the obvious cross-object test misses, because it varies the
// path while holding the expiry fixed and every such pair is trivially distinct.
func TestSigningInputIsUnambiguous(t *testing.T) {
	withSecret(t, testSecret)

	// Chosen so that path+expires is byte-identical across the two.
	longPath, shortExp := "modules/acme/vpc/aws/1.0.0.tar.gz1", int64(700000900)
	shortPath, longExp := "modules/acme/vpc/aws/1.0.0.tar.gz", int64(1700000900)
	if longPath+strconv.FormatInt(shortExp, 10) != shortPath+strconv.FormatInt(longExp, 10) {
		t.Fatal("test inputs no longer collide under naive concatenation; pick new ones")
	}

	k, err := key()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if signature(k, longPath, shortExp) == signature(k, shortPath, longExp) {
		t.Error("two different (path, expiry) pairs produced the same signature.\n" +
			"A URL for one object can be replayed against another at a different expiry: " +
			"the signing input needs the length prefix.")
	}
}

// TestExpiryIsCoveredByTheSignature stops the cheapest possible forgery: keep a
// real signature and edit the expiry in the querystring, turning a 15-minute
// credential into a permanent one.
func TestExpiryIsCoveredByTheSignature(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)

	exp, sig, err := Sign("modules/acme/vpc/aws/1.0.0.tar.gz", time.Minute, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	extended := strconv.FormatInt(now.Add(100*365*24*time.Hour).Unix(), 10)
	if extended == exp {
		t.Fatal("test is not extending the expiry")
	}
	if err := Verify("modules/acme/vpc/aws/1.0.0.tar.gz", extended, sig, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("the expiry could be extended without invalidating the signature: got %v", err)
	}
}

func TestExpiredSignatureIsRefused(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)
	const key = "modules/acme/vpc/aws/1.0.0.tar.gz"

	exp, sig, err := Sign(key, 15*time.Minute, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(key, exp, sig, now.Add(14*time.Minute)); err != nil {
		t.Errorf("still inside the TTL but refused: %v", err)
	}
	// Exactly at the expiry is still valid; one second past is not.
	if err := Verify(key, exp, sig, now.Add(15*time.Minute)); err != nil {
		t.Errorf("at the expiry boundary: got %v, want valid", err)
	}
	if err := Verify(key, exp, sig, now.Add(15*time.Minute+time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("one second past the expiry: got %v, want ErrExpired", err)
	}
}

// TestMissingParamsAreDistinguishable lets an operator upgrading a deployment
// tell an old client from a forgery in the log, without the HTTP response
// telling the caller anything.
func TestMissingParamsAreDistinguishable(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)

	for _, tc := range []struct{ name, exp, sig string }{
		{"neither", "", ""},
		{"expires only", "1700000900", ""},
		{"sig only", "", "AAAA"},
	} {
		if err := Verify("k", tc.exp, tc.sig, now); !errors.Is(err, ErrMissingSignature) {
			t.Errorf("%s: got %v, want ErrMissingSignature", tc.name, err)
		}
	}
	if err := Verify("k", "not-a-number", "AAAA", now); !errors.Is(err, ErrMalformedExpiry) {
		t.Errorf("non-numeric expiry: got %v, want ErrMalformedExpiry", err)
	}
}

// TestNoKeyFailsClosed is the fail-closed property.
//
// HMAC accepts a zero-length key without complaint and produces a signature
// anyone can recompute. Falling back to one would leave a route that looks
// authorised and is not -- a lock that reports locked. Both directions must
// refuse, because signing with no key is what would MINT those forgeable URLs.
func TestNoKeyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source func() (string, error)
	}{
		{"empty secret", func() (string, error) { return "", nil }},
		{"source errors", func() (string, error) { return "", errors.New("no secret configured") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := secretSource
			secretSource = tc.source
			t.Cleanup(func() { secretSource = prev })

			if _, _, err := Sign("k", time.Minute, time.Unix(1_700_000_000, 0)); err == nil {
				t.Error("Sign produced a signature with no key; every URL it mints would be forgeable")
			}
			if err := Verify("k", "1700000900", "AAAA", time.Unix(1_700_000_000, 0)); err == nil {
				t.Error("Verify accepted a signature with no key")
			}
		})
	}
}

// TestKeyIsDomainSeparated proves the signing key is not the root secret.
//
// Signing URLs with the JWT secret directly would mean one key produces both
// session tokens and URL signatures, and any future confusion between the two
// message formats becomes a forgery. Asserted by construction: the signature
// must differ from what the raw secret would produce.
func TestKeyIsDomainSeparated(t *testing.T) {
	withSecret(t, testSecret)
	derived, err := key()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if string(derived) == testSecret {
		t.Fatal("the signing key IS the root secret; no domain separation")
	}
	if strings.Contains(string(derived), testSecret) {
		t.Error("the signing key contains the root secret verbatim")
	}
}

// TestDifferentSecretsProduceDifferentSignatures catches a derivation that
// ignores its input -- a constant key would pass every other test here.
func TestDifferentSecretsProduceDifferentSignatures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const k = "modules/acme/vpc/aws/1.0.0.tar.gz"

	sign := func(secret string) string {
		prev := secretSource
		secretSource = func() (string, error) { return secret, nil }
		defer func() { secretSource = prev }()
		_, sig, err := Sign(k, time.Minute, now)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return sig
	}
	if a, b := sign("secret-one-0123456789abcdef"), sign("secret-two-0123456789abcdef"); a == b {
		t.Error("two different root secrets produced the same signature; the derivation ignores the secret")
	}
}

// TestSignatureIsURLSafe — the value goes into a querystring. A signature
// carrying '+' or '/' would be mangled or re-decoded differently by an
// intermediary and fail intermittently, which is worse than failing always.
func TestSignatureIsURLSafe(t *testing.T) {
	withSecret(t, testSecret)
	now := time.Unix(1_700_000_000, 0)
	for i := range 200 {
		_, sig, err := Sign("modules/acme/vpc/aws/1.0."+strconv.Itoa(i)+".tar.gz", time.Minute, now)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if strings.ContainsAny(sig, "+/=") {
			t.Fatalf("signature %q contains a character that changes meaning in a querystring", sig)
		}
	}
}

// TestComparisonIsConstantTime guards a property no behavioural test can see.
//
// A byte-wise `want != sig` passes every functional test in this file and leaks
// the correct prefix through timing. This endpoint is unauthenticated and merely
// rate-limited, so an attacker gets as many attempts as they like -- which is
// exactly the situation constant-time comparison exists for. Asserted at the
// source level because the alternative is a flaky timing benchmark.
func TestComparisonIsConstantTime(t *testing.T) {
	src, err := os.ReadFile("urlsign.go")
	if err != nil {
		t.Fatalf("read urlsign.go: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "func Verify(")
	if i < 0 {
		t.Fatal("Verify not found; if it was renamed, point this guard at the new name rather than deleting it")
	}
	verify := body[i:]
	if !strings.Contains(verify, "hmac.Equal(") {
		t.Error("Verify does not compare the signature with hmac.Equal.\n" +
			"A plain != leaks the correct prefix by timing, on an unauthenticated endpoint " +
			"an attacker may hit as often as the rate limit allows.")
	}
	// And the naive comparison must not be there as well -- a short-circuit
	// added "for speed" in front of hmac.Equal would restore the leak while
	// leaving the call present.
	if strings.Contains(verify, "want != sig") || strings.Contains(verify, "sig != want") {
		t.Error("Verify contains a byte-wise signature comparison alongside hmac.Equal")
	}
}

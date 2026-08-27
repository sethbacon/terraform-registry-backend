// Package urlsign gives the local storage backend the same protection the three
// cloud backends already have: a download URL that is only usable for a specific
// object, for a bounded time (#973).
//
// THE HOLE THIS CLOSES. Storage.GetURL is the one seam every download flows
// through, and three of its four implementations return a credential: S3
// presigns, GCS signs, Azure returns a time-limited SAS. The local backend
// returned a bare, unexpiring, guessable API path -- and the route that serves
// it, GET /v1/files/*filepath, is registered with NO authentication middleware
// at all. Keys are structural (modules/{ns}/{name}/{system}/{version}.tar.gz,
// terraform-binaries/{version}/{os}/{arch}/{file}), so anyone who could reach
// the deployment could enumerate and fetch every module archive and binary,
// unauthenticated, without it appearing anywhere as an authorised download.
//
// WHY A SIGNATURE RATHER THAN AUTHENTICATION ON THE ROUTE. The consumer is
// Terraform, following an X-Terraform-Get or a mirror archive URL. It does not
// necessarily carry a registry credential to a redirected host, which is exactly
// why the object-store protocol is a signed URL rather than an authenticated
// fetch. Matching that shape keeps the local backend a drop-in for the cloud
// ones instead of a configuration with different client requirements.
//
// This is deliberately a miniature of an S3 presigned querystring, not a new
// scheme.
package urlsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// Query parameter names, matching the presign convention closely enough to be
// recognisable in a log.
const (
	ParamExpires   = "expires"
	ParamSignature = "sig"
)

var (
	// ErrMissingSignature means the request carried no signature at all -- the
	// pre-#973 URL shape, or a hand-constructed one. Kept distinct from
	// ErrBadSignature so an operator upgrading can tell "old client" from
	// "someone is forging".
	ErrMissingSignature = errors.New("urlsign: request is not signed")
	ErrBadSignature     = errors.New("urlsign: signature does not match")
	ErrExpired          = errors.New("urlsign: signature has expired")
	ErrMalformedExpiry  = errors.New("urlsign: expiry is not a unix timestamp")
	// ErrNoKey means no signing key could be derived. Every entry point returns
	// it rather than falling back to an empty HMAC key, which would otherwise
	// produce signatures anyone can compute -- a lock that reports locked.
	ErrNoKey = errors.New("urlsign: no signing key available")
)

// secretSource is the root secret the signing key is derived from, or an error
// if none is configured.
//
// It does NOT call auth.GetJWTSecret directly, which PANICS when no secret is
// configured. That panic is defensible at boot and wrong on a request path: it
// would turn a misconfiguration into a stack trace and a 500 on a route whose
// correct answer is a plain 403. auth.ValidateJWTSecret returns the same
// condition as an error (it is sync.Once-guarded, so this is a load after the
// first call), which lets the failure stay fail-closed and quiet.
//
// Indirected through a variable so tests can supply a secret without standing up
// the auth package's global state.
var secretSource = func() (string, error) {
	if err := auth.ValidateJWTSecret(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoKey, err)
	}
	return auth.GetJWTSecret(), nil
}

// derivationLabel domain-separates this key from every other use of the same
// root secret.
//
// Signing with the JWT secret DIRECTLY would mean a URL signature and a session
// token are produced by the same key, and any future confusion between the two
// message formats becomes a forgery. The label costs one HMAC and removes the
// question. Versioned so a future scheme change is a new key rather than a
// silent reinterpretation of old signatures.
const derivationLabel = "terraform-registry/local-storage-url/v1"

// key derives the URL-signing key from the root secret.
//
// The root secret is the JWT secret, which the server validates for presence and
// strength at boot (auth.ValidateJWTSecret) and refuses to start without -- so
// by the time a request is served it is always set. An empty one is still
// treated as fatal here rather than assumed impossible, because the failure it
// would cause is silent: HMAC accepts a zero-length key happily and returns a
// signature every caller can reproduce.
func key() ([]byte, error) {
	secret, err := secretSource()
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, ErrNoKey
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(derivationLabel))
	return m.Sum(nil), nil
}

// signature computes the MAC over the storage key and the expiry.
//
// LENGTH-PREFIXED, so no two (path, expires) pairs can produce the same signing
// input. storage.ValidateKey already rejects control characters, which makes a
// plain newline delimiter safe today -- but that is a property of a guard in
// another package, and this construction does not depend on it holding.
func signature(k []byte, path string, expires int64) string {
	m := hmac.New(sha256.New, k)
	fmt.Fprintf(m, "%d:%s:%d", len(path), path, expires)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Sign returns the query parameters that authorise fetching path until now+ttl.
//
// path is the storage key exactly as the serving handler will see it after it
// strips the leading slash -- NOT URL-escaped. Signing an escaped form and
// verifying a decoded one is the classic way a signature scheme comes apart, so
// the canonical form is fixed here as "the storage key" and both ends use it.
func Sign(path string, ttl time.Duration, now time.Time) (expires string, sig string, err error) {
	k, err := key()
	if err != nil {
		return "", "", err
	}
	exp := now.Add(ttl).Unix()
	return strconv.FormatInt(exp, 10), signature(k, path, exp), nil
}

// Verify reports whether sig authorises path at time now.
//
// Order matters: the signature is checked BEFORE the expiry. Reversing them
// would let an unauthenticated caller probe for a valid signature by observing
// which of two errors comes back, and would answer "was this ever signed?" for a
// path they cannot sign for.
func Verify(path, expires, sig string, now time.Time) error {
	if expires == "" || sig == "" {
		return ErrMissingSignature
	}
	k, err := key()
	if err != nil {
		return err
	}
	exp, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		return ErrMalformedExpiry
	}
	want := signature(k, path, exp)
	// Constant-time: a byte-wise comparison leaks the correct prefix, and this
	// endpoint is unauthenticated and rate-limited rather than blocked, so an
	// attacker gets as many attempts as they like.
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return ErrBadSignature
	}
	if now.Unix() > exp {
		return ErrExpired
	}
	return nil
}

// SetSecretSourceForTest replaces the root secret for the duration of a test.
//
// Exported because the fail-closed path matters MOST outside this package:
// LocalStorage.GetURL must return an error rather than an unsigned URL when
// signing fails, and without a way to force that failure the branch is
// unreachable from a test and can be quietly deleted.
func SetSecretSourceForTest(tb testing.TB, source func() (string, error)) {
	tb.Helper()
	prev := secretSource
	secretSource = source
	tb.Cleanup(func() { secretSource = prev })
}

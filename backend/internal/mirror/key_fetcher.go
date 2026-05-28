// key_fetcher.go fetches and parses ASCII-armored release-signing GPG keys
// from each tool's .well-known/pgp-key.txt endpoint, with strict primary-key
// fingerprint pinning so a compromised TLS path can never substitute a
// different key.
//
// The same parsing helper is reused by both the live fetcher and the
// embedded-snapshot inspector so the expiry math stays consistent.
package mirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Fingerprint hex length in characters (20 bytes -> 40 hex chars).
const fingerprintHexLen = 40

// maxKeyBodyBytes caps the response body to a generous size so a hostile
// server can't exhaust memory. Real release keys are <10 KB; 1 MB is plenty.
const maxKeyBodyBytes = 1 << 20

// Common errors returned by the fetcher / parser. Callers identify these by
// errors.Is rather than string matching so telemetry labels stay stable.
var (
	// ErrFingerprintMismatch is returned when the parsed primary key
	// fingerprint does not match the caller-supplied pin. The cached key is
	// kept; the operator must investigate before allow-listing a new key.
	ErrFingerprintMismatch = errors.New("releases key: primary fingerprint mismatch")

	// ErrNoUsableSigningKey is returned when the parsed entity has no
	// non-expired signing-capable key (primary or subkey). A key with this
	// shape will produce "openpgp: key expired" at verification time.
	ErrNoUsableSigningKey = errors.New("releases key: no unexpired signing-capable key")

	// ErrEmptyKeyring is returned when the armored input parses but contains
	// no entities at all.
	ErrEmptyKeyring = errors.New("releases key: empty keyring")
)

// ReleasesKeyInfo summarizes the trust-relevant facts about an armored key.
// LatestSigningExpiry is the latest expiry across all signing-capable subkeys
// (and the primary if it has the sign flag), or zero if no expiry is set on
// any signing key.
type ReleasesKeyInfo struct {
	PrimaryFingerprint  string
	LatestSigningExpiry time.Time
	HasUsableSigningKey bool
}

// ParseReleasesKey parses an ASCII-armored OpenPGP key block and reports the
// primary fingerprint plus signing-key expiry information. It does not
// network — the live fetcher delegates here after retrieving the body.
func ParseReleasesKey(armored string) (*ReleasesKeyInfo, error) {
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("releases key: parse armored: %w", err)
	}
	if len(ring) == 0 {
		return nil, ErrEmptyKeyring
	}
	entity := ring[0]
	if entity.PrimaryKey == nil {
		return nil, errors.New("releases key: entity has no primary key")
	}

	fpr := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))

	now := time.Now()
	var latest time.Time
	hasUsable := false

	// Walk all subkeys looking for signing-capable, non-expired ones.
	for _, sub := range entity.Subkeys {
		if sub.Sig == nil || !sub.Sig.FlagsValid || !sub.Sig.FlagSign {
			continue
		}
		expiry, hasExpiry := subkeyExpiry(sub)
		if hasExpiry {
			if expiry.After(latest) {
				latest = expiry
			}
			if expiry.Before(now) {
				continue
			}
		}
		hasUsable = true
	}

	// Primary key can sign directly only if its self-sig has the sign flag.
	if !hasUsable {
		ident := primaryIdentity(entity)
		if ident != nil && ident.SelfSignature != nil && ident.SelfSignature.FlagsValid && ident.SelfSignature.FlagSign {
			expiry, hasExpiry := primaryExpiry(entity, ident)
			if hasExpiry {
				if expiry.After(latest) {
					latest = expiry
				}
				if !expiry.Before(now) {
					hasUsable = true
				}
			} else {
				hasUsable = true
			}
		}
	}

	if !hasUsable {
		return &ReleasesKeyInfo{
			PrimaryFingerprint:  fpr,
			LatestSigningExpiry: latest,
		}, ErrNoUsableSigningKey
	}

	return &ReleasesKeyInfo{
		PrimaryFingerprint:  fpr,
		LatestSigningExpiry: latest,
		HasUsableSigningKey: true,
	}, nil
}

// FetchReleasesKey downloads an ASCII-armored key from url, parses it,
// and rejects it if the primary fingerprint does not match
// allowedFingerprint. allowedFingerprint must be the 40-character uppercase
// hex form (the format returned by ParseReleasesKey).
//
// On success it returns the raw armored body so callers can persist it
// verbatim — preserving HashiCorp's own armor formatting matters for
// auditability.
func FetchReleasesKey(ctx context.Context, httpClient *http.Client, url string, allowedFingerprint string) (string, *ReleasesKeyInfo, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if !isAllowedFingerprintShape(allowedFingerprint) {
		return "", nil, fmt.Errorf("releases key: allowed fingerprint must be %d hex chars, got %q", fingerprintHexLen, allowedFingerprint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("releases key: build request: %w", err)
	}
	req.Header.Set("Accept", "application/pgp-keys, text/plain")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("releases key: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("releases key: fetch %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyBodyBytes))
	if err != nil {
		return "", nil, fmt.Errorf("releases key: read body: %w", err)
	}
	armored := strings.TrimSpace(string(body))

	info, err := ParseReleasesKey(armored)
	if err != nil {
		// ErrNoUsableSigningKey still returns info so the caller can log
		// the parsed fingerprint and expiry for diagnosis.
		return "", info, err
	}

	if !strings.EqualFold(info.PrimaryFingerprint, allowedFingerprint) {
		return "", info, fmt.Errorf("%w: got %s, want %s", ErrFingerprintMismatch, info.PrimaryFingerprint, allowedFingerprint)
	}

	return armored, info, nil
}

func isAllowedFingerprintShape(fpr string) bool {
	if len(fpr) != fingerprintHexLen {
		return false
	}
	for _, c := range fpr {
		isHex := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
		if !isHex {
			return false
		}
	}
	return true
}

func primaryIdentity(e *openpgp.Entity) *openpgp.Identity {
	for _, id := range e.Identities {
		return id
	}
	return nil
}

func primaryExpiry(e *openpgp.Entity, ident *openpgp.Identity) (time.Time, bool) {
	if ident == nil || ident.SelfSignature == nil || ident.SelfSignature.KeyLifetimeSecs == nil {
		return time.Time{}, false
	}
	return e.PrimaryKey.CreationTime.Add(time.Duration(*ident.SelfSignature.KeyLifetimeSecs) * time.Second), true
}

func subkeyExpiry(sub openpgp.Subkey) (time.Time, bool) {
	if sub.Sig == nil || sub.Sig.KeyLifetimeSecs == nil {
		return time.Time{}, false
	}
	return sub.PublicKey.CreationTime.Add(time.Duration(*sub.Sig.KeyLifetimeSecs) * time.Second), true
}

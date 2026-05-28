package mirror

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// HashiCorp's release primary fingerprint — used as the pin in production.
// Repeated here as a literal so a future test author can copy this pattern.
const testHashiCorpFingerprint = "C874011F0AB405110D02105534365D9472D7468F"

func TestParseReleasesKey_EmbeddedSnapshotsRoundTrip(t *testing.T) {
	info, err := ParseReleasesKey(HashiCorpReleasesGPGKey)
	if err != nil {
		t.Fatalf("ParseReleasesKey: %v", err)
	}
	if info.PrimaryFingerprint != testHashiCorpFingerprint {
		t.Errorf("PrimaryFingerprint = %q, want %q", info.PrimaryFingerprint, testHashiCorpFingerprint)
	}
	if !info.HasUsableSigningKey {
		t.Error("HasUsableSigningKey = false, want true for embedded HashiCorp key")
	}
}

func TestParseReleasesKey_Garbage(t *testing.T) {
	if _, err := ParseReleasesKey("not a key block at all"); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestParseReleasesKey_EmptyArmor(t *testing.T) {
	// Valid armor frame, but empty payload — ReadArmoredKeyRing returns an error.
	const empty = `-----BEGIN PGP PUBLIC KEY BLOCK-----

-----END PGP PUBLIC KEY BLOCK-----`
	if _, err := ParseReleasesKey(empty); err == nil {
		t.Fatal("expected parse error for empty armor, got nil")
	}
}

func TestFetchReleasesKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(HashiCorpReleasesGPGKey))
	}))
	t.Cleanup(srv.Close)

	armored, info, err := FetchReleasesKey(context.Background(), srv.Client(), srv.URL, testHashiCorpFingerprint)
	if err != nil {
		t.Fatalf("FetchReleasesKey: %v", err)
	}
	if info.PrimaryFingerprint != testHashiCorpFingerprint {
		t.Errorf("PrimaryFingerprint = %q, want %q", info.PrimaryFingerprint, testHashiCorpFingerprint)
	}
	if armored == "" {
		t.Error("armored body is empty")
	}
}

func TestFetchReleasesKey_FingerprintMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(HashiCorpReleasesGPGKey))
	}))
	t.Cleanup(srv.Close)

	// Wrong fingerprint (all zeros, valid shape) — must be rejected.
	const wrong = "0000000000000000000000000000000000000000"
	_, _, err := FetchReleasesKey(context.Background(), srv.Client(), srv.URL, wrong)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
	}
}

func TestFetchReleasesKey_FingerprintCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(HashiCorpReleasesGPGKey))
	}))
	t.Cleanup(srv.Close)

	// Allow-listed fingerprints are commonly copy-pasted in lowercase; the
	// pin check must succeed regardless of case.
	lower := "c874011f0ab405110d02105534365d9472d7468f"
	if _, _, err := FetchReleasesKey(context.Background(), srv.Client(), srv.URL, lower); err != nil {
		t.Fatalf("expected case-insensitive match to succeed, got %v", err)
	}
}

func TestFetchReleasesKey_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, _, err := FetchReleasesKey(context.Background(), srv.Client(), srv.URL, testHashiCorpFingerprint)
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}

func TestFetchReleasesKey_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a pgp key block"))
	}))
	t.Cleanup(srv.Close)

	_, _, err := FetchReleasesKey(context.Background(), srv.Client(), srv.URL, testHashiCorpFingerprint)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestFetchReleasesKey_BadFingerprintShape(t *testing.T) {
	// "too short" is not a 40-char hex string — the fetcher must reject the
	// pin without making any HTTP call.
	_, _, err := FetchReleasesKey(context.Background(), nil, "http://example.invalid", "TOO-SHORT")
	if err == nil {
		t.Fatal("expected validation error for bad fingerprint shape, got nil")
	}
}

func TestIsAllowedFingerprintShape(t *testing.T) {
	tests := []struct {
		fpr string
		ok  bool
	}{
		{"C874011F0AB405110D02105534365D9472D7468F", true},
		{"c874011f0ab405110d02105534365d9472d7468f", true},   // lower
		{"C874011F0AB405110D02105534365D9472D7468", false},   // 39 chars
		{"C874011F0AB405110D02105534365D9472D7468FX", false}, // 41
		{"G874011F0AB405110D02105534365D9472D7468F", false},  // non-hex
		{"", false},
	}
	for _, tc := range tests {
		if got := isAllowedFingerprintShape(tc.fpr); got != tc.ok {
			t.Errorf("isAllowedFingerprintShape(%q) = %v, want %v", tc.fpr, got, tc.ok)
		}
	}
}

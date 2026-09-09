package appcreds

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	sharedcreds "github.com/sethbacon/terraform-suite-identity/identity/appcreds"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// loopbackGuard allow-lists the loopback addresses httptest.NewServer binds to
// (127.0.0.1 / ::1) so the positive-path tests below can exercise a real HTTP
// round trip through the httpsafe-guarded client (issue #676) without the
// strict default policy rejecting the test server itself as an internal
// target.
var loopbackGuard = httpsafe.MustGuard("127.0.0.1", "::1")

// fakeStore is an in-memory ProviderTokenStore for tests.
type fakeStore struct {
	get     *scm.SCMProviderTokenRecord
	getErr  error
	upserts []*scm.SCMProviderTokenRecord
}

func (f *fakeStore) GetProviderToken(_ context.Context, _ uuid.UUID) (*scm.SCMProviderTokenRecord, error) {
	return f.get, f.getErr
}

func (f *fakeStore) UpsertProviderToken(_ context.Context, rec *scm.SCMProviderTokenRecord) error {
	f.upserts = append(f.upserts, rec)
	return nil
}

func testCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	c, err := crypto.NewTokenCipher(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return c
}

func generateTestKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func strptr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Entra (Azure DevOps) client-credentials
// ---------------------------------------------------------------------------

func TestMintProviderToken_EntraApp(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if !strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = r.ParseForm()
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("scope"); got != sharedcreds.AzureDevOpsResourceID+"/.default" {
			t.Errorf("scope = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "the-secret" {
			t.Errorf("client_secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"ado-token","expires_in":3600}`)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	store := &fakeStore{}
	m := testMinter(t, cipher, store, sharedcreds.WithEntraLoginBaseURL(srv.URL))

	secret, _ := cipher.Seal("the-secret")
	p := &scm.SCMProvider{
		ID:                    uuid.New(),
		ProviderType:          scm.ProviderAzureDevOps,
		AuthMode:              scm.AuthModeEntraApp,
		TenantID:              strptr("tenant-1"),
		ClientID:              "client-1",
		ClientSecretEncrypted: secret,
	}

	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "ado-token" {
		t.Errorf("token = %q, want ado-token", tok.AccessToken)
	}
	if called != 1 {
		t.Errorf("idp called %d times, want 1", called)
	}
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(store.upserts))
	}
	// The cached token is bound to its provider row (suite-identity #153), so it
	// opens under that row's context and NOT with a plain Open. This assertion
	// previously used Open and is inverted rather than relaxed: a value that
	// still opened unbound would mean the binding never happened.
	dec, err := cipher.OpenWithContext(
		store.upserts[0].AccessTokenEncrypted, scm.ProviderTokenContext(p.ID))
	if err != nil || dec != "ado-token" {
		t.Errorf("cached token under its own context = (%q, %v), want ado-token", dec, err)
	}
	if _, err := cipher.Open(store.upserts[0].AccessTokenEncrypted); err == nil {
		t.Error("cached token still opens WITHOUT a context; it was not bound to its provider row")
	}
	// And it must not open as another provider's cached token -- the move this
	// binding exists to prevent.
	if _, err := cipher.OpenWithContext(
		store.upserts[0].AccessTokenEncrypted, scm.ProviderTokenContext(uuid.New()),
	); err == nil {
		t.Error("cached token opened under another provider's context; the binding is vacuous")
	}
}

func TestMintProviderToken_EntraApp_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	m := testMinter(t, cipher, &fakeStore{}, sharedcreds.WithEntraLoginBaseURL(srv.URL))

	secret, _ := cipher.Seal("bad")
	p := &scm.SCMProvider{
		ID:                    uuid.New(),
		AuthMode:              scm.AuthModeEntraApp,
		TenantID:              strptr("t"),
		ClientID:              "c",
		ClientSecretEncrypted: secret,
	}
	if _, err := m.MintProviderToken(context.Background(), p); err == nil {
		t.Fatal("expected error on 401 from Entra")
	}
}

// TestMintProviderToken_EntraApp_RejectsLoopbackTarget exercises the egress
// guard wired in NewMinter/NewMinterWithGuard (issue #676): entraLoginBaseURL
// is hard-coded in production, but the client itself must still fail closed
// against an internal/loopback target rather than silently dialing it, so a
// future misconfiguration (or test regression) can't turn this into a live
// SSRF primitive. A nil guard is the strict default policy, and port 1 is
// closed, so no listener is needed for this to fail before any TCP connect.
func TestMintProviderToken_EntraApp_RejectsLoopbackTarget(t *testing.T) {
	cipher := testCipher(t)
	m := guardedMinter(t, cipher, &fakeStore{}, sharedcreds.WithEntraLoginBaseURL("https://127.0.0.1:1"))

	secret, _ := cipher.Seal("s")
	p := &scm.SCMProvider{
		ID:                    uuid.New(),
		AuthMode:              scm.AuthModeEntraApp,
		TenantID:              strptr("t"),
		ClientID:              "c",
		ClientSecretEncrypted: secret,
	}
	_, err := m.MintProviderToken(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for loopback entraLoginBaseURL target")
	}
	// Assert on the guard's own wording, not just "any error": port 1 is
	// closed, so a bare connection-refused error would also satisfy err != nil
	// without proving the egress guard is what blocked this.
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to mention the egress guard blocking the target", err.Error())
	}
}

// ---------------------------------------------------------------------------
// GitHub App installation token
// ---------------------------------------------------------------------------

func TestMintProviderToken_GitHubApp(t *testing.T) {
	keyPEM := generateTestKeyPEM(t)
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if !strings.Contains(r.URL.Path, "/app/installations/") || !strings.HasSuffix(r.URL.Path, "/access_tokens") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("authorization = %q, want Bearer app JWT", auth)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"ghs_token","expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	store := &fakeStore{}
	m := testMinter(t, cipher, store, sharedcreds.WithGitHubAPIBaseURL(srv.URL))

	encKey, _ := cipher.Seal(keyPEM)
	p := &scm.SCMProvider{
		ID:                     uuid.New(),
		ProviderType:           scm.ProviderGitHub,
		AuthMode:               scm.AuthModeGitHubApp,
		GitHubAppID:            strptr("12345"),
		GitHubInstallationID:   strptr("67890"),
		EncryptedAppPrivateKey: &encKey,
	}

	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "ghs_token" {
		t.Errorf("token = %q, want ghs_token", tok.AccessToken)
	}
	if called != 1 {
		t.Errorf("github called %d times, want 1", called)
	}
	if len(store.upserts) != 1 {
		t.Errorf("upserts = %d, want 1", len(store.upserts))
	}
}

// TestMintProviderToken_GitHubApp_RejectsLoopbackTarget is the GitHub-App
// counterpart of TestMintProviderToken_EntraApp_RejectsLoopbackTarget: the
// installation-token exchange must fail closed against a loopback
// githubAPIBaseURL rather than dialing it (issue #676).
func TestMintProviderToken_GitHubApp_RejectsLoopbackTarget(t *testing.T) {
	cipher := testCipher(t)
	m := guardedMinter(t, cipher, &fakeStore{}, sharedcreds.WithGitHubAPIBaseURL("https://127.0.0.1:1"))

	encKey, _ := cipher.Seal(generateTestKeyPEM(t))
	p := &scm.SCMProvider{
		ID:                     uuid.New(),
		ProviderType:           scm.ProviderGitHub,
		AuthMode:               scm.AuthModeGitHubApp,
		GitHubAppID:            strptr("12345"),
		GitHubInstallationID:   strptr("67890"),
		EncryptedAppPrivateKey: &encKey,
	}
	_, err := m.MintProviderToken(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for loopback githubAPIBaseURL target")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to mention the egress guard blocking the target", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Caching
// ---------------------------------------------------------------------------

func TestMintProviderToken_CacheHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("identity provider must not be called on a cache hit")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	enc, _ := cipher.Seal("cached-token")
	exp := time.Now().Add(time.Hour)
	id := uuid.New()
	store := &fakeStore{get: &scm.SCMProviderTokenRecord{
		SCMProviderID:        id,
		AccessTokenEncrypted: enc,
		TokenType:            "Bearer",
		ExpiresAt:            &exp,
	}}
	m := testMinter(t, cipher, store, sharedcreds.WithEntraLoginBaseURL(srv.URL))

	secret, _ := cipher.Seal("s")
	p := &scm.SCMProvider{
		ID:                    id,
		AuthMode:              scm.AuthModeEntraApp,
		TenantID:              strptr("t"),
		ClientID:              "c",
		ClientSecretEncrypted: secret,
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "cached-token" {
		t.Errorf("token = %q, want cached-token", tok.AccessToken)
	}
	if len(store.upserts) != 0 {
		t.Errorf("cache hit should not upsert, got %d", len(store.upserts))
	}
}

func TestMintProviderToken_CacheExpiredRemints(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"fresh-token","expires_in":3600}`)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	enc, _ := cipher.Seal("stale-token")
	past := time.Now().Add(-time.Minute) // within refresh margin / already expired
	id := uuid.New()
	store := &fakeStore{get: &scm.SCMProviderTokenRecord{
		SCMProviderID:        id,
		AccessTokenEncrypted: enc,
		TokenType:            "Bearer",
		ExpiresAt:            &past,
	}}
	m := testMinter(t, cipher, store, sharedcreds.WithEntraLoginBaseURL(srv.URL))

	secret, _ := cipher.Seal("s")
	p := &scm.SCMProvider{
		ID:                    id,
		AuthMode:              scm.AuthModeEntraApp,
		TenantID:              strptr("t"),
		ClientID:              "c",
		ClientSecretEncrypted: secret,
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "fresh-token" {
		t.Errorf("token = %q, want fresh-token", tok.AccessToken)
	}
	if called != 1 {
		t.Errorf("expected a re-mint (1 IdP call), got %d", called)
	}
}

// ---------------------------------------------------------------------------
// Validation / error paths
// ---------------------------------------------------------------------------

func TestMintProviderToken_UnsupportedMode(t *testing.T) {
	m := NewMinter(testCipher(t), &fakeStore{})
	p := &scm.SCMProvider{ID: uuid.New(), AuthMode: scm.AuthModeOAuthUser}
	if _, err := m.MintProviderToken(context.Background(), p); err == nil {
		t.Fatal("expected error for oauth_user provider")
	}
}

func TestMintProviderToken_MissingEntraCreds(t *testing.T) {
	m := NewMinter(testCipher(t), &fakeStore{})
	p := &scm.SCMProvider{ID: uuid.New(), AuthMode: scm.AuthModeEntraApp, ClientID: "c"} // no tenant
	if _, err := m.MintProviderToken(context.Background(), p); err == nil {
		t.Fatal("expected error for entra_app missing tenant_id")
	}
}

func TestMintProviderToken_MissingGitHubCreds(t *testing.T) {
	m := NewMinter(testCipher(t), &fakeStore{})
	p := &scm.SCMProvider{ID: uuid.New(), AuthMode: scm.AuthModeGitHubApp, GitHubAppID: strptr("1")} // no installation/key
	if _, err := m.MintProviderToken(context.Background(), p); err == nil {
		t.Fatal("expected error for github_app missing fields")
	}
}

func TestMintProviderToken_NilProvider(t *testing.T) {
	m := NewMinter(testCipher(t), &fakeStore{})
	if _, err := m.MintProviderToken(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

// ValidRSAPrivateKey is now a re-export of the shared package's. This guards the
// WIRING: the admin handlers validate an uploaded App key through this name, and
// a re-export left pointing at nothing (or at a different function) would accept
// a key the mint then rejects, days later and somewhere else.
func TestValidRSAPrivateKey(t *testing.T) {
	if !ValidRSAPrivateKey(generateTestKeyPEM(t)) {
		t.Error("generated RSA key should be valid")
	}
	if ValidRSAPrivateKey("not a pem") {
		t.Error("garbage should not be a valid RSA key")
	}
	if ValidRSAPrivateKey("") {
		t.Error("empty string should not be a valid RSA key")
	}
}

// TestSignAppJWT_Structure used to live here. It asserted that the app JWT had
// three segments; the signing itself now belongs to
// terraform-suite-identity/identity/appcreds, whose TestMintGitHubApp_Success
// VERIFIES the RS256 signature against the app's own public key and checks the
// header, the issuer, the clock-skew backdating and GitHub's 10-minute lifetime
// cap. Deleted rather than kept as a weaker duplicate (suite-identity#301).

// suite-identity #153 transition. A cache entry written before the binding
// shipped must still serve, or the deploy that ships this forces every provider
// to re-mint at once.
func TestMintProviderToken_ServesALegacyUnboundCacheEntry(t *testing.T) {
	cipher := testCipher(t)
	providerID := uuid.New()

	legacy, err := cipher.Seal("cached-legacy-token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	future := time.Now().Add(time.Hour)
	store := &fakeStore{get: &scm.SCMProviderTokenRecord{
		SCMProviderID:        providerID,
		AccessTokenEncrypted: legacy,
		TokenType:            "Bearer",
		ExpiresAt:            &future,
	}}

	m := testMinter(t, cipher, store)
	tok, err := m.MintProviderToken(context.Background(), &scm.SCMProvider{
		ID: providerID, AuthMode: scm.AuthModeEntraApp,
	})
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "cached-legacy-token" {
		t.Errorf("token = %q; an unbound cache entry must still serve during the transition", tok.AccessToken)
	}
	// Served from cache, so nothing was minted and nothing was written.
	if len(store.upserts) != 0 {
		t.Errorf("upserts = %d, want 0 — the cached entry should have been served as-is", len(store.upserts))
	}
}

// The other side: a cache entry bound to a DIFFERENT provider must not be
// served. It falls through to a fresh mint rather than handing one provider's
// token to another.
func TestMintProviderToken_IgnoresACacheEntryBoundToAnotherProvider(t *testing.T) {
	cipher := testCipher(t)
	providerID := uuid.New()

	foreign, err := cipher.SealWithContext("someone-elses-token", scm.ProviderTokenContext(uuid.New()))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}
	future := time.Now().Add(time.Hour)
	store := &fakeStore{get: &scm.SCMProviderTokenRecord{
		SCMProviderID:        providerID,
		AccessTokenEncrypted: foreign,
		TokenType:            "Bearer",
		ExpiresAt:            &future,
	}}

	m := testMinter(t, cipher, store)
	tok, err := m.MintProviderToken(context.Background(), &scm.SCMProvider{
		ID: providerID, AuthMode: scm.AuthModeEntraApp,
	})
	// The mint itself fails here (no IdP configured in this fixture); what
	// matters is that the foreign token was NOT returned.
	if err == nil && tok != nil && tok.AccessToken == "someone-elses-token" {
		t.Fatal("served a cached token bound to a different provider row")
	}
}

// testMinter builds a Minter whose exchanges reach a test server.
//
// The endpoint hosts used to be fields on this package's Minter, poked directly
// by each test. They now belong to the shared minter, so they are supplied as
// options at construction -- which is also what production does, through exactly
// one option (the guarded client).
func testMinter(t *testing.T, cipher *crypto.TokenCipher, store ProviderTokenStore, opts ...sharedcreds.Option) *Minter {
	t.Helper()
	return newMinter(cipher, store, httpsafe.NewClient(egressTimeout, loopbackGuard), opts...)
}

// guardedMinter builds a Minter with the STRICT egress policy -- the production
// default -- for the tests that assert an internal target is refused.
func guardedMinter(t *testing.T, cipher *crypto.TokenCipher, store ProviderTokenStore, opts ...sharedcreds.Option) *Minter {
	t.Helper()
	return newMinter(cipher, store, httpsafe.NewClient(egressTimeout, nil), opts...)
}

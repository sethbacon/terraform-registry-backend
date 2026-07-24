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
		if got := r.Form.Get("scope"); got != azureDevOpsResourceID+"/.default" {
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
	m := NewMinterWithGuard(cipher, store, loopbackGuard)
	m.entraLoginBaseURL = srv.URL

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
	dec, _ := cipher.Open(store.upserts[0].AccessTokenEncrypted)
	if dec != "ado-token" {
		t.Errorf("cached token decrypts to %q, want ado-token", dec)
	}
}

func TestMintProviderToken_EntraApp_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	cipher := testCipher(t)
	m := NewMinterWithGuard(cipher, &fakeStore{}, loopbackGuard)
	m.entraLoginBaseURL = srv.URL

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
	m := NewMinter(cipher, &fakeStore{}) // nil guard == strict default
	m.entraLoginBaseURL = "https://127.0.0.1:1"

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
	m := NewMinterWithGuard(cipher, store, loopbackGuard)
	m.githubAPIBaseURL = srv.URL

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
	m := NewMinter(cipher, &fakeStore{}) // nil guard == strict default
	m.githubAPIBaseURL = "https://127.0.0.1:1"

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
	m := NewMinter(cipher, store)
	m.entraLoginBaseURL = srv.URL

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
	m := NewMinterWithGuard(cipher, store, loopbackGuard)
	m.entraLoginBaseURL = srv.URL

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

func TestSignAppJWT_Structure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwt, err := signAppJWT("appid", key, time.Now())
	if err != nil {
		t.Fatalf("signAppJWT: %v", err)
	}
	if parts := strings.Split(jwt, "."); len(parts) != 3 {
		t.Errorf("jwt has %d segments, want 3", len(parts))
	}
}

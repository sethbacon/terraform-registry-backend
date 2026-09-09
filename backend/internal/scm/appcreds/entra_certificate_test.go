package appcreds

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"
	sharedcreds "github.com/sethbacon/terraform-suite-identity/identity/appcreds"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1041 -- dispatch policy only. The exchange itself is tested in
// terraform-suite-identity/identity/appcreds; what this repository owns is
// that a provider ROW with entra_credential_type=certificate routes to it,
// with the bundle opened under its own row-bound context.

func testBundle(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

type recordedCertFactory struct {
	cred     *fakeFederatedCredential
	calls    int
	tenantID string
	clientID string
	ncerts   int
}

func (f *recordedCertFactory) factory() sharedcreds.CertificateCredentialFactory {
	return func(_ string, tenantID, clientID string, certs []*x509.Certificate, _ crypto.PrivateKey) (sharedcreds.FederatedCredential, error) {
		f.calls++
		f.tenantID, f.clientID, f.ncerts = tenantID, clientID, len(certs)
		return f.cred, nil
	}
}

func TestMintProviderToken_CertificateRowUsesTheCertificateCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-secret token endpoint was called for a certificate provider")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	fake := &recordedCertFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "cert-ado-token", ExpiresOn: expiry}}}
	cipher := testCipher(t)
	store := &fakeStore{}
	m := testMinter(t, cipher, store,
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithCertificateCredentialFactory(fake.factory()))

	id := uuid.New()
	bundle := testBundle(t)
	sealed, err := cipher.SealWithContext(bundle, scm.ProviderEntraCertificateContext(id.String()))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	p := &scm.SCMProvider{
		ID: id, ProviderType: scm.ProviderAzureDevOps, AuthMode: scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialCertificate,
		TenantID:            strptr("tenant-1"), ClientID: "client-1", EncryptedEntraCertificate: &sealed,
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "cert-ado-token" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if fake.calls != 1 || fake.tenantID != "tenant-1" || fake.clientID != "client-1" || fake.ncerts != 1 {
		t.Errorf("certificate credential built %d times for (%q, %q, %d certs)", fake.calls, fake.tenantID, fake.clientID, fake.ncerts)
	}
	// Cached sealed and bound to the row -- the policy that did not move.
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(store.upserts))
	}
	if dec, err := cipher.OpenWithContext(store.upserts[0].AccessTokenEncrypted, scm.ProviderTokenContext(id)); err != nil || dec != "cert-ado-token" {
		t.Errorf("cached token under its own context = (%q, %v)", dec, err)
	}
}

// A bundle sealed for ANOTHER row must not mint for this one.
func TestMintProviderToken_CertificateBundleIsBoundToItsRow(t *testing.T) {
	fake := &recordedCertFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}}}
	cipher := testCipher(t)
	m := testMinter(t, cipher, &fakeStore{}, sharedcreds.WithCertificateCredentialFactory(fake.factory()))

	other := uuid.New()
	sealedForOther, _ := cipher.SealWithContext(testBundle(t), scm.ProviderEntraCertificateContext(other.String()))
	p := &scm.SCMProvider{
		ID: uuid.New(), ProviderType: scm.ProviderAzureDevOps, AuthMode: scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialCertificate,
		TenantID:            strptr("t"), ClientID: "c", EncryptedEntraCertificate: &sealedForOther,
	}
	if _, err := m.MintProviderToken(context.Background(), p); err == nil {
		t.Fatal("a bundle sealed for another provider's row minted a token for this one")
	}
	if fake.calls != 0 {
		t.Errorf("the credential was built %d times from a foreign bundle, want 0", fake.calls)
	}
}

func TestMintProviderToken_ClientSecretRowDoesNotUseTheCertificateCredential(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"secret-ado-token","expires_in":3600}`))
	}))
	defer srv.Close()
	fake := &recordedCertFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "should-not-be-used"}}}
	cipher := testCipher(t)
	m := testMinter(t, cipher, &fakeStore{},
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithCertificateCredentialFactory(fake.factory()))
	secret, _ := cipher.Seal("the-secret")
	p := &scm.SCMProvider{
		ID: uuid.New(), ProviderType: scm.ProviderAzureDevOps, AuthMode: scm.AuthModeEntraApp,
		TenantID: strptr("t"), ClientID: "c", ClientSecretEncrypted: secret,
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil || tok.AccessToken != "secret-ado-token" || called != 1 || fake.calls != 0 {
		t.Fatalf("client_secret row: err=%v token=%q idp calls=%d cert factory calls=%d", err, tok.AccessToken, called, fake.calls)
	}
}

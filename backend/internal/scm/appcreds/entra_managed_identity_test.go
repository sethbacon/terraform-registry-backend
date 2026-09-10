package appcreds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"
	sharedcreds "github.com/sethbacon/terraform-suite-identity/identity/appcreds"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1042 -- dispatch policy. The exchange is tested in the shared module;
// what this repository owns is that a provider ROW with
// entra_credential_type=managed_identity routes to it, carrying only the
// client id that names which identity to assume.

type recordedMIFactory struct {
	cred     *fakeFederatedCredential
	calls    int
	clientID string
}

func (f *recordedMIFactory) factory() sharedcreds.ManagedIdentityCredentialFactory {
	return func(clientID string) (sharedcreds.FederatedCredential, error) {
		f.calls++
		f.clientID = clientID
		return f.cred, nil
	}
}

func TestMintProviderToken_ManagedIdentityRowUsesTheManagedIdentityCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-secret token endpoint was called for a managed identity provider")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	fake := &recordedMIFactory{cred: &fakeFederatedCredential{
		token: azcore.AccessToken{Token: "mi-ado-token", ExpiresOn: expiry}}}
	cipher := testCipher(t)
	store := &fakeStore{}
	m := testMinter(t, cipher, store,
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithManagedIdentityCredentialFactory(fake.factory()))

	id := uuid.New()
	p := &scm.SCMProvider{
		ID: id, ProviderType: scm.ProviderAzureDevOps, AuthMode: scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialManagedIdentity, ClientID: "uami-1",
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "mi-ado-token" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if fake.calls != 1 {
		t.Fatalf("managed identity exchanged %d times, want 1", fake.calls)
	}
	// The row's client_id selects WHICH identity; the wrong one mints a valid
	// token for the wrong principal.
	if fake.clientID != "uami-1" {
		t.Errorf("credential built for client_id %q, want the row's uami-1", fake.clientID)
	}
	// Cached sealed and bound to the row, like every other credential type.
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(store.upserts))
	}
	if dec, err := cipher.OpenWithContext(store.upserts[0].AccessTokenEncrypted, scm.ProviderTokenContext(id)); err != nil || dec != "mi-ado-token" {
		t.Errorf("cached token under its own context = (%q, %v)", dec, err)
	}
}

// A provider that has NOT opted into managed identity must keep using its
// secret; otherwise every existing entra_app provider would be rerouted.
func TestMintProviderToken_ClientSecretRowDoesNotUseManagedIdentity(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"secret-ado-token","expires_in":3600}`))
	}))
	defer srv.Close()

	fake := &recordedMIFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "should-not-be-used"}}}
	cipher := testCipher(t)
	m := testMinter(t, cipher, &fakeStore{},
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithManagedIdentityCredentialFactory(fake.factory()))
	secret, _ := cipher.Seal("the-secret")
	p := &scm.SCMProvider{
		ID: uuid.New(), ProviderType: scm.ProviderAzureDevOps, AuthMode: scm.AuthModeEntraApp,
		TenantID: strptr("t"), ClientID: "c", ClientSecretEncrypted: secret,
	}
	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil || tok.AccessToken != "secret-ado-token" || called != 1 || fake.calls != 0 {
		t.Fatalf("client_secret row: err=%v token=%q idp=%d mi=%d", err, tok.AccessToken, called, fake.calls)
	}
}

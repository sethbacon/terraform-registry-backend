package appcreds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	sharedcreds "github.com/sethbacon/terraform-suite-identity/identity/appcreds"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Issue #1037 -- an entra_app provider may prove itself with workload identity
// federation instead of a stored client secret.
//
// The federated EXCHANGE is no longer tested here: it belongs to
// terraform-suite-identity/identity/appcreds, which tests it against a fake
// credential and asserts the audience, the trimming and every failure mode
// (suite-identity#301). What is tested here is the part this repository still
// owns -- that a provider ROW selects the right mechanism -- because the row
// shape and the entra_credential_type column are this application's policy and
// the shared package has never heard of either.

// fakeFederatedCredential stands in for the projected-token exchange, which no
// test host can perform.
type fakeFederatedCredential struct {
	token    azcore.AccessToken
	calls    int
	clientID string
}

func (f *fakeFederatedCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	return f.token, nil
}

// federatedFactory records the client id the provider row supplied.
func federatedFactory(cred *fakeFederatedCredential) sharedcreds.FederatedCredentialFactory {
	return func(clientID string) (sharedcreds.FederatedCredential, error) {
		cred.clientID = clientID
		return cred, nil
	}
}

func TestMintProviderToken_FederatedRowUsesWorkloadIdentity(t *testing.T) {
	// An IdP that fails the test if it is reached. A federated provider has no
	// client secret, so any call here means the client-secret arm ran -- the
	// dispatch failure this test exists to catch, and one that would otherwise
	// surface as a confusing "missing client secret" in production.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-secret token endpoint was called for a federated provider")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	cred := &fakeFederatedCredential{token: azcore.AccessToken{Token: "federated-ado-token", ExpiresOn: expiry}}

	cipher := testCipher(t)
	store := &fakeStore{}
	m := testMinter(t, cipher, store,
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithFederatedCredentialFactory(federatedFactory(cred)))

	p := &scm.SCMProvider{
		ID:                  uuid.New(),
		ProviderType:        scm.ProviderAzureDevOps,
		AuthMode:            scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialFederated,
		ClientID:            "federated-client-1",
	}

	tok, err := m.MintProviderToken(context.Background(), p)
	if err != nil {
		t.Fatalf("MintProviderToken: %v", err)
	}
	if tok.AccessToken != "federated-ado-token" {
		t.Errorf("token = %q, want federated-ado-token", tok.AccessToken)
	}
	if cred.calls != 1 {
		t.Fatalf("workload identity exchanged %d times, want 1", cred.calls)
	}
	// The row's client_id is what selects the identity, and it is the only
	// field a federated row carries -- so passing the wrong one would mint a
	// valid token for the wrong tenant's identity.
	if cred.clientID != "federated-client-1" {
		t.Errorf("credential built for client_id %q, want the row's federated-client-1", cred.clientID)
	}

	// Cached like any other provider token, sealed and bound to its row
	// (suite-identity #153). Federation changes how a token is obtained, not how
	// this application keeps it -- and the persistent cache is precisely the
	// policy that did NOT move to the shared package.
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(store.upserts))
	}
	dec, err := cipher.OpenWithContext(store.upserts[0].AccessTokenEncrypted, scm.ProviderTokenContext(p.ID))
	if err != nil || dec != "federated-ado-token" {
		t.Errorf("cached token under its own context = (%q, %v), want federated-ado-token", dec, err)
	}
	if store.upserts[0].ExpiresAt == nil || !store.upserts[0].ExpiresAt.Equal(expiry) {
		t.Errorf("cached expiry = %v, want the credential's %v", store.upserts[0].ExpiresAt, expiry)
	}
}

// A provider that has NOT opted into federation must keep using its client
// secret. Without this the test above could be satisfied by routing every
// entra_app provider through workload identity, which would break every
// existing deployment on the release that ships it.
func TestMintProviderToken_ClientSecretRowDoesNotUseWorkloadIdentity(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"secret-ado-token","expires_in":3600}`))
	}))
	defer srv.Close()

	cred := &fakeFederatedCredential{token: azcore.AccessToken{Token: "should-not-be-used"}}
	cipher := testCipher(t)
	m := testMinter(t, cipher, &fakeStore{},
		sharedcreds.WithEntraLoginBaseURL(srv.URL),
		sharedcreds.WithFederatedCredentialFactory(federatedFactory(cred)))

	secret, _ := cipher.Seal("the-secret")
	// Empty EntraCredentialType on purpose: every row written before migration
	// 000062, and every caller that never sets the field.
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
	if tok.AccessToken != "secret-ado-token" {
		t.Errorf("token = %q, want secret-ado-token", tok.AccessToken)
	}
	if called != 1 {
		t.Errorf("idp called %d times, want 1", called)
	}
	if cred.calls != 0 {
		t.Errorf("workload identity was used %d times for a client_secret row, want 0", cred.calls)
	}
}

// A federated row with no client_id has no identity to assume. The shared
// package refuses it; this asserts the refusal survives the wiring rather than
// being swallowed into a nil token.
func TestMintProviderToken_FederatedRowWithoutAClientID(t *testing.T) {
	m := testMinter(t, testCipher(t), &fakeStore{})
	_, err := m.MintProviderToken(context.Background(), &scm.SCMProvider{
		ID:                  uuid.New(),
		ProviderType:        scm.ProviderAzureDevOps,
		AuthMode:            scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialFederated,
	})
	if err == nil {
		t.Fatal("a federated provider with no client_id minted a token")
	}
}

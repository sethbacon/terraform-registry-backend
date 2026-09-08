package appcreds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// fakeWorkloadCredential stands in for the projected-token exchange. Tests may
// substitute it because a real WorkloadIdentityCredential needs a platform that
// projects a service-account token, which no test host does.
type fakeWorkloadCredential struct {
	token    azcore.AccessToken
	err      error
	scopes   []string
	calls    int
	clientID string
}

func (f *fakeWorkloadCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.scopes = opts.Scopes
	return f.token, f.err
}

// withFakeWorkloadIdentity swaps the credential factory for the duration of one
// test and records the client id it was asked for -- the assertion that the
// provider row selects the identity, since a federated mint has no other input.
func withFakeWorkloadIdentity(t *testing.T, cred *fakeWorkloadCredential, buildErr error) {
	t.Helper()
	prev := workloadIdentityCredentialFactory
	t.Cleanup(func() { workloadIdentityCredentialFactory = prev })
	workloadIdentityCredentialFactory = func(clientID string) (adoTokenCredential, error) {
		cred.clientID = clientID
		if buildErr != nil {
			return nil, buildErr
		}
		return cred, nil
	}
}

// federatedProvider is an entra_app provider that mints via workload identity:
// a client id, no tenant id and no stored secret.
func federatedProvider() *scm.SCMProvider {
	return &scm.SCMProvider{
		ID:                  uuid.New(),
		ProviderType:        scm.ProviderAzureDevOps,
		AuthMode:            scm.AuthModeEntraApp,
		EntraCredentialType: scm.EntraCredentialFederated,
		ClientID:            "federated-client-1",
	}
}

func TestMintProviderToken_FederatedUsesWorkloadIdentity(t *testing.T) {
	// An IdP that fails the test if it is reached. A federated provider has no
	// client secret, so any call here means the client-secret arm ran -- the
	// failure this test exists to catch, and one that would otherwise surface
	// only as a confusing "missing client secret" in production.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("client-secret token endpoint was called for a federated provider")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	cred := &fakeWorkloadCredential{token: azcore.AccessToken{Token: "federated-ado-token", ExpiresOn: expiry}}
	withFakeWorkloadIdentity(t, cred, nil)

	cipher := testCipher(t)
	store := &fakeStore{}
	m := NewMinterWithGuard(cipher, store, loopbackGuard)
	m.entraLoginBaseURL = srv.URL

	p := federatedProvider()
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
	if cred.clientID != "federated-client-1" {
		t.Errorf("credential built for client_id %q, want the provider row's federated-client-1", cred.clientID)
	}
	// The audience is what makes the token usable against Azure DevOps at all;
	// a token minted for the wrong resource authenticates to nothing.
	if len(cred.scopes) != 1 || !strings.HasPrefix(cred.scopes[0], azureDevOpsResourceID) {
		t.Errorf("scopes = %v, want the Azure DevOps resource id %s/.default", cred.scopes, azureDevOpsResourceID)
	}

	// Cached like any other provider token, bound to its row (suite-identity
	// #153) -- federation changes how the token is obtained, not how it is kept.
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
// secret. Without this the previous test could be satisfied by routing every
// entra_app provider through workload identity, which would break every
// existing deployment on the release that ships this.
func TestMintProviderToken_ClientSecretProviderDoesNotUseWorkloadIdentity(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"secret-ado-token","expires_in":3600}`))
	}))
	defer srv.Close()

	cred := &fakeWorkloadCredential{token: azcore.AccessToken{Token: "should-not-be-used"}}
	withFakeWorkloadIdentity(t, cred, nil)

	cipher := testCipher(t)
	m := NewMinterWithGuard(cipher, &fakeStore{}, loopbackGuard)
	m.entraLoginBaseURL = srv.URL

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
		t.Errorf("workload identity was used %d times for a client_secret provider, want 0", cred.calls)
	}
}

func TestMintFederatedToken_Failures(t *testing.T) {
	m := NewMinterWithGuard(testCipher(t), &fakeStore{}, loopbackGuard)

	t.Run("no client id", func(t *testing.T) {
		cred := &fakeWorkloadCredential{}
		withFakeWorkloadIdentity(t, cred, nil)
		if _, _, err := m.mintFederatedToken(context.Background(), FederatedCreds{}); err == nil {
			t.Fatal("a federated mint with no client_id succeeded; there is no identity to assert")
		}
		if cred.calls != 0 {
			t.Errorf("token exchange attempted %d times without a client id, want 0", cred.calls)
		}
	})

	t.Run("platform projects no token", func(t *testing.T) {
		// The realistic failure: running somewhere the workload-identity webhook
		// never ran, so AZURE_FEDERATED_TOKEN_FILE is absent.
		withFakeWorkloadIdentity(t, &fakeWorkloadCredential{}, errors.New("AZURE_FEDERATED_TOKEN_FILE is not set"))
		_, _, err := m.mintFederatedToken(context.Background(), FederatedCreds{ClientID: "c1"})
		if err == nil {
			t.Fatal("building a credential failed but the mint succeeded")
		}
		// The operator has to be able to tell "this host cannot federate" from
		// "these credentials are wrong"; the bare SDK error does not say which.
		if !strings.Contains(err.Error(), "AZURE_FEDERATED_TOKEN_FILE") {
			t.Errorf("error does not name what the platform must provide: %v", err)
		}
	})

	t.Run("exchange rejected", func(t *testing.T) {
		withFakeWorkloadIdentity(t, &fakeWorkloadCredential{err: errors.New("AADSTS700213: no matching federated identity record")}, nil)
		if _, _, err := m.mintFederatedToken(context.Background(), FederatedCreds{ClientID: "c1"}); err == nil {
			t.Fatal("the exchange was rejected but the mint succeeded")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		// A credential that reports success with nothing in it would otherwise
		// be cached and sent to Azure DevOps as an empty bearer token.
		withFakeWorkloadIdentity(t, &fakeWorkloadCredential{token: azcore.AccessToken{}}, nil)
		if _, _, err := m.mintFederatedToken(context.Background(), FederatedCreds{ClientID: "c1"}); err == nil {
			t.Fatal("an empty token was accepted")
		}
	})
}

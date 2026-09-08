// entra_federated.go mints Azure DevOps access tokens through workload identity
// federation: the platform (AKS, Container Apps, any OIDC-capable host) projects
// a service-account token, and that token is exchanged for an Entra one. No
// client secret exists, so there is nothing to store, rotate, or leak (#1037).
//
// PORTED, NOT INVENTED. terraform-state-manager-backend has run this mechanism
// in internal/pipelines/entra.go since before this issue was filed, using the
// same azidentity.WorkloadIdentityCredential and the same ADO scope. This is the
// registry side of the same thing. The duplication is real and is tracked in
// sethbacon/terraform-suite-identity#301, which proposes extracting the whole
// credential-minting mechanism into the module both backends already depend on;
// until that lands, matching the working implementation beats writing a second
// design.
package appcreds

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// FederatedCreds identifies a workload identity used to mint Azure DevOps
// tokens. Unlike EntraCreds there is no secret material at all: only the
// federated app registration's client id.
//
// TenantID and the path to the projected token come from the pod's own
// environment (AZURE_TENANT_ID / AZURE_FEDERATED_TOKEN_FILE, set by the AKS
// workload-identity webhook) rather than from the provider row -- the row
// records WHICH identity to use, the platform supplies the proof. That is why
// a federated provider needs no tenant_id of its own.
type FederatedCreds struct {
	ClientID string
}

// adoTokenCredential is the subset of azcore.TokenCredential this needs,
// satisfied by *azidentity.WorkloadIdentityCredential and by a fake in tests.
// Narrow on purpose: a full azcore.TokenCredential is not substitutable without
// pulling the SDK into every test that touches minting.
type adoTokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// workloadIdentityCredentialFactory builds the credential for a client id. A
// package var so tests can substitute a fake without a real federated identity;
// production never overrides it.
var workloadIdentityCredentialFactory = func(clientID string) (adoTokenCredential, error) {
	return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		ClientID: clientID,
	})
}

// mintFederatedToken exchanges the platform-projected token for an Azure DevOps
// access token. Returns the token and its absolute expiry, matching
// mintEntraToken so MintProviderToken's caching is identical either way.
func (m *Minter) mintFederatedToken(ctx context.Context, creds FederatedCreds) (string, time.Time, error) {
	if strings.TrimSpace(creds.ClientID) == "" {
		return "", time.Time{}, errors.New("appcreds: federated entra_app provider missing client_id")
	}

	cred, err := workloadIdentityCredentialFactory(creds.ClientID)
	if err != nil {
		// The common cause is running outside a workload-identity-enabled
		// platform, where AZURE_FEDERATED_TOKEN_FILE is simply absent. Say so:
		// the raw SDK error names an environment variable without explaining
		// which deployment shape is expected to set it.
		return "", time.Time{}, fmt.Errorf(
			"appcreds: could not build a workload identity credential for client_id %s "+
				"(federated auth requires the platform to project a token -- on AKS that is the "+
				"workload-identity webhook setting AZURE_TENANT_ID and AZURE_FEDERATED_TOKEN_FILE): %w",
			creds.ClientID, err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{azureDevOpsResourceID + "/.default"},
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("appcreds: mint federated Azure DevOps token: %w", err)
	}
	if tok.Token == "" {
		return "", time.Time{}, errors.New("appcreds: federated token exchange returned an empty token")
	}
	return tok.Token, tok.ExpiresOn, nil
}

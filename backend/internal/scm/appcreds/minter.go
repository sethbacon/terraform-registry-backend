// Package appcreds mints shared, admin-managed SCM app credentials: a single
// provider-level token used for every user's module linking and all background
// syncs, replacing the legacy per-user OAuth model for providers opted into an
// app auth mode.
//
// Three credential types are supported:
//   - entra_app + client_secret: Microsoft Entra app registration (OAuth 2.0
//     client-credentials) for Azure DevOps.
//   - entra_app + federated: the same app registration proved by workload
//     identity federation, with no stored secret at all (#1037).
//   - github_app: a GitHub App (RS256 app JWT exchanged for an installation
//     access token) for GitHub.
//
// # What lives here and what does not
//
// THE EXCHANGES THEMSELVES ARE NOT HERE. They live in
// terraform-suite-identity/identity/appcreds, because terraform-state-manager
// implemented the same three mechanisms independently and the two copies drifted
// -- state-manager had workload identity federation before this repository did,
// this repository had the egress guard state-manager lacked, and neither gained
// the other's until someone went looking (suite-identity#301).
//
// What remains here is this application's POLICY, which is genuinely its own:
//   - the scm_providers row shape, and how credentials are read out of it;
//   - decrypting those credentials, each bound to the provider row it belongs to
//     (suite-identity#153), so a secret cannot be moved between rows;
//   - the persistent token cache in scm_provider_tokens, sealed and bound the
//     same way, which survives restarts and additional replicas.
//
// That last point is why this does not use the shared package's in-memory Cache:
// a process-local map cannot be revoked, cannot be shared between replicas, and
// would serve a token this application's own store had already replaced.
package appcreds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	sharedcreds "github.com/sethbacon/terraform-suite-identity/identity/appcreds"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// tokenRefreshMargin re-mints this long before a cached token's hard expiry so an
// in-flight request never races the expiry boundary.
const tokenRefreshMargin = 60 * time.Second

// egressTimeout bounds a token exchange, matching the other SCM outbound paths.
const egressTimeout = 30 * time.Second

// ValidRSAPrivateKey reports whether pemStr parses as a supported RSA private
// key. Re-exported rather than re-implemented so the admin handlers that
// validate an uploaded App key keep importing one package, and so the check they
// perform is by construction the same one the mint performs.
var ValidRSAPrivateKey = sharedcreds.ValidRSAPrivateKey

// ProviderTokenStore persists the shared app token cache. *repositories.SCMRepository
// satisfies it; tests supply a fake.
type ProviderTokenStore interface {
	GetProviderToken(ctx context.Context, providerID uuid.UUID) (*scm.SCMProviderTokenRecord, error)
	UpsertProviderToken(ctx context.Context, token *scm.SCMProviderTokenRecord) error
}

// SharedMinter returns a usable token for a provider in an app auth mode,
// refreshing from the IdP when the cached token is missing or near expiry.
type SharedMinter interface {
	MintProviderToken(ctx context.Context, p *scm.SCMProvider) (*scm.OAuthToken, error)
}

// Minter implements SharedMinter. It reads the provider's stored app credentials,
// hands them to the shared minter for the exchange, and caches the result.
type Minter struct {
	cipher        *crypto.TokenCipher
	store         ProviderTokenStore
	shared        *sharedcreds.Minter
	now           func() time.Time
	refreshMargin time.Duration
}

// NewMinter builds a Minter using the production identity-provider endpoints
// and the strict (no allow-list) egress policy. Equivalent to
// NewMinterWithGuard(cipher, store, nil).
func NewMinter(cipher *crypto.TokenCipher, store ProviderTokenStore) *Minter {
	return NewMinterWithGuard(cipher, store, nil)
}

// NewMinterWithGuard is NewMinter with an egress guard.
//
// The token-exchange requests carry a credential -- the RS256 app JWT, or the
// client secret itself -- so they go through this repository's own httpsafe
// resolve-and-pin client rather than a bare http.Client (issue #676). The client
// is BUILT HERE and handed over, rather than letting the shared package build
// its own: this repository has its own httpsafe with its own allow-list plumbing,
// and passing the finished client keeps one egress policy in force instead of
// two that can disagree.
func NewMinterWithGuard(cipher *crypto.TokenCipher, store ProviderTokenStore, egress *httpsafe.Guard) *Minter {
	return newMinter(cipher, store, httpsafe.NewClient(egressTimeout, egress))
}

// newMinter is the shared constructor.
//
// Tests use the option list to point the exchanges at an httptest server and to
// substitute the workload-identity credential factory, which no test host can
// satisfy for real. Production goes through NewMinterWithGuard, which supplies
// exactly one option: the guarded client.
// The client is a TYPED PARAMETER rather than one option among many, so that
// every construction of the shared minter carries a literal WithHTTPClient --
// which is what makes the invariant checkable by
// TestEgressGuard_SharedMinterIsBuiltWithAGuardedClient. Passed through a
// variadic option list it would be invisible to any static check, and an edit
// that dropped it would fall back to the shared package's own egress policy
// silently.
func newMinter(cipher *crypto.TokenCipher, store ProviderTokenStore, client *http.Client,
	opts ...sharedcreds.Option) *Minter {
	return &Minter{
		cipher: cipher,
		store:  store,
		shared: sharedcreds.New(append(
			[]sharedcreds.Option{sharedcreds.WithHTTPClient(client)}, opts...)...),
		now:           time.Now,
		refreshMargin: tokenRefreshMargin,
	}
}

// MintProviderToken returns a token for an app-mode provider, serving the cached
// token when still comfortably valid and otherwise minting + caching a fresh one.
func (m *Minter) MintProviderToken(ctx context.Context, p *scm.SCMProvider) (*scm.OAuthToken, error) {
	if p == nil {
		return nil, errors.New("appcreds: nil provider")
	}

	// Serve from the cache table when the token is not within the refresh margin.
	if m.store != nil {
		if rec, err := m.store.GetProviderToken(ctx, p.ID); err == nil && rec != nil {
			if rec.ExpiresAt == nil || rec.ExpiresAt.Sub(m.now()) > m.refreshMargin {
				// Accepts the row-bound form and the legacy unbound one, so a
				// cache written before this change still serves rather than
				// forcing every provider to re-mint on the deploy that ships it.
				tok, _, derr := m.cipher.OpenWithContextOrLegacy(
					rec.AccessTokenEncrypted, scm.ProviderTokenContext(p.ID))
				if derr == nil && tok != "" {
					return &scm.OAuthToken{AccessToken: tok, TokenType: rec.TokenType, ExpiresAt: rec.ExpiresAt}, nil
				}
			}
		}
	}

	var (
		minted sharedcreds.Token
		err    error
	)
	switch p.AuthMode {
	case scm.AuthModeEntraApp:
		// The credential type decides how, not whether. Both arms return a token
		// and an absolute expiry, so the caching below is identical either way
		// (#1037).
		if p.EntraCredentialType == scm.EntraCredentialFederated {
			minted, err = m.shared.MintFederated(ctx,
				sharedcreds.FederatedCreds{ClientID: p.ClientID})
			break
		}
		if p.EntraCredentialType == scm.EntraCredentialManagedIdentity {
			minted, err = m.shared.MintManagedIdentity(ctx,
				sharedcreds.ManagedIdentityCreds{ClientID: p.ClientID})
			break
		}
		if p.EntraCredentialType == scm.EntraCredentialCertificate {
			var certCreds sharedcreds.CertificateCreds
			if certCreds, err = m.certificateCreds(p); err == nil {
				minted, err = m.shared.MintCertificate(ctx, certCreds)
			}
			break
		}
		var creds sharedcreds.EntraCreds
		if creds, err = m.entraCreds(p); err == nil {
			minted, err = m.shared.MintEntra(ctx, creds)
		}
	case scm.AuthModeGitHubApp:
		var creds sharedcreds.GitHubAppCreds
		if creds, err = m.githubAppCreds(p); err == nil {
			minted, err = m.shared.MintGitHubApp(ctx, creds)
		}
	default:
		return nil, fmt.Errorf("appcreds: provider %s is not in an app auth mode (auth_mode=%q)", p.ID, p.AuthMode)
	}
	if err != nil {
		return nil, err
	}

	token, expiresAt := minted.AccessToken, minted.ExpiresAt

	// Best-effort cache write — a persistence failure must not fail the request.
	if m.store != nil {
		// Bound to the provider row: a cached token cannot be copied into another
		// provider's cache row and served as that provider's.
		if enc, sealErr := m.cipher.SealWithContext(token, scm.ProviderTokenContext(p.ID)); sealErr == nil {
			exp := expiresAt
			_ = m.store.UpsertProviderToken(ctx, &scm.SCMProviderTokenRecord{
				SCMProviderID:        p.ID,
				AccessTokenEncrypted: enc,
				TokenType:            "Bearer",
				ExpiresAt:            &exp,
			})
		}
	}

	exp := expiresAt
	return &scm.OAuthToken{AccessToken: token, TokenType: "Bearer", ExpiresAt: &exp}, nil
}

// entraCreds extracts and decrypts the Entra client-credentials for a provider.
func (m *Minter) entraCreds(p *scm.SCMProvider) (sharedcreds.EntraCreds, error) {
	if p.TenantID == nil || *p.TenantID == "" {
		return sharedcreds.EntraCreds{}, errors.New("appcreds: entra_app provider missing tenant_id")
	}
	if p.ClientID == "" {
		return sharedcreds.EntraCreds{}, errors.New("appcreds: entra_app provider missing client_id")
	}
	secret, _, err := m.cipher.OpenWithContextOrLegacy(
		p.ClientSecretEncrypted, scm.ProviderClientSecretContext(p.ID.String()))
	if err != nil {
		return sharedcreds.EntraCreds{}, fmt.Errorf("appcreds: decrypt client secret: %w", err)
	}
	if secret == "" {
		return sharedcreds.EntraCreds{}, errors.New("appcreds: entra_app provider missing client secret")
	}
	return sharedcreds.EntraCreds{TenantID: *p.TenantID, ClientID: p.ClientID, ClientSecret: secret}, nil
}

// certificateCreds extracts and decrypts the certificate credential for a
// provider. The bundle is opened under its own row-bound context, so a bundle
// copied from another provider's row does not decrypt here (#1041).
func (m *Minter) certificateCreds(p *scm.SCMProvider) (sharedcreds.CertificateCreds, error) {
	if p.TenantID == nil || *p.TenantID == "" {
		return sharedcreds.CertificateCreds{}, errors.New("appcreds: certificate entra_app provider missing tenant_id")
	}
	if p.ClientID == "" {
		return sharedcreds.CertificateCreds{}, errors.New("appcreds: certificate entra_app provider missing client_id")
	}
	if p.EncryptedEntraCertificate == nil || *p.EncryptedEntraCertificate == "" {
		return sharedcreds.CertificateCreds{}, errors.New("appcreds: certificate entra_app provider missing entra_certificate")
	}
	bundle, _, err := m.cipher.OpenWithContextOrLegacy(
		*p.EncryptedEntraCertificate, scm.ProviderEntraCertificateContext(p.ID.String()))
	if err != nil {
		return sharedcreds.CertificateCreds{}, fmt.Errorf("appcreds: decrypt certificate bundle: %w", err)
	}
	return sharedcreds.CertificateCreds{TenantID: *p.TenantID, ClientID: p.ClientID, CertificatePEM: bundle}, nil
}

// githubAppCreds extracts and decrypts the GitHub App credentials for a provider.
func (m *Minter) githubAppCreds(p *scm.SCMProvider) (sharedcreds.GitHubAppCreds, error) {
	if p.GitHubAppID == nil || *p.GitHubAppID == "" {
		return sharedcreds.GitHubAppCreds{}, errors.New("appcreds: github_app provider missing github_app_id")
	}
	if p.GitHubInstallationID == nil || *p.GitHubInstallationID == "" {
		return sharedcreds.GitHubAppCreds{}, errors.New("appcreds: github_app provider missing github_installation_id")
	}
	if p.EncryptedAppPrivateKey == nil || *p.EncryptedAppPrivateKey == "" {
		return sharedcreds.GitHubAppCreds{}, errors.New("appcreds: github_app provider missing private key")
	}
	pemStr, _, err := m.cipher.OpenWithContextOrLegacy(
		*p.EncryptedAppPrivateKey, scm.ProviderAppPrivateKeyContext(p.ID.String()))
	if err != nil {
		return sharedcreds.GitHubAppCreds{}, fmt.Errorf("appcreds: decrypt app private key: %w", err)
	}
	return sharedcreds.GitHubAppCreds{
		AppID: *p.GitHubAppID, InstallationID: *p.GitHubInstallationID, PrivateKeyPEM: pemStr,
	}, nil
}

// ValidCertificateBundle reports, as an error naming the problem, whether a
// certificate credential's PEM bundle parses. Re-exported for the same reason
// as ValidRSAPrivateKey: the admin handlers validate an upload through this
// package's name, and the check at upload is by construction the mint's.
var ValidCertificateBundle = sharedcreds.ValidCertificateBundle

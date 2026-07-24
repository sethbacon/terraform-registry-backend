// Package appcreds mints shared, admin-managed SCM app credentials: a single
// provider-level token used for every user's module linking and all background
// syncs, replacing the legacy per-user OAuth model for providers opted into an
// app auth mode.
//
// Two modes are supported, mirroring the terraform-state-manager drift plans:
//   - entra_app:  Microsoft Entra app registration (OAuth 2.0 client-credentials)
//     for Azure DevOps.
//   - github_app: a GitHub App (RS256 app JWT exchanged for an installation
//     access token) for GitHub.
//
// Minted tokens are cached in the scm_provider_tokens table (encrypted at rest)
// so process restarts and additional replicas don't re-mint on every request.
// The cache is re-mintable from the provider's stored app secrets, so losing it
// is never fatal.
package appcreds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// tokenRefreshMargin re-mints this long before a cached token's hard expiry so an
// in-flight request never races the expiry boundary.
const tokenRefreshMargin = 60 * time.Second

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

// Minter implements SharedMinter. It decrypts the provider's stored app secrets,
// mints a token from the appropriate identity provider, and caches it.
type Minter struct {
	cipher        *crypto.TokenCipher
	store         ProviderTokenStore
	httpClient    *http.Client
	now           func() time.Time
	refreshMargin time.Duration

	// Endpoint bases are fields (not consts) so tests can point them at an
	// httptest server. Defaults are the public production hosts.
	entraLoginBaseURL string
	githubAPIBaseURL  string
}

// NewMinter builds a Minter using the production identity-provider endpoints
// and the strict (no allow-list) egress policy. Equivalent to
// NewMinterWithGuard(cipher, store, nil).
func NewMinter(cipher *crypto.TokenCipher, store ProviderTokenStore) *Minter {
	return NewMinterWithGuard(cipher, store, nil)
}

// NewMinterWithGuard is NewMinter with an egress guard, for parity with the
// other SCM outbound paths (scm.HTTPClient): the token-exchange requests carry
// a credential (the RS256 app JWT or a client assertion), so they are routed
// through the shared httpsafe resolve-and-pin client rather than a bare
// http.Client, even though entraLoginBaseURL/githubAPIBaseURL are currently
// fixed to public hosts (issue #676).
func NewMinterWithGuard(cipher *crypto.TokenCipher, store ProviderTokenStore, egress *httpsafe.Guard) *Minter {
	return &Minter{
		cipher:            cipher,
		store:             store,
		httpClient:        httpsafe.NewClient(30*time.Second, egress),
		now:               time.Now,
		refreshMargin:     tokenRefreshMargin,
		entraLoginBaseURL: "https://login.microsoftonline.com",
		githubAPIBaseURL:  "https://api.github.com",
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
				if tok, derr := m.cipher.Open(rec.AccessTokenEncrypted); derr == nil && tok != "" {
					return &scm.OAuthToken{AccessToken: tok, TokenType: rec.TokenType, ExpiresAt: rec.ExpiresAt}, nil
				}
			}
		}
	}

	var (
		token     string
		expiresAt time.Time
		err       error
	)
	switch p.AuthMode {
	case scm.AuthModeEntraApp:
		var creds EntraCreds
		if creds, err = m.entraCreds(p); err == nil {
			token, expiresAt, err = m.mintEntraToken(ctx, creds)
		}
	case scm.AuthModeGitHubApp:
		var creds GitHubAppCreds
		if creds, err = m.githubAppCreds(p); err == nil {
			token, expiresAt, err = m.mintGitHubInstallationToken(ctx, creds)
		}
	default:
		return nil, fmt.Errorf("appcreds: provider %s is not in an app auth mode (auth_mode=%q)", p.ID, p.AuthMode)
	}
	if err != nil {
		return nil, err
	}

	// Best-effort cache write — a persistence failure must not fail the request.
	if m.store != nil {
		if enc, sealErr := m.cipher.Seal(token); sealErr == nil {
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
func (m *Minter) entraCreds(p *scm.SCMProvider) (EntraCreds, error) {
	if p.TenantID == nil || *p.TenantID == "" {
		return EntraCreds{}, errors.New("appcreds: entra_app provider missing tenant_id")
	}
	if p.ClientID == "" {
		return EntraCreds{}, errors.New("appcreds: entra_app provider missing client_id")
	}
	secret, err := m.cipher.Open(p.ClientSecretEncrypted)
	if err != nil {
		return EntraCreds{}, fmt.Errorf("appcreds: decrypt client secret: %w", err)
	}
	if secret == "" {
		return EntraCreds{}, errors.New("appcreds: entra_app provider missing client secret")
	}
	return EntraCreds{TenantID: *p.TenantID, ClientID: p.ClientID, ClientSecret: secret}, nil
}

// githubAppCreds extracts and decrypts the GitHub App credentials for a provider.
func (m *Minter) githubAppCreds(p *scm.SCMProvider) (GitHubAppCreds, error) {
	if p.GitHubAppID == nil || *p.GitHubAppID == "" {
		return GitHubAppCreds{}, errors.New("appcreds: github_app provider missing github_app_id")
	}
	if p.GitHubInstallationID == nil || *p.GitHubInstallationID == "" {
		return GitHubAppCreds{}, errors.New("appcreds: github_app provider missing github_installation_id")
	}
	if p.EncryptedAppPrivateKey == nil || *p.EncryptedAppPrivateKey == "" {
		return GitHubAppCreds{}, errors.New("appcreds: github_app provider missing private key")
	}
	pemStr, err := m.cipher.Open(*p.EncryptedAppPrivateKey)
	if err != nil {
		return GitHubAppCreds{}, fmt.Errorf("appcreds: decrypt app private key: %w", err)
	}
	return GitHubAppCreds{AppID: *p.GitHubAppID, InstallationID: *p.GitHubInstallationID, PrivateKeyPEM: pemStr}, nil
}

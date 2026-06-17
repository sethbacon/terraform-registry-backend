# Plan: Migrate Registry SCM Auth from Per-User OAuth to Shared App Credentials

> **Status:** Proposed
> **Repo:** `terraform-registry-backend` (+ `terraform-registry-frontend`)
> **Scope:** Replace the **per-user OAuth token** model for SCM module linking with
> a single **admin-created, org-shared app credential** per SCM provider — the same
> kind of app/service auth the TSM drift plans adopt (Entra app registration for
> Azure DevOps, GitHub App for GitHub). Removes the "every user must Connect"
> friction.

## 1. Motivation

Today the registry stores **one OAuth token per (user, provider)** in
`scm_oauth_tokens` and resolves the token for a repo sync from the **module
creator**:

```go
// internal/services/scm_publisher.go (verified)
if module.CreatedBy != nil {
    tokenRecord, _ := p.scmRepo.GetUserToken(ctx, createdByUUID, repo.SCMProviderID)
    accessToken, _ := p.tokenCipher.Open(tokenRecord.AccessTokenEncrypted)
    oauthToken = &scm.OAuthToken{ AccessToken: accessToken, ... }
}
```

Consequences we want to remove:

- Each user must run the OAuth **authorize → callback** dance before they can link.
- A module's syncs **depend on the creator's** personal token; if that user's token
  expires/revokes or they leave, publishing breaks.
- GitHub OAuth tokens **don't refresh** at all here
  (`RenewToken` returns `ErrTokenRefreshFailed`).

**Target:** an admin registers one app credential per provider; **all users** linking
modules and **all** background syncs use that shared, app-owned credential.

## 2. Goals / Non-goals

### Goals

- One **admin-managed** credential per SCM provider, shared across users for module
  linking + webhook-driven publish.
- App/service auth matching TSM: **Entra app registration** (Azure DevOps),
  **GitHub App** (GitHub). GitLab/Bitbucket: see §8.
- Sync no longer keyed on `module.CreatedBy`.
- Keep the existing `scm.Connector` package and `TokenCipher`; minimize churn.

### Non-goals

- Per-user authorization for *write-on-behalf-of-user* features (none rely on it for
  publishing today). Audit any UI that shows "connected as a specific user".
- Removing the OAuth code paths immediately — keep them during a deprecation window
  (§9), then delete.

## 3. Current-state anchors (verified)

- Schema [`000001_initial_schema.up.sql`](../backend/internal/db/migrations/000001_initial_schema.up.sql):
  - `scm_providers(client_id, client_secret_encrypted, tenant_id, base_url, ...)`
  - `scm_oauth_tokens(user_id, scm_provider_id, access_token_encrypted,
    refresh_token_encrypted, token_type, expires_at, UNIQUE(user_id, scm_provider_id))`
  - `module_scm_repos(module_id, scm_provider_id, repository_owner, repository_name, ...)`
- OAuth endpoints + token storage:
  [`internal/api/admin/scm_oauth.go`](../backend/internal/api/admin/scm_oauth.go)
  (`InitiateOAuth`, `HandleOAuthCallback`, `RefreshToken`, token status, revoke,
  `SavePATToken`).
- Connector interface + Entra `.default`/`offline_access`:
  [`internal/scm/connector.go`](../backend/internal/scm/connector.go),
  [`internal/scm/azuredevops/connector.go`](../backend/internal/scm/azuredevops/connector.go).
- Token consumption: `GetUserToken(...)` in
  [`internal/services/scm_publisher.go`](../backend/internal/services/scm_publisher.go).
- Crypto: `TokenCipher.Seal/Open` (AES-256-GCM, key rotation) in
  [`internal/crypto/tokencipher.go`](../backend/internal/crypto/tokencipher.go).
- Next migration number: **`000041`**.

## 4. Design

### 4.1 New credential model — provider-level, not per-user

Add a single shared credential per provider, minted on demand (no user binding):

```sql
-- migration 000041_scm_shared_app_credentials

-- How a provider authenticates for shared, headless access.
ALTER TABLE scm_providers ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'oauth_user'
    CHECK (auth_mode IN ('oauth_user', 'entra_app', 'github_app'));

-- GitHub App fields (auth_mode = 'github_app').
ALTER TABLE scm_providers ADD COLUMN github_app_id TEXT;
ALTER TABLE scm_providers ADD COLUMN github_installation_id TEXT;
ALTER TABLE scm_providers ADD COLUMN encrypted_app_private_key TEXT; -- base64 GCM

-- Entra app-registration uses existing client_id + tenant_id +
-- client_secret_encrypted (already on scm_providers) with a client-credentials
-- grant. No new columns needed for Entra beyond auth_mode.

-- Cached shared token (optional persistence so restarts don't re-mint immediately).
CREATE TABLE scm_provider_tokens (
    scm_provider_id        UUID PRIMARY KEY REFERENCES scm_providers(id) ON DELETE CASCADE,
    access_token_encrypted TEXT NOT NULL,
    token_type             VARCHAR(50) NOT NULL DEFAULT 'Bearer',
    expires_at             TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT NOW()
);
```

`auth_mode='oauth_user'` preserves today's behaviour during migration.
`entra_app` / `github_app` are the shared app modes.

### 4.2 Shared token minter

Add a provider-level minter alongside the connector:

```go
// internal/scm/appcreds/minter.go (new)
type SharedMinter interface {
    // MintProviderToken returns a usable token for a provider, refreshing if needed.
    MintProviderToken(ctx context.Context, p *scm.SCMProvider) (*scm.OAuthToken, error)
}
```

- `entra_app`: client-credentials POST to
  `login.microsoftonline.com/{tenant}/oauth2/v2.0/token`,
  `scope=499b84ac-.../.default` (reuse the constant already in the ADO connector).
- `github_app`: app-JWT (RS256 from `encrypted_app_private_key`) →
  `POST /app/installations/{id}/access_tokens`.
- Cache in `scm_provider_tokens` (encrypted via `TokenCipher`) with a refresh margin;
  re-mint on expiry. Re-mintable from stored secrets, so cache loss is non-fatal.

> The minter mirrors the two TSM minters (Entra client-credentials, GitHub App). The
> registry and TSM implementations stay independent (no shared module), but the
> request shaping should be kept identical for review parity.

### 4.3 Token resolution change (the core migration)

`scm_publisher.go` stops using `module.CreatedBy`/`GetUserToken`:

```go
// before: per-user, keyed on module creator
// tokenRecord, _ := p.scmRepo.GetUserToken(ctx, createdByUUID, repo.SCMProviderID)

// after: one shared credential per provider
provider, _ := p.scmRepo.GetProvider(ctx, repo.SCMProviderID)
switch provider.AuthMode {
case "entra_app", "github_app":
    oauthToken, _ = p.sharedMinter.MintProviderToken(ctx, provider)
case "oauth_user":
    // legacy fallback during deprecation window (existing code path)
}
```

Every other consumer of `GetUserToken` for **linking/sync** is repointed the same
way. Interactive repo-browsing endpoints (list repos/branches/tags in the link
wizard) also switch to the shared token, which is the whole point — users no longer
need a personal token to browse.

### 4.4 Admin API + endpoints

- Extend the provider create/update admin handlers
  ([`internal/api/admin/`](../backend/internal/api/admin/)) to accept
  `auth_mode` and the app fields (Entra: existing client/tenant/secret;
  GitHub App: app id, installation id, private key PEM). Encrypt secrets via
  `TokenCipher`.
- Add `POST /api/v1/scm-providers/{id}/verify` — mint a shared token and hit a cheap
  API (`GET /_apis/projects` for ADO, `GET /installation/repositories` for GitHub) →
  `{ ok, expires_at }`. Admin-gated.
- **Deprecate** the per-user endpoints (`/oauth/authorize`, `/oauth/callback`,
  `/oauth/refresh`, `/oauth/token`) — keep functioning while `auth_mode='oauth_user'`
  exists, mark deprecated in swagger, remove in the cleanup phase (§9).
- RBAC: shared-credential management stays **admin-only** (same gating as provider
  CRUD today).

### 4.5 Frontend (`terraform-registry-frontend`)

- `SCMProvidersPage.tsx`: provider form gains an **Auth mode** selector
  (App credential | Per-user OAuth [deprecated]). For app modes, render the relevant
  fields + "Test connection". Remove the per-user **Connect/Refresh/Disconnect**
  affordances for app-mode providers (they become a single org-level status row).
- `api.ts`/`types/scm.ts`: add `auth_mode` + app fields; add `verifySCMProvider`.
- Link-module wizard: drop any "you must connect your account first" gate when the
  provider is in app mode — browsing/listing uses the shared credential.

## 5. Data migration & backfill

- The migration is **additive**; existing providers default to `auth_mode='oauth_user'`
  and keep working unchanged.
- No automatic conversion of existing OAuth tokens (they're user-delegated and can't
  become app creds). An admin **opts a provider into** app mode by entering app
  credentials; on save, the provider flips to `entra_app`/`github_app` and subsequent
  syncs use the shared token.
- Existing `scm_oauth_tokens` rows are left in place until the cleanup phase, then
  dropped with the table.

## 6. Security

- Shared secrets (Entra client secret, GitHub App private key) encrypted at rest via
  `TokenCipher` (existing key-rotation supported); never returned in JSON (expose
  only `has_*` booleans).
- The shared token is **powerful** (acts for the whole org). Document least-privilege
  app permissions (ADO: Code Read; GitHub App: Contents R, Metadata R, plus webhook
  perms only if the registry manages webhooks).
- Audit-log credential create/update/verify and every sync that uses the shared token
  (record `provider_id`, not a user).
- Threat note: moving from per-user to shared widens blast radius of one credential —
  mitigate with least privilege + rotation + admin-only management.

## 7. Testing

- **Unit:** shared minter (Entra client-credentials + GitHub App JWT), cache
  hit/miss/expiry, error mapping. `httptest` + throwaway RSA key.
- **Unit:** `scm_publisher` resolves the shared token by `auth_mode` and **no longer**
  calls `GetUserToken` in app mode; `oauth_user` legacy path still works.
- **Unit:** admin create/update validates app fields; secrets never echoed; `/verify`.
- **Migration:** up adds columns/table + default `oauth_user`; existing providers
  unaffected; down is safe only with no app-mode rows (fail loudly otherwise).
- **Frontend:** auth-mode form gating; removal of per-user Connect in app mode; verify
  call; link wizard no longer blocks on personal connection.
- `make test` (Go) + `npx vitest run` for touched FE; ensure `gosec` baseline updated
  if JWT signing trips a rule.

## 8. GitLab / Bitbucket

- **GitLab:** supports OAuth refresh and also **group/project access tokens** and
  **CI job tokens**; the closest "shared app" analog is a bot/group access token
  stored as a shared provider credential (`auth_mode` could gain `shared_token`).
  Out of scope for the first cut — keep GitLab on `oauth_user` until a follow-up.
- **Bitbucket DC:** already PAT-based (`SavePATToken`). A shared PAT stored at the
  provider level is a trivial extension (`auth_mode='shared_token'`); fold into the
  follow-up.
- First delivery targets **Azure DevOps (Entra app)** and **GitHub (GitHub App)** —
  matching the TSM plans — and leaves GitLab/Bitbucket on the existing path.

## 9. Rollout & deprecation

1. Ship migration `000041` + shared minter + admin API (additive; default
   `oauth_user`). Per-user OAuth still fully works.
2. Ship FE auth-mode selector + verify.
3. Pilot: flip one provider to app mode; confirm linking + webhook publish use the
   shared credential and no per-user Connect is required.
4. Announce deprecation of per-user OAuth for publishing.
5. **Cleanup phase (separate PR, after a validation window):** repoint any remaining
   consumers, drop per-user OAuth endpoints + `scm_oauth_tokens` table + the
   `oauth_user` branch.

## 10. Effort / sequencing

1. Migration `000041` (columns + `scm_provider_tokens`).
2. Shared minter (Entra + GitHub App) + cache (unit-tested standalone).
3. Repoint `scm_publisher` + interactive browse endpoints off `GetUserToken`.
4. Admin create/update/verify + JSON exposure.
5. Frontend auth-mode UI + wizard de-gate.
6. Deprecate per-user endpoints (swagger + UI).
7. Tests + runbook.
8. **Later:** cleanup PR removing OAuth-user code + table.

Steps 1–4 are backend-only and independently reviewable; the user-facing behaviour
change lands with step 5.

# SCM Shared App Credentials (Entra App / GitHub App)

> Configure a single, admin-managed app credential per SCM provider so that **all**
> module linking and **all** background syncs use a shared, app-owned identity —
> removing the per-user "Connect your account" requirement.

## Overview

By default the registry authenticates to an SCM provider with **per-user OAuth**:
each user runs an authorize → callback flow and stores a personal token, and a
module's webhook-driven publishes use the **module creator's** token. If that user
leaves or their token is revoked, publishing breaks.

An SCM provider can instead be put into an **app auth mode**, where the registry
mints a shared token on demand from an admin-configured app credential:

| `auth_mode`   | Provider type | Credential                                   |
| ------------- | ------------- | -------------------------------------------- |
| `oauth_user`  | all           | Per-user OAuth (default, legacy)             |
| `entra_app`   | `azuredevops` | Microsoft Entra app registration (client-credentials) |
| `github_app`  | `github`      | GitHub App (installation token)              |

Switching is **opt-in and additive**: existing providers stay on `oauth_user` and
keep working until an admin supplies app credentials. GitLab and Bitbucket Data
Center remain on the existing model.

Minted tokens are cached (encrypted) in `scm_provider_tokens` and re-minted shortly
before expiry. Secrets (the Entra client secret and the GitHub App private key) are
encrypted at rest with the registry `TokenCipher` and are **never** returned by the
API — responses expose only `has_client_secret` / `has_app_private_key` booleans.

---

## Azure DevOps — Microsoft Entra app registration (`entra_app`)

### 1. Create the app registration

1. In the Microsoft Entra admin center, **App registrations → New registration**.
   Single-tenant is sufficient. No redirect URI is required (client-credentials).
2. Record the **Application (client) ID** and **Directory (tenant) ID**.
3. **Certificates & secrets → New client secret**. Record the secret **value**.
4. Grant the app access to your Azure DevOps organization:
   - In Azure DevOps: **Organization settings → Users → Add users**, add the app's
     service principal, and give it **least-privilege** access — **Code (Read)** is
     enough to clone module sources; add webhook-management scope only if the
     registry manages repository webhooks for you.

### 2. Configure the provider

Create (or update) the SCM provider with `auth_mode=entra_app`:

```http
POST /api/v1/scm-providers
{
  "provider_type": "azuredevops",
  "name": "ado-shared",
  "auth_mode": "entra_app",
  "tenant_id": "<directory-tenant-id>",
  "client_id": "<application-client-id>",
  "client_secret": "<client-secret-value>",
  "base_url": "https://dev.azure.com/<org>"
}
```

### 3. Verify

```http
POST /api/v1/scm-providers/{id}/verify   →   { "ok": true, "expires_at": "..." }
```

Verification performs a real client-credentials token request against
`login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with scope
`499b84ac-1321-427f-aa17-267ca6975798/.default`. A non-2xx response means the
tenant/client/secret are wrong or the secret has expired.

---

## GitHub — GitHub App (`github_app`)

### 1. Create the GitHub App

1. **Settings → Developer settings → GitHub Apps → New GitHub App** (org-owned
   recommended).
2. Repository **permissions** (least privilege):
   - **Contents: Read-only** (clone module sources / read tags).
   - **Metadata: Read-only** (mandatory).
   - **Webhooks: Read & write** only if the registry should manage repo webhooks.
3. **Generate a private key** and download the `.pem` (PKCS#1 or PKCS#8 both work).
4. **Install** the App on the org/repositories that host your modules. From the
   installation URL (`.../installations/<id>`) record the **Installation ID**.
5. Record the numeric **App ID** from the App's settings page.

### 2. Configure the provider

```http
POST /api/v1/scm-providers
{
  "provider_type": "github",
  "name": "github-shared",
  "auth_mode": "github_app",
  "github_app_id": "<app-id>",
  "github_installation_id": "<installation-id>",
  "app_private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}
```

`client_id` / `client_secret` are not used for GitHub App auth and may be omitted.

### 3. Verify

```http
POST /api/v1/scm-providers/{id}/verify   →   { "ok": true, "expires_at": "..." }
```

Verification signs a short-lived app JWT (RS256) and exchanges it for an
installation access token at
`POST /app/installations/{installation_id}/access_tokens`. A failure means the App
ID, Installation ID, or private key is wrong, or the App is not installed.

---

## Operational notes

- **Rotation:** issue a new Entra client secret / GitHub App private key, `PUT` it
  onto the provider, then `POST .../verify`. Updating a provider drops the cached
  shared token so the next request re-mints with the new credential.
- **Blast radius:** a shared credential acts for the whole organization. Keep it
  least-privilege, rotate regularly, and restrict provider management to admins
  (`scm:manage`).
- **Auditing:** credential create/update/verify and every sync that uses the shared
  token are attributable to the provider (not a user).
- **Rollback:** convert a provider back to `auth_mode=oauth_user` to restore the
  per-user flow. The down migration refuses to run while any provider is still in an
  app auth mode (it would destroy the only copy of those credentials) — convert such
  providers first.

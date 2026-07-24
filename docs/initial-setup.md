<!-- markdownlint-disable MD013 -->
# Initial Setup Guide

This document covers the first-run setup wizard for the Terraform Registry. The setup wizard allows you to configure OIDC authentication, storage backend, and the initial admin user through a secure, one-time process.

## Table of Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Setup Token](#setup-token)
4. [Using the Web Wizard](#using-the-web-wizard)
5. [Using the API (Headless)](#using-the-api-headless)
6. [Configuration Steps](#configuration-steps)
7. [Security Model](#security-model)
8. [Troubleshooting](#troubleshooting)

---

## Overview

When the Terraform Registry starts for the first time, it generates a **one-time setup token** and prints it to the server logs. This token is used to authenticate with the setup wizard endpoints, which allow you to configure:

1. **OIDC Provider** — Your identity provider for user authentication
2. **Storage Backend** — Where Terraform modules and providers are stored
3. **Admin User** — The first user with full administrative access

After setup completes, the setup token is invalidated and these endpoints are permanently disabled. All subsequent configuration changes are made through the authenticated admin interface.

This approach follows the same pattern used by ArgoCD, Rancher, and other infrastructure tools.

## How It Works

```txt
┌─────────────────────────────────────────────────────────┐
│                    Server Startup                       │
│                                                         │
│  1. Run database migrations                             │
│  2. Check if setup is already completed                 │
│  3. If not: generate setup token → print to logs        │
│  4. Start HTTP server with setup endpoints enabled      │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│                    Setup Phase                          │
│                                                         │
│  ▸ Operator copies token from logs                      │
│  ▸ Uses web wizard OR curl to configure:                │
│     • OIDC provider (issuer, client ID/secret, etc.)    │
│     • Storage backend (local, S3, Azure, GCS)           │
│     • Admin user email                                  │
│  ▸ Calls /api/v1/setup/complete to finalize             │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│                   Normal Operation                      │
│                                                         │
│  ▸ Setup token is invalidated (hash cleared from DB)    │
│  ▸ Setup endpoints return 403 permanently               │
│  ▸ OIDC login is available                              │
│  ▸ Admin user logs in and inherits admin role           │
└─────────────────────────────────────────────────────────┘
```

## Setup Token

### Generation

On first startup, the server generates a 32-byte cryptographically random token with the prefix `tfr_setup_`. The token is:

- Printed to stdout in a clearly framed box
- Optionally written to a file if `SETUP_TOKEN_FILE` environment variable is set
- Stored in the database as a bcrypt hash (cost 12) — the plaintext is never stored

### Token Format

```txt
tfr_setup_<base64url-encoded-random-bytes>
```

Example:

```txt
╔══════════════════════════════════════════════════════════════════╗
║                     INITIAL SETUP TOKEN                          ║
║                                                                  ║
║  tfr_setup_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEF            ║
║                                                                  ║
║  Use this token to complete initial setup via:                   ║
║    • Web UI: https://your-registry/setup                         ║
║    • API:    Authorization: SetupToken <token>                   ║
║                                                                  ║
║  This token will not be shown again.                             ║
╚══════════════════════════════════════════════════════════════════╝
```

### Environment Variables

| Variable | Description |
| -- | -- |
| `SETUP_TOKEN_FILE` | Path to write the setup token for automated retrieval (e.g., `/run/secrets/setup-token`) |
| `ENCRYPTION_KEY` | **Required.** 32-byte key for encrypting sensitive data (OIDC client secrets, storage credentials). The server refuses to start if this looks human-typed rather than CSPRNG-generated; see `TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY` below. |
| `TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY` | Set to `true` to temporarily bypass the low-entropy `ENCRYPTION_KEY` startup check while rotating an existing deployment to a stronger, CSPRNG-generated key (e.g. `openssl rand -hex 16`). Off by default; the server fails closed instead of only warning. |
| `TFR_ALLOW_FEATURE_SETUP_REARM` | Set to `true` to allow the server to mint a new setup token, scoped only to an optional feature left unconfigured after initial setup (currently: security scanning). Off by default; OIDC/LDAP/storage/admin setup remain permanently disabled regardless of this flag. See [Reconfiguring a pending optional feature](#reconfiguring-a-pending-optional-feature) below. |

### Token File for Automation

For automated deployments (CI/CD, Kubernetes init containers, etc.), set `SETUP_TOKEN_FILE` to have the token written to a file:

```bash
export SETUP_TOKEN_FILE=/tmp/setup-token.txt
./terraform-registry-server
# Token is now in /tmp/setup-token.txt
```

### Reconfiguring a pending optional feature

Once initial setup completes, OIDC/LDAP/storage/admin bootstrapping are permanently disabled — there is no setup-token path back into them. Optional features added in a later release (currently: security scanning) can still show up as "pending" if left unconfigured, but the server no longer auto-mints a setup token for that case. If the startup log reports an unconfigured feature, set `TFR_ALLOW_FEATURE_SETUP_REARM=true` and restart once to mint a token scoped only to that feature's own setup routes (e.g. `/api/v1/setup/scanning`), then unset the variable again. All other setup routes remain disabled even while this flag is set.

## Using the Web Wizard

1. Navigate to `https://your-registry/setup`
2. Enter the setup token from the server logs
3. Follow the 6-step wizard:
   - **Step 1: Authenticate** — Paste the setup token
   - **Step 2: OIDC Provider** — Configure your identity provider
   - **Step 3: Storage Backend** — Configure module/provider storage
   - **Step 4: Security Scanning** *(optional)* — Enable module scanning and auto-install a supported scanner (Trivy, Terrascan, or Checkov). The **Install** button downloads the official release, verifies the SHA256 checksum, and places the binary in the scanner directory. See [Module Security Scanning](module-scanning.md) for details.
   - **Step 5: Admin User** — Set the initial admin email
   - **Step 6: Complete** — Review and finalize

## Using the API (Headless)

All setup steps can be performed via HTTP API calls with `curl` or any HTTP client. Use the `Authorization: SetupToken <token>` header for all requests.

### 1. Validate Token

```bash
curl -X POST https://your-registry/api/v1/setup/validate-token \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN"
```

### 2. Check Setup Status (public, no auth required)

```bash
curl https://your-registry/api/v1/setup/status
```

Response:

```json
{
  "setup_completed": false,
  "storage_configured": false,
  "oidc_configured": false,
  "ldap_configured": false,
  "auth_method": "",
  "admin_configured": false,
  "setup_required": true
}
```

`auth_method` reports the configured authentication method (`oidc` or `ldap`)
once one is saved; `ldap_configured` mirrors `oidc_configured` for the LDAP path.

### 3. Test OIDC Configuration

```bash
curl -X POST https://your-registry/api/v1/setup/oidc/test \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_type": "generic_oidc",
    "issuer_url": "https://accounts.google.com",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_url": "https://your-registry/api/v1/auth/callback",
    "scopes": ["openid", "email", "profile"]
  }'
```

### 4. Save OIDC Configuration

```bash
curl -X POST https://your-registry/api/v1/setup/oidc \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_type": "generic_oidc",
    "issuer_url": "https://accounts.google.com",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_url": "https://your-registry/api/v1/auth/callback",
    "scopes": ["openid", "email", "profile"]
  }'
```

### 4b. Configure LDAP (alternative to OIDC)

LDAP is a first-class authentication option equal to OIDC — configure **either**
OIDC (steps 3–4) **or** LDAP, not both. Test the connection first, then save:

```bash
# Test the LDAP connection / bind
curl -X POST https://your-registry/api/v1/setup/ldap/test \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "ldap.example.com",
    "port": 636,
    "use_tls": true,
    "bind_dn": "cn=registry,ou=svc,dc=example,dc=com",
    "bind_password": "YOUR_BIND_PASSWORD",
    "base_dn": "ou=users,dc=example,dc=com",
    "user_filter": "(uid=%s)",
    "user_attr_email": "mail",
    "user_attr_name": "cn",
    "group_base_dn": "ou=groups,dc=example,dc=com",
    "group_filter": "(member=%s)",
    "group_member_attr": "member"
  }'

# Save the LDAP configuration
curl -X POST https://your-registry/api/v1/setup/ldap \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "ldap.example.com",
    "port": 636,
    "use_tls": true,
    "bind_dn": "cn=registry,ou=svc,dc=example,dc=com",
    "bind_password": "YOUR_BIND_PASSWORD",
    "base_dn": "ou=users,dc=example,dc=com",
    "user_filter": "(uid=%s)"
  }'
```

Required fields: `host`, `bind_dn`, `bind_password`, `base_dn`, `user_filter`.
Use `use_tls: true` for LDAPS (port 636) or `start_tls: true` for StartTLS on the
plain port. The group fields enable group-to-role mapping. After saving, the
setup-status response reports `auth_method: "ldap"` and `ldap_configured: true`.

### 5. Test Storage Configuration

```bash
curl -X POST https://your-registry/api/v1/setup/storage/test \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "backend_type": "s3",
    "s3_region": "us-east-1",
    "s3_bucket": "my-terraform-registry",
    "s3_auth_method": "access_key",
    "s3_access_key_id": "AKIA...",
    "s3_secret_access_key": "..."
  }'
```

### 6. Save Storage Configuration

```bash
curl -X POST https://your-registry/api/v1/setup/storage \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "backend_type": "s3",
    "s3_region": "us-east-1",
    "s3_bucket": "my-terraform-registry",
    "s3_auth_method": "access_key",
    "s3_access_key_id": "AKIA...",
    "s3_secret_access_key": "..."
  }'
```

### 7. Configure Admin User

```bash
curl -X POST https://your-registry/api/v1/setup/admin \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com"}'
```

### 8. Complete Setup

```bash
curl -X POST https://your-registry/api/v1/setup/complete \
  -H "Authorization: SetupToken tfr_setup_YOUR_TOKEN"
```

Response on success:

```json
{
  "message": "Setup completed successfully. You can now log in via OIDC.",
  "setup_completed": true
}
```

## Configuration Steps

### OIDC Provider

| Field | Required | Description |
| ----- | -------- | ----------- |
| `provider_type` | Yes | `generic_oidc` or `azuread` |
| `issuer_url` | Yes | Your OIDC issuer URL |
| `client_id` | Yes | OAuth client ID |
| `client_secret` | Yes | OAuth client secret (encrypted at rest) |
| `redirect_url` | Yes | OAuth callback URL (`https://your-registry/api/v1/auth/callback`) |
| `scopes` | No | OIDC scopes (default: `openid email profile`) |
| `name` | No | Display name for this configuration (default: `default`) |

The client secret is encrypted using AES-256-GCM before being stored in the database. It is never exposed in API responses.

### Storage Backend

Supported backend types: `local`, `azure` (Blob Storage), `s3` (AWS/MinIO), `gcs` (Google Cloud).

See the [Configuration Guide](configuration.md) for detailed field descriptions for each backend type.

### Admin User

The admin email must match the email claim in your OIDC provider. When this user logs in via OIDC for the first time:

1. The system matches the OIDC email to the pre-provisioned user record
2. Links the OIDC identity (`sub` claim) to the user
3. The user inherits the admin role template and default organization membership

## Security Model

### Authentication

- Setup endpoints use a dedicated `Authorization: SetupToken <token>` scheme, completely separate from JWT bearer tokens and API keys
- The setup token is verified against a bcrypt hash stored in the database
- Rate limiting (5 requests per minute per IP) prevents brute-force attacks on the token

### Encryption

- OIDC client secrets are encrypted using AES-256-GCM (via the `ENCRYPTION_KEY` environment variable)
- Storage credentials are encrypted using the same mechanism
- Encrypted values are stored as base64url-encoded ciphertext in the database

### Lifecycle

- The setup token is generated once at first startup
- If the server restarts before setup completes, the existing token hash in the database is preserved and a message directs the operator to check the original logs
- After setup completes:
  - `setup_completed` is set to `true` in the database
  - `setup_token_hash` is set to `NULL`
  - All setup endpoints return `403 Forbidden` permanently
  - The setup token can never be used again, even if someone obtains it later

### Existing Deployments

For registries that were already deployed and configured before the setup wizard was added:

- The database migration automatically sets `setup_completed = true` when `storage_configured = true`
- No setup token is generated
- The setup wizard is not shown
- All existing configuration continues to work unchanged

## Troubleshooting

### "Setup already completed" error

The setup wizard can only be used once. After completion, all configuration must be done through the authenticated admin interface. If you need to reconfigure OIDC, use the standard OIDC configuration in `config.yaml` or redeploy with a fresh database. This applies even if the server logs report a pending optional feature (e.g. scanning) — see [Reconfiguring a pending optional feature](#reconfiguring-a-pending-optional-feature); OIDC/LDAP/storage/admin stay disabled regardless.

### "Invalid setup token" error

- Ensure you're copying the complete token including the `tfr_setup_` prefix
- Check that there are no extra spaces or line breaks
- The token is case-sensitive
- If the server restarted, the original token from the first startup is still valid

### "Rate limit exceeded" error

The setup endpoints are rate-limited to 5 requests per minute per IP. Wait 60 seconds and try again.

### OIDC discovery failed

- Verify the issuer URL is correct and accessible from the server
- Check that the `.well-known/openid-configuration` endpoint responds
- If using a self-signed certificate, ensure the server trusts it
- Test the URL manually: `curl https://your-issuer/.well-known/openid-configuration`

### Token file not created

- Check that `SETUP_TOKEN_FILE` is set before the server starts
- Verify the directory exists and is writable
- The file is only created during the first startup when setup is not yet completed

### TLS Warning

If the server detects that TLS is not enabled, it will print a warning. In production, always use TLS to protect the setup token in transit. Consider using a reverse proxy (nginx, Caddy, Traefik) for TLS termination.

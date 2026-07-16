<!-- markdownlint-disable MD013 -->
# Configuration Reference

This document covers all configuration options for the Enterprise Terraform Registry backend. Configuration is loaded from a YAML file (`config.yaml` by default) with environment variable overrides using the `TFR_` prefix.

**Precedence:** environment variables override YAML values, which override built-in defaults.
This means the same binary runs with a YAML file in local development and with pure environment
variables in containerized deployments — no recompilation needed.

## Quick Start

```bash
# Copy the example config
cp backend/config.example.yaml backend/config.yaml

# Edit config.yaml for your environment, then start the server
go run cmd/server/main.go serve
```

Environment variable format: `TFR_<SECTION>_<FIELD>` (uppercase, underscores replace dots).
For example, `database.host` in YAML becomes `TFR_DATABASE_HOST` as an env var.

---

## Quick Reference

| Variable                                             | Type     | Default                 | Required   | Description                                                                  |
| ---------------------------------------------------- | -------- | ----------------------- | ---------- | ---------------------------------------------------------------------------- |
| `TFR_DATABASE_HOST`                                  | string   | `localhost`             | Yes        | PostgreSQL host                                                              |
| `TFR_DATABASE_PORT`                                  | int      | `5432`                  | No         | PostgreSQL port                                                              |
| `TFR_DATABASE_NAME`                                  | string   | `terraform_registry`    | Yes        | Database name                                                                |
| `TFR_DATABASE_USER`                                  | string   | `registry`              | Yes        | Database user                                                                |
| `TFR_DATABASE_PASSWORD`                              | string   | —                       | Yes        | Database password                                                            |
| `TFR_DATABASE_SSL_MODE`                              | string   | `require`               | No         | `disable`, `prefer`, `require`, `verify-ca`, `verify-full`                   |
| `TFR_DATABASE_MAX_CONNECTIONS`                       | int      | `25`                    | No         | Connection pool size                                                         |
| `TFR_SERVER_HOST`                                    | string   | `0.0.0.0`               | No         | Bind address                                                                 |
| `TFR_SERVER_PORT`                                    | int      | `8080`                  | No         | HTTP listen port                                                             |
| `TFR_SERVER_BASE_URL`                                | string   | `http://localhost:8080` | Yes        | Public URL (used in redirect and download URLs)                              |
| `TFR_SERVER_READ_TIMEOUT`                            | duration | `30s`                   | No         | HTTP read timeout                                                            |
| `TFR_SERVER_WRITE_TIMEOUT`                           | duration | `30s`                   | No         | HTTP write timeout                                                           |
| `TFR_SERVER_TRUSTED_PROXIES`                         | list     | `[]`                    | No         | Trusted reverse-proxy CIDRs for `X-Forwarded-For` (empty = none)             |
| `TFR_STORAGE_DEFAULT_BACKEND`                        | string   | `local`                 | No         | `local`, `azure`, `s3`, `gcs`                                                |
| `TFR_JWT_SECRET`                                     | string   | —                       | Yes (prod) | JWT signing secret, min 32 chars                                             |
| `ENCRYPTION_KEY`                                     | string   | —                       | Yes        | 32-byte key for SCM OAuth token encryption                                   |
| `TFR_AUTH_API_KEYS_ENABLED`                          | bool     | `true`                  | No         | Enable API key authentication                                                |
| `TFR_AUTH_OIDC_ENABLED`                              | bool     | `false`                 | No         | Enable generic OIDC                                                          |
| `TFR_AUTH_AZURE_AD_ENABLED`                          | bool     | `false`                 | No         | Enable Azure AD / Entra ID                                                   |
| `TFR_MULTI_TENANCY_ENABLED`                          | bool     | `false`                 | No         | Enable multi-organization mode                                               |
| `TFR_IDENTITY_MIGRATIONS_ENABLED`                    | bool     | `false`                 | No         | Run the shared identity-schema migrations ([guide](identity-schema.md))      |
| `TFR_IDENTITY_SCHEMA_ENABLED`                        | bool     | `false`                 | No         | Route identity at the shared `identity` schema ([guide](identity-schema.md)) |
| `TFR_IDENTITY_SCHEMA_NAME`                           | string   | `identity`              | No         | Identity schema name                                                         |
| `TFR_LOGGING_LEVEL`                                  | string   | `info`                  | No         | `debug`, `info`, `warn`, `error`                                             |
| `TFR_LOGGING_FORMAT`                                 | string   | `json`                  | No         | `json`, `text`                                                               |
| `TFR_TELEMETRY_ENABLED`                              | bool     | `true`                  | No         | Enable telemetry subsystem                                                   |
| `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT`              | int      | `9090`                  | No         | Prometheus metrics port                                                      |
| `TFR_REDIS_HOST`                                     | string   | —                       | No         | Redis host (enables HA rate limiting and OIDC sessions)                      |
| `TFR_REDIS_PORT`                                     | int      | `6379`                  | No         | Redis port                                                                   |
| `TFR_REDIS_PASSWORD`                                 | string   | —                       | No         | Redis password                                                               |
| `TFR_REDIS_DB`                                       | int      | `0`                     | No         | Redis database number                                                        |
| `TFR_REDIS_TLS`                                      | bool     | `false`                 | No         | Enable TLS for Redis connection                                              |
| `TFR_REDIS_POOL_SIZE`                                | int      | `10`                    | No         | Redis connection pool size                                                   |
| `TFR_REDIS_DIAL_TIMEOUT`                             | duration | `5s`                    | No         | Redis connection timeout                                                     |
| `TFR_JWT_SECRET_FILE`                                | string   | —                       | No         | Path to file containing JWT secret (enables hot-reload)                      |
| `ENCRYPTION_KEY_PREVIOUS`                            | string   | —                       | No         | Previous encryption key for zero-downtime rotation                           |
| `TFR_SECURITY_RATE_LIMITING_ORG_REQUESTS_PER_MINUTE` | int      | `0`                     | No         | Per-org aggregate rate limit (0 = disabled)                                  |
| `TFR_SECURITY_RATE_LIMITING_ORG_BURST`               | int      | `0`                     | No         | Per-org burst allowance                                                      |
| `TFR_SCANNING_ENABLED`                               | bool     | `false`                 | No         | Enable module security scanning                                              |
| `TFR_SCANNING_TOOL`                                  | string   | `trivy`                 | No         | Scanner backend (`trivy`, `checkov`, `terrascan`, `snyk`, `custom`)          |
| `TFR_AUDIT_RETENTION_RETENTION_DAYS`                 | int      | `90`                    | No         | Delete audit logs older than N days (0 = keep forever)                       |
| `TFR_AUDIT_RETENTION_CLEANUP_BATCH_SIZE`             | int      | `1000`                  | No         | Rows per cleanup batch                                                       |
| `TFR_WEBHOOKS_MAX_RETRIES`                           | int      | `3`                     | No         | Webhook delivery retry attempts (0 = no retries)                             |
| `TFR_WEBHOOKS_RETRY_INTERVAL_MINS`                   | int      | `2`                     | No         | Minutes between webhook retries                                              |
| `TFR_NOTIFICATIONS_ENABLED`                          | bool     | `false`                 | No         | Enable outbound email notifications                                          |

> **Secrets are environment-only.** `TFR_JWT_SECRET`, `TFR_JWT_SECRET_FILE`,
> `ENCRYPTION_KEY`, and `ENCRYPTION_KEY_PREVIOUS` are **not** part of the Viper config —
> they have no YAML/struct field and are read directly via `os.Getenv` at startup. The
> `TFR_<SECTION>_<FIELD>` ↔ YAML-key mapping rule above does **not** apply to them, and they
> cannot be set in `config.yaml`. (`ENCRYPTION_KEY` intentionally has no `TFR_` prefix.)

---

## Redis (Optional)

Redis enables high-availability features that require shared state across multiple backend
pods: distributed rate limiting (GCRA algorithm) and OIDC session state. When `redis.host`
is not set, the backend falls back to in-memory stores which work correctly for single-instance
deployments but cause issues behind a load balancer.

```yaml
redis:
  host: redis.example.com     # leave empty to use in-memory fallback
  port: 6379
  password: ${REDIS_PASSWORD}  # omit or leave blank if Redis has no auth
  db: 0
  tls: false                   # set true if Redis requires TLS (e.g., Azure Cache for Redis)
  pool_size: 10                # connection pool size per backend instance
  dial_timeout: 5s             # timeout for new connections
```

| Variable                 | Type     | Default | Description                                                                                    |
| ------------------------ | -------- | ------- | ---------------------------------------------------------------------------------------------- |
| `TFR_REDIS_HOST`         | string   | —       | Redis server hostname or IP. When empty, HA features use in-memory fallback.                   |
| `TFR_REDIS_PORT`         | int      | `6379`  | Redis server port.                                                                             |
| `TFR_REDIS_PASSWORD`     | string   | —       | Redis AUTH password. Leave blank for unauthenticated connections.                              |
| `TFR_REDIS_DB`           | int      | `0`     | Redis database number (0-15).                                                                  |
| `TFR_REDIS_TLS`          | bool     | `false` | Enable TLS. Required for Azure Cache for Redis and AWS ElastiCache with in-transit encryption. |
| `TFR_REDIS_POOL_SIZE`    | int      | `10`    | Maximum number of connections per backend instance.                                            |
| `TFR_REDIS_DIAL_TIMEOUT` | duration | `5s`    | Timeout for establishing new connections.                                                      |

### Redis in Kubernetes

For Kubernetes deployments, you can use:

- **Azure Cache for Redis**: Set `tls: true`, use a Private Endpoint for network isolation.
- **AWS ElastiCache**: Set `tls: true` if in-transit encryption is enabled.
- **Bitnami Redis Helm Chart**: Deploy Redis alongside the registry in the same namespace.

The backend gracefully falls back to in-memory stores if Redis becomes unreachable at startup.
If Redis becomes unreachable after startup, rate limiting and OIDC operations will return
errors until the connection recovers.

---

## Database

PostgreSQL 14 or later is required. PostgreSQL 16 is recommended and is the
version used in the bundled Docker Compose stack and in CI.

```yaml
database:
  host: localhost
  port: 5432
  name: terraform_registry
  user: registry
  password: ${DATABASE_PASSWORD}   # use env var; never commit credentials
  ssl_mode: require                # require is the default; use prefer for local development
  max_connections: 25              # tune based on your PostgreSQL max_connections setting
```

### SSL Mode Options

| Value         | Description                                                                                   |
| ------------- | --------------------------------------------------------------------------------------------- |
| `disable`     | No TLS. Use only in isolated internal networks.                                               |
| `prefer`      | Use TLS if available, fall back to plain. Suitable for development.                           |
| `require`     | Require TLS but do not verify the server certificate.                                         |
| `verify-ca`   | Require TLS and verify the certificate is signed by a trusted CA.                             |
| `verify-full` | Require TLS, verify certificate, and verify the hostname matches. Recommended for production. |

### Connection Pool

`max_connections` controls the size of the connection pool. Set it to roughly `PostgreSQL max_connections / number_of_backend_instances`, leaving headroom for migrations and admin connections. A value of 25 per instance is a safe starting point.

`min_idle_connections` (env `TFR_DATABASE_MIN_IDLE_CONNECTIONS`, default `5`) sets the minimum number of idle connections kept warm in the pool, so the first requests after an idle period do not pay the connection-establishment cost.

---

## Server

```yaml
server:
  host: 0.0.0.0         # bind to all interfaces; use 127.0.0.1 to restrict to localhost
  port: 8080
  base_url: https://registry.example.com   # IMPORTANT: must be the public URL
  public_url: ""        # optional; OAuth-facing URL when it differs from base_url
  default_language: en  # default UI locale (see allowed list below)
  read_timeout: 30s
  write_timeout: 30s
  trusted_proxies: []   # CIDRs/IPs of reverse proxies allowed to set X-Forwarded-For
```

### Why `base_url` Matters

`base_url` is injected into URLs that are returned to the Terraform CLI — specifically
module download redirect targets and provider download URLs. If this is set incorrectly,
`terraform init` will follow broken redirects and fail. Always set this to the public
hostname that Terraform clients will reach (e.g., the load balancer or ingress URL).

### `public_url` vs `base_url` (OAuth Redirects)

**`TFR_SERVER_PUBLIC_URL`** is the externally-reachable URL used for OAuth
callbacks/redirects (via `GetPublicURL()`). It is **optional**: when unset, it falls back
to `base_url`. It only matters in reverse-proxied deployments where the internal listen
address (`base_url`) differs from the URL registered with the OAuth provider as the
redirect URI. If you hit an OIDC redirect-URI-mismatch and `base_url` alone is not the URL
the IdP redirects back to, set `public_url` to the OAuth-registered URL.

### `default_language`

**`TFR_SERVER_DEFAULT_LANGUAGE`** (default `en`) sets the default UI locale. It is
validated at startup against a fixed list of 10 locales — **`en`, `es`, `fr`, `de`, `ja`,
`pt`, `nl`, `nb`, `zh`, `it`** — and an invalid value causes startup to fail.

### `trusted_proxies` and Client IP

**`TFR_SERVER_TRUSTED_PROXIES`** — Comma-separated CIDR ranges (or IPs) of the reverse
proxies/load balancers in front of the registry. The client IP — used for rate limiting,
the binary-mirror IP allowlist, setup-token throttling, and audit logging — is taken from
the `X-Forwarded-For` header **only** when the immediate connection comes from one of these
ranges.

The default is empty, which **trusts no proxy**: the client IP is the direct connection
address and forwarded headers are ignored. This is the secure default — it prevents a
client from spoofing `X-Forwarded-For` to bypass IP-based controls. **Reverse-proxied
deployments must set this** to their proxy CIDR(s) (e.g. `["10.0.0.0/8"]` or
`["127.0.0.1"]`); otherwise every request appears to originate from the proxy and per-IP
rate limiting collapses all clients into one bucket.

---

## Storage Backends

Configure which backend is active and supply credentials for it.

```yaml
storage:
  default_backend: local   # Options: local | azure | s3 | gcs
```

### Local Filesystem

Suitable for single-node deployments and development. Files are served directly
by the Go backend or stored at a path accessible to the process.

```yaml
storage:
  local:
    base_path: /var/lib/terraform-registry   # absolute path recommended in production
    serve_directly: true                     # serve files from Go instead of redirecting
```

**`TFR_STORAGE_LOCAL_BASE_PATH`** — Directory where modules and provider binaries are stored.
The backend process must have read/write access. Use an absolute path in production.

**`TFR_STORAGE_LOCAL_SERVE_DIRECTLY`** — When `true`, file contents are streamed through
the backend. When `false`, the backend generates a redirect URL (requires an external
file server). `true` is recommended unless you have a separate file server.

### Azure Blob Storage

```yaml
storage:
  azure:
    account_name: myaccount
    account_key: ${AZURE_STORAGE_KEY}   # primary or secondary access key
    container_name: terraform-registry  # must exist before use
    cdn_url: ""                         # optional: CDN endpoint for faster downloads
    sas_token_expiry: 15m               # how long download SAS tokens are valid
    access_tier: Hot                    # Hot | Cool | Cold | Archive
```

| Variable                             | Description                                                        |
| ------------------------------------ | ------------------------------------------------------------------ |
| `TFR_STORAGE_AZURE_ACCOUNT_NAME`     | Storage account name (visible in Azure Portal)                     |
| `TFR_STORAGE_AZURE_ACCOUNT_KEY`      | Primary or secondary access key                                    |
| `TFR_STORAGE_AZURE_CONTAINER_NAME`   | Blob container name. Must exist before first use.                  |
| `TFR_STORAGE_AZURE_CDN_URL`          | Optional CDN endpoint URL for high-performance downloads           |
| `TFR_STORAGE_AZURE_SAS_TOKEN_EXPIRY` | Duration for which download SAS URLs are valid (e.g., `15m`, `1h`) |

### AWS S3 / S3-Compatible

Supports AWS S3, MinIO, DigitalOcean Spaces, and any S3-compatible API.

```yaml
storage:
  s3:
    bucket: terraform-registry
    region: us-east-1
    endpoint: ""                    # leave blank for AWS; set for MinIO/DigitalOcean/etc.
    force_path_style: false         # set true for MinIO and other non-AWS services
    auth_method: default            # default | static | oidc | assume_role
    access_key_id: ""               # used only with auth_method: static
    secret_access_key: ""           # used only with auth_method: static
    role_arn: ""                    # used with auth_method: oidc or assume_role
    role_session_name: terraform-registry
    external_id: ""                 # optional, for assume_role cross-account trust
    web_identity_token_file: ""     # path to OIDC token file (Kubernetes ServiceAccount)
```

#### S3 Authentication Methods

Choose the authentication method that matches your deployment:

| Method        | When to Use                                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `default`     | **Recommended for AWS.** Uses the AWS credential chain: env vars → shared credentials file → EC2 instance profile → ECS task role → EKS IRSA. Zero-credential configuration for cloud deployments. |
| `static`      | Explicit access key and secret. Use only for local development against MinIO or for S3-compatible services that don't support IAM. Never use in production AWS deployments.                        |
| `oidc`        | Web Identity / OIDC token file (e.g., EKS Pod Identity, GitHub Actions OIDC). The registry assumes a role by exchanging an OIDC token. Keyless — no long-lived credentials.                        |
| `assume_role` | AssumeRole for cross-account access. The current identity (from the `default` chain) assumes a specified role ARN. Use `external_id` when required by the role's trust policy.                     |

**`TFR_STORAGE_S3_ENDPOINT`** — Only set for non-AWS services. For MinIO:
`http://minio:9000`. For DigitalOcean Spaces: `https://<region>.digitaloceanspaces.com`.

### Google Cloud Storage

```yaml
storage:
  gcs:
    bucket: terraform-registry
    project_id: my-gcp-project     # required only if creating a new bucket
    auth_method: default           # default | service_account | workload_identity
    credentials_file: ""           # path to service account JSON (service_account only)
    credentials_json: ""           # inline service account JSON (alternative to file)
    endpoint: ""                   # override for GCS emulators (fake-gcs-server, etc.)
```

#### GCS Authentication Methods

| Method              | When to Use                                                                                                                                                                                        |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `default`           | **Recommended for GCP.** Uses Application Default Credentials (ADC): env var `GOOGLE_APPLICATION_CREDENTIALS` → gcloud CLI credentials → GCE/GKE metadata server. Zero-config for GKE deployments. |
| `service_account`   | Service account key file or inline JSON. Use for non-GCP environments or when ADC is not available. Rotate keys regularly; prefer Workload Identity when on GKE.                                   |
| `workload_identity` | Keyless federation via GKE Workload Identity or GitHub Actions with GCP Workload Identity Federation. No long-lived credentials; the provider identity is verified by Google.                      |

---

## Authentication

At least one authentication method must be enabled. API keys are recommended for automation;
OIDC or Azure AD for human users with SSO.

```yaml
auth:
  api_keys:
    enabled: true
    prefix: "tfr_"   # visual identifier in logs and UIs; all generated keys start with this

  oidc:
    enabled: false
    issuer_url: https://accounts.google.com
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    redirect_url: https://registry.example.com/auth/callback
    scopes:
      - openid
      - email
      - profile
    require_verified_email: true   # reject logins whose IdP has not verified the email

  azure_ad:
    enabled: false
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
    redirect_url: https://registry.example.com/auth/azure/callback
```

> **Note:** Email-verification enforcement (`require_verified_email`) is currently
> implemented for the **generic OIDC provider only**. The dedicated `azure_ad`
> provider has no `require_verified_email` field — see [Email Verification and
> Account Linking](#email-verification-and-account-linking) below.

For detailed OIDC provider setup (Azure AD, Okta, Keycloak, Auth0, Google Workspace),
see [OIDC Configuration](OIDC_CONFIGURATION.md).

### Email Verification and Account Linking

The email address asserted by an identity provider is the anchor used to match and link
accounts, so the registry hardens it in two ways:

- **`TFR_AUTH_OIDC_REQUIRE_VERIFIED_EMAIL`** (default `true`) — for the generic OIDC
  provider, a login is rejected unless the ID token asserts `email_verified=true`. An ID
  token that explicitly sets `email_verified=false` is always rejected regardless of this
  flag. When the flag is `true` and the claim is **absent**, the login is also rejected.

  > **Scope note:** This enforcement applies to the **generic `oidc` provider only**. The
  > dedicated `azure_ad` provider does **not** have a `require_verified_email` field, so there
  > is no equivalent `TFR_AUTH_AZURE_AD_REQUIRE_VERIFIED_EMAIL` variable. If you need
  > email-verification enforcement for Entra ID, configure it through the generic `oidc`
  > provider (Entra ID is OIDC-compliant), and note that Entra v2.0 tokens frequently omit
  > `email_verified` — add it as an optional claim if your tenant does not emit it.

- **Cross-provider account-link guard (always on)** — the registry will not rebind an existing
  account to a different provider identity by email match. Email-based linking is allowed only
  for pre-provisioned accounts (no provider subject yet) or a repeat login with the same
  subject. A login asserting an email already bound to a *different* subject is rejected. This
  prevents an attacker who can assert a victim's email through a second provider from taking
  over the victim's account. A genuine subject change (e.g. an IdP re-import) requires an admin
  to clear the stored subject first.

### SAML 2.0

The registry also acts as a SAML 2.0 Service Provider. SAML config is a list of
structs (one or more IdPs), so it is set in `config.yaml`. The SP metadata and ACS
endpoints are registered under `/api/v1/auth/saml/`.

```yaml
auth:
  saml:
    enabled: false
    entity_id: https://registry.example.com/saml/metadata   # this SP's entity ID
    acs_url: https://registry.example.com/api/v1/auth/saml/acs
    cert_file: /etc/registry/saml-sp.crt   # SP signing cert
    key_file: /etc/registry/saml-sp.key    # SP signing key
    idps:
      - name: corp-idp
        metadata_url: https://idp.example.com/metadata   # or metadata_xml: "<inline XML>"
    # Group-to-role mapping (same model as OIDC)
    group_attribute_name: groups
    default_role: viewer
    group_mappings:
      - group: registry-admins
        organization: default
        role: admin
```

### LDAP / Active Directory

LDAP authentication exposes a direct login endpoint at **`POST /api/v1/auth/ldap/login`**.
A service account (`bind_dn`/`bind_password`) is used to search for users.

```yaml
auth:
  ldap:
    enabled: false
    host: ldap.example.com
    port: 636
    use_tls: true            # LDAPS on connect
    start_tls: false         # or StartTLS on a plain port
    insecure_skip_verify: false   # NOT recommended in production
    bind_dn: "CN=svc-registry,OU=Service Accounts,DC=example,DC=com"
    bind_password: ${LDAP_BIND_PASSWORD}
    base_dn: "OU=Users,DC=example,DC=com"
    user_filter: "(sAMAccountName=%s)"
    user_attr_email: mail
    user_attr_name: displayName
    # Group lookup + role mapping
    group_base_dn: "OU=Groups,DC=example,DC=com"
    group_filter: "(member=%s)"
    group_member_attr: member
    default_role: viewer
    group_mappings:
      - group_dn: "CN=Registry Admins,OU=Groups,DC=example,DC=com"
        organization: default
        role: admin
```

---

## Security

### JWT Secret

```bash
export TFR_JWT_SECRET=$(openssl rand -hex 32)
```

The JWT secret signs authentication tokens. In production:

- Minimum 32 characters. The server refuses to start without a sufficient secret when `DEV_MODE` is not set.
- Store in a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), not in environment files checked into source control.

#### File-Based Hot-Reload (Zero-Downtime Rotation)

Instead of setting `TFR_JWT_SECRET` as an environment variable, you can point the backend
at a file containing the secret:

```bash
export TFR_JWT_SECRET_FILE=/etc/secrets/jwt-secret
```

When the file is modified, the backend detects the change via `fsnotify` and atomically
swaps the signing key. New tokens are signed with the new key, while tokens signed with the
previous key remain valid for an overlap period (default: 5 minutes). This enables
zero-downtime secret rotation in Kubernetes by updating the backing Secret object.

See [Secrets Rotation Guide](secrets-rotation.md) for detailed procedures.

### Encryption Key

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 16)   # produces 32 hex characters = 32 bytes (required for AES-256)
```

The encryption key protects SCM OAuth tokens stored in the database (AES-256-GCM). It is separate
from the JWT secret because OAuth tokens have different sensitivity and lifetime characteristics.
If this key is lost, all SCM connections will need to be re-authorized -- the encrypted tokens
cannot be recovered.

> To avoid per-user OAuth entirely, a provider can use a shared, admin-managed app
> credential (Microsoft Entra app for Azure DevOps, GitHub App for GitHub). See
> [SCM Shared App Credentials](deployment/scm-shared-app-credentials.md).

#### Zero-Downtime Key Rotation

To rotate the encryption key without invalidating existing encrypted tokens, set the previous
key alongside the new one:

```bash
export ENCRYPTION_KEY=<new-key>
export ENCRYPTION_KEY_PREVIOUS=<old-key>
```

The backend encrypts new data with `ENCRYPTION_KEY` and decrypts using both keys (current
first, then previous as fallback). Once all tokens have been re-encrypted with the new key,
you can remove `ENCRYPTION_KEY_PREVIOUS`.

See [Secrets Rotation Guide](secrets-rotation.md) for the full step-by-step procedure.

### CORS

```yaml
security:
  cors:
    allowed_origins:
      - https://registry.example.com   # add your frontend origin
    allowed_methods: [GET, POST, PUT, DELETE, OPTIONS]
```

Restrict `allowed_origins` to your actual frontend URL(s) in production. The built-in
default is `[]` (no origins allowed — deny-by-default); browsers will be unable to read
cross-origin responses via `fetch`/XHR until you explicitly list your frontend origin(s).
(If `config.example.yaml` ships example origins, those are example values for local
development, not the built-in default.)

### Rate Limiting

```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_minute: 60   # per-IP limit for most endpoints
    burst: 10                  # allow short bursts above the per-minute limit
    org_requests_per_minute: 0 # per-organization aggregate limit (0 = disabled)
    org_burst: 0               # org-level burst allowance
```

Rate limiting applies per client IP (or per user/API key when authenticated). Increase
`requests_per_minute` if you have many Terraform agents running concurrently from the
same IP (e.g., behind a NAT gateway).

When Redis is configured (`redis.host` is set), rate limiting uses the GCRA (Generic Cell
Rate Algorithm) in Redis, which correctly enforces limits across all backend pods. Without
Redis, each pod maintains an independent in-memory token bucket -- clients can bypass limits
by rotating across pods.

#### Per-Organization Rate Limiting

When `org_requests_per_minute` is set to a value greater than 0 and multi-tenancy is enabled,
an additional aggregate rate limit is enforced per organization. Both the individual limit
and the organization limit must pass for a request to proceed.

This prevents a single organization from consuming all capacity on a shared registry, even
if each individual user stays within their personal limit.

| Variable                                             | Type | Default | Description                                   |
| ---------------------------------------------------- | ---- | ------- | --------------------------------------------- |
| `TFR_SECURITY_RATE_LIMITING_ENABLED`                 | bool | `true`  | Master toggle for rate limiting.              |
| `TFR_SECURITY_RATE_LIMITING_REQUESTS_PER_MINUTE`     | int  | `60`    | Per-client rate limit.                        |
| `TFR_SECURITY_RATE_LIMITING_BURST`                   | int  | `10`    | Burst allowance above per-minute limit.       |
| `TFR_SECURITY_RATE_LIMITING_ORG_REQUESTS_PER_MINUTE` | int  | `0`     | Per-organization aggregate limit. 0 disables. |
| `TFR_SECURITY_RATE_LIMITING_ORG_BURST`               | int  | `0`     | Organization-level burst allowance.           |

### TLS

TLS termination at the Go layer is supported but most deployments terminate TLS at the
load balancer or ingress controller instead (Nginx, Azure Application Gateway, AWS ALB).

```yaml
security:
  tls:
    enabled: false
    cert_file: /etc/certs/tls.crt
    key_file: /etc/certs/tls.key
```

---

## Multi-Tenancy

```yaml
multi_tenancy:
  enabled: false                    # false = single-tenant (one organization)
  default_organization: default     # slug of the default organization
  allow_public_signup: false        # whether unauthenticated users can create orgs
```

**Single-tenant mode** (`enabled: false`): All modules and providers belong to one
organization. Namespaces in Terraform addresses are not organization-isolated.
Suitable for teams that don't need separate permission boundaries.

**Multi-tenant mode** (`enabled: true`): Each organization has isolated modules,
providers, and member lists. Users must be added to an organization to access its resources.
Use this when hosting the registry for multiple independent teams or customers.

---

## Shared Identity Schema

**Optional and off by default.** The registry can serve its identity tables from a
dedicated, shared `identity` PostgreSQL schema (the `terraform-suite-identity` component)
so that it and the other suite apps share one identity store. By default the registry is
fully self-contained — identity lives in its own `public` schema and there is nothing
extra to deploy.

These are environment-only flags (not in `config.yaml`):

```bash
TFR_IDENTITY_MIGRATIONS_ENABLED=false   # create/update the shared identity schema
TFR_IDENTITY_SCHEMA_ENABLED=false       # route identity reads/writes there
TFR_IDENTITY_SCHEMA_NAME=identity       # schema name
```

> Enabling the cutover on a registry with existing module/provider data has a cross-schema
> foreign-key consideration. **Read [`identity-schema.md`](identity-schema.md)** for the
> full rollout, verification, rollback, and the known limitation before turning it on.

---

## Logging

```yaml
logging:
  level: info        # debug | info | warn | error
  format: json       # json (structured, for log aggregators) | text (human-readable)
  output: stdout     # stdout | /var/log/registry.log
```

Use `json` format in production so log aggregators (Splunk, Datadog, ELK) can parse
structured fields. Use `text` format locally for readability.

Set `TFR_LOGGING_LEVEL=debug` to see detailed request tracing, including authentication
decisions and storage backend calls. Avoid debug level in production — it logs
sensitive headers.

---

## Telemetry

```yaml
telemetry:
  enabled: true
  service_name: terraform-registry

  metrics:
    enabled: true
    prometheus_port: 9090   # Prometheus scrapes http://<host>:9090/metrics

  tracing:
    enabled: false
    jaeger_endpoint: http://jaeger:14268/api/traces

  profiling:
    enabled: false
    port: 6060   # Go pprof endpoint at http://<host>:6060/debug/pprof/
```

Prometheus metrics are exposed on a **separate port** from the main API (9090 vs 8080).
This allows the metrics endpoint to be accessible only within your network without
exposing it through the public ingress.

---

## API Docs Metadata

The Swagger/OpenAPI spec served at `/swagger.json` includes metadata that can be
customized without recompiling:

```yaml
api_docs:
  terms_of_service: https://registry.example.com/terms
  contact_name: Platform Engineering
  contact_email: platform@example.com
  license: Apache-2.0
```

These fields are injected at runtime into the spec served by the backend.

---

## Dev Mode

```bash
export DEV_MODE=true
```

Dev mode is gated by the bare `DEV_MODE` env var (`true` or `1`) only. Note `DEV_MODE` is
intentionally **un-prefixed** (no `TFR_` prefix), the same as `ENCRYPTION_KEY`.
`NODE_ENV` has no effect — this is a Go service, and checking a Node.js-ecosystem
convention here would risk silently enabling dev mode from a copied env file.

Dev mode enables:

- A bypass login endpoint (`POST /api/v1/dev/login`) that creates a session without OIDC
- Relaxed JWT secret validation (allows short secrets)
- Additional debug logging

**Never set `DEV_MODE=true` in production.** The dev login endpoint allows anyone
to authenticate as any user without credentials.

As a backstop against this being set by mistake in a production-like deployment, the
server refuses to start when `DEV_MODE` is enabled together with a production-level
`logging.level` (`warn` or `error`) — this repo's own production manifests
(`docker-compose.prod.yml`, the kubernetes `production` overlay) always set
`TFR_LOGGING_LEVEL=warn`, while every dev/test manifest defaults to `info` or sets
`debug`. There is no other environment/production flag in this codebase (no `TFR_ENV`), so
`logging.level` is the signal used. See `devModeProductionGuard` in `cmd/server/main.go`.

---

## Module Security Scanning

The registry can automatically scan every uploaded module version for IaC misconfigurations and vulnerabilities. Scanning is disabled by default and requires a supported scanner binary installed on the server.

For full installation instructions per scanner tool, see [Module Security Scanning](module-scanning.md).

```yaml
scanning:
  enabled: false          # set true to activate
  tool: trivy             # trivy | checkov | terrascan | snyk | custom
  binary_path: /usr/local/bin/trivy
  expected_version: ""    # optional version pin (supply-chain protection)
  severity_threshold: ""  # blank = record all; e.g. "CRITICAL,HIGH" to filter
  timeout: 5m
  worker_count: 2
  scan_interval_mins: 5
  install_dir: /app/scanners  # auto-install target directory
```

| Variable                          | Type     | Default                    | Description                                                                                                                                       |
| --------------------------------- | -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TFR_SCANNING_ENABLED`            | bool     | `false`                    | Master toggle for the scanning feature.                                                                                                           |
| `TFR_SCANNING_TOOL`               | string   | `trivy`                    | Scanner backend: `trivy`, `checkov`, `terrascan`, `snyk`, or `custom`.                                                                            |
| `TFR_SCANNING_BINARY_PATH`        | string   | —                          | Absolute path to the scanner binary on the server.                                                                                                |
| `TFR_SCANNING_EXPECTED_VERSION`   | string   | —                          | Exact version string the binary must report. The job refuses to start if it doesn't match. Leave blank to disable pinning.                        |
| `TFR_SCANNING_SEVERITY_THRESHOLD` | string   | `CRITICAL,HIGH,MEDIUM,LOW` | Comma-separated severities to record: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. The default lists all severities (record all); blank also records all. |
| `TFR_SCANNING_TIMEOUT`            | duration | `5m`                       | Maximum time a single scan may run.                                                                                                               |
| `TFR_SCANNING_WORKER_COUNT`       | int      | `2`                        | Concurrent scan workers.                                                                                                                          |
| `TFR_SCANNING_SCAN_INTERVAL_MINS` | int      | `5`                        | How often the job polls for pending scans.                                                                                                        |
| `TFR_SCANNING_INSTALL_DIR`        | string   | `/app/scanners`            | Directory where auto-installed scanner binaries are placed. Each version gets a subdirectory; a symlink points to the active version.             |
| `TFR_SCANNING_VERSION_ARGS`       | string[] | —                          | **`custom` tool only.** Arguments to print the binary version.                                                                                    |
| `TFR_SCANNING_SCAN_ARGS`          | string[] | —                          | **`custom` tool only.** Arguments passed before the target directory.                                                                             |
| `TFR_SCANNING_OUTPUT_FORMAT`      | string   | —                          | **`custom` tool only.** Output parser: `sarif` or `json`.                                                                                         |

The scanning feature can also be configured through the web-based setup wizard, which
stores the configuration encrypted in the database. DB-stored config takes precedence
over config file values and supports runtime changes without restart.

---

## Audit Log Shipping

Beyond the database trail, the backend can ship each audit entry to external
destinations (SIEM, log aggregator) or **federate** it to a sibling Terraform
State Manager so both apps share one unified Audit Log. Shippers are a structured
list, configured in `config.yaml` (environment variables cannot express a list of
structs):

```yaml
audit:
  enabled: true
  shippers:
    - enabled: true
      type: webhook   # webhook | syslog | file
      webhook:
        url: https://siem.example.com/ingest
        headers: { Authorization: "Bearer ${SIEM_TOKEN}" }
```

For the suite cross-app unified audit trail, see
[Suite Audit Federation](suite-audit-federation.md).

---

## Audit Log Retention

The backend can automatically delete audit log entries older than a configurable
threshold. This prevents unbounded table growth in long-running deployments. When
`retention_days` is `0` the cleanup job is disabled and logs are kept indefinitely.

```yaml
audit_retention:
  retention_days: 90        # delete entries older than 90 days; 0 = keep forever
  cleanup_batch_size: 1000  # rows deleted per batch to avoid long-running transactions
```

| Variable                                 | Type | Default | Description                                                                                          |
| ---------------------------------------- | ---- | ------- | ---------------------------------------------------------------------------------------------------- |
| `TFR_AUDIT_RETENTION_RETENTION_DAYS`     | int  | `90`    | Entries older than this many days are deleted. Set to `0` to disable cleanup.                        |
| `TFR_AUDIT_RETENTION_CLEANUP_BATCH_SIZE` | int  | `1000`  | Maximum rows deleted per cleanup iteration. Smaller values reduce lock contention on busy databases. |

The cleanup job runs periodically in the background and emits the
`terraform_registry_audit_logs_cleaned_total` Prometheus counter. See
[Observability Reference](observability.md) for monitoring details.

---

## Webhooks

Webhook delivery retries can be configured to automatically re-attempt failed
deliveries. When `max_retries` is `0`, failed webhook deliveries are not retried.

```yaml
webhooks:
  max_retries: 3            # number of retry attempts after initial failure
  retry_interval_mins: 2    # minutes between retry attempts
```

| Variable                           | Type | Default | Description                                                                                    |
| ---------------------------------- | ---- | ------- | ---------------------------------------------------------------------------------------------- |
| `TFR_WEBHOOKS_MAX_RETRIES`         | int  | `3`     | Maximum number of retry attempts for failed webhook deliveries. Set to `0` to disable retries. |
| `TFR_WEBHOOKS_RETRY_INTERVAL_MINS` | int  | `2`     | Interval in minutes between retry attempts.                                                    |

The retry processor emits the `terraform_registry_webhook_retries_total` Prometheus
counter with an `outcome` label (`success`, `failure`, `exhausted`). See
[Observability Reference](observability.md) for alerting recommendations.

---

## Release Signing Keys (auto-refresh)

The terraform binary mirror verifies upstream SHA256SUMS files against ASCII-armored
GPG keys for HashiCorp and OpenTofu. The repo ships embedded snapshots of those keys
as an offline fallback, but every snapshot has a self-sig expiration — when it
passes, every mirror sync fails GPG verification (see [#415][issue-415] for the
incident). To prevent that, a background job re-fetches each tool's public key
from its `.well-known/pgp-key.txt` endpoint on a schedule and caches it in the
database. The mirror sync prefers the cached key over the embedded snapshot.

New keys are accepted only if their parsed **primary fingerprint matches a
hardcoded allow-list** in `internal/jobs`. A compromised TLS path can never
substitute a different key — at worst it can serve a stale or denied response,
and we fall back to the embedded snapshot.

Rotating to a new fingerprint requires a reviewed code change to update the
allow-list. There is intentionally no DB or config knob for that.

[issue-415]: https://github.com/sethbacon/terraform-registry-backend/issues/415

```yaml
releases_gpg_keys:
  enabled: true                  # set false for air-gapped deployments
  refresh_interval_hours: 24
  expiry_warning_days: 60
  hashicorp_url: https://www.hashicorp.com/.well-known/pgp-key.txt
  opentofu_url:  https://opentofu.org/.well-known/pgp-key.txt
```

| Variable                                       | Type   | Default                                             | Description                                                                                                            |
| ---------------------------------------------- | ------ | --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `TFR_RELEASES_GPG_KEYS_ENABLED`                | bool   | `true`                                              | Master toggle. When `false`, the job never runs and mirror sync always uses the embedded snapshots.                    |
| `TFR_RELEASES_GPG_KEYS_REFRESH_INTERVAL_HOURS` | int    | `24`                                                | How often the job re-fetches each upstream key.                                                                        |
| `TFR_RELEASES_GPG_KEYS_EXPIRY_WARNING_DAYS`    | int    | `60`                                                | Warning threshold. When the effective key (cache or embedded) is within this many days of expiry, the job logs a warn. |
| `TFR_RELEASES_GPG_KEYS_HASHICORP_URL`          | string | `https://www.hashicorp.com/.well-known/pgp-key.txt` | Override the HashiCorp upstream URL (e.g. when proxying through an internal mirror).                                   |
| `TFR_RELEASES_GPG_KEYS_OPENTOFU_URL`           | string | `https://opentofu.org/.well-known/pgp-key.txt`      | Override the OpenTofu upstream URL.                                                                                    |

The job emits two Prometheus metrics:

- `terraform_registry_releases_key_refresh_total{tool, outcome}` (counter):
  outcomes are `success`, `fingerprint_mismatch`, `fetch_failed`,
  `parse_failed`, `db_failed`, `skipped_unchanged`. Any
  `fingerprint_mismatch` should page on-call — it indicates either an
  upstream key rotation we need to allow-list, or an attempted substitution.
- `terraform_registry_releases_key_expires_seconds{tool, source}` (gauge):
  seconds until the earliest signing-key expiry. `source` is `cache` or
  `embedded`. Alert when `min by (tool) (...)` drops below your refresh SLA.

See [Observability Reference](observability.md) for example PromQL alerts.

---

## Notifications

```yaml
notifications:
  enabled: false
  smtp:
    host: smtp.sendgrid.net
    port: 587
    username: ${SMTP_USERNAME}
    password: ${SMTP_PASSWORD}
    from: registry@example.com
    use_tls: true
  recipients: []
  events:
    api_key_expiring: true
    module_published: true
    approval_pending: true
    cve_detected: true
    scanner_update_available: true
  api_key_expiry_warning_days: 7
  api_key_expiry_check_interval_hours: 24
```

| Variable                                                | Type   | Default | Description                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------- | ------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TFR_NOTIFICATIONS_ENABLED`                             | bool   | `false` | Master toggle for outbound email notifications.                                                                                                                                                                                                                                                             |
| `TFR_NOTIFICATIONS_SMTP_HOST`                           | string | —       | SMTP server hostname.                                                                                                                                                                                                                                                                                       |
| `TFR_NOTIFICATIONS_SMTP_PORT`                           | int    | `587`   | SMTP server port (587 for STARTTLS, 465 for implicit TLS).                                                                                                                                                                                                                                                  |
| `TFR_NOTIFICATIONS_SMTP_USERNAME`                       | string | —       | SMTP authentication username. Leave this and the password blank to send through an unauthenticated relay.                                                                                                                                                                                                   |
| `TFR_NOTIFICATIONS_SMTP_PASSWORD`                       | string | —       | SMTP authentication password. Leave this and the username blank to send through an unauthenticated relay.                                                                                                                                                                                                   |
| `TFR_NOTIFICATIONS_SMTP_FROM`                           | string | —       | Sender address for notification emails.                                                                                                                                                                                                                                                                     |
| `TFR_NOTIFICATIONS_SMTP_USE_TLS`                        | bool   | `true`  | When true, uses STARTTLS (587) or implicit TLS (465). When false, the connection is deliberately kept plaintext and never opportunistically upgraded, even if the relay advertises STARTTLS — use this for a trusted internal relay whose STARTTLS support is broken or backed by an untrusted certificate. |
| `TFR_NOTIFICATIONS_EVENTS_API_KEY_EXPIRING`             | bool   | `true`  | Enables the per-user API key expiry warning email.                                                                                                                                                                                                                                                          |
| `TFR_NOTIFICATIONS_EVENTS_MODULE_PUBLISHED`             | bool   | `true`  | Enables the admin notification sent when a new module version is published.                                                                                                                                                                                                                                 |
| `TFR_NOTIFICATIONS_EVENTS_APPROVAL_PENDING`             | bool   | `true`  | Enables the admin notification sent when a mirror provider approval request or scanner version needs approval.                                                                                                                                                                                              |
| `TFR_NOTIFICATIONS_EVENTS_CVE_DETECTED`                 | bool   | `true`  | Enables the CVE poll job's advisory/digest emails.                                                                                                                                                                                                                                                          |
| `TFR_NOTIFICATIONS_EVENTS_SCANNER_UPDATE_AVAILABLE`     | bool   | `true`  | Enables the informational email sent when an auto-approved scanner update is discovered.                                                                                                                                                                                                                    |
| `TFR_NOTIFICATIONS_API_KEY_EXPIRY_WARNING_DAYS`         | int    | `7`     | Days before API key expiry to send the first warning email.                                                                                                                                                                                                                                                 |
| `TFR_NOTIFICATIONS_API_KEY_EXPIRY_CHECK_INTERVAL_HOURS` | int    | `24`    | How often the expiry check job runs (in hours).                                                                                                                                                                                                                                                             |

`notifications.recipients` (admin-editable via the Notifications settings page,
or `notifications.recipients` in YAML) is the general recipient list for the
`module_published`, `approval_pending`, `cve_detected`, and
`scanner_update_available` event types. It falls back to `cve.email_recipients`
when empty, for deployments that only ever configured the CVE recipient list.

> **Security note:** an unauthenticated relay (blank username/password) should only be
> pointed at a trusted, network-isolated internal mail server -- restrict network access
> to it (e.g. firewall/security-group rules) rather than relying on SMTP auth as the
> control. Prefer use_tls: true (STARTTLS) even without credentials so the connection,
> including notification content, is encrypted in transit.

---

## Storage Migration

The backend supports live migration between storage backends. When you change
`storage.default_backend`, new uploads go to the new backend while existing artifacts
remain in the old backend. The admin API provides migration endpoints to move existing
artifacts:

- `POST /api/v1/admin/storage/migrate` -- Start a background migration
- `GET /api/v1/admin/storage/migrate/status` -- Check migration progress

During migration, reads transparently fall back to the old backend for artifacts that
have not yet been copied. No downtime is required.

---

## Binary Mirror Access Control

Access control for the `/terraform/binaries` endpoint group (the binary-mirror
IP allowlist referenced by `trusted_proxies` above).

```yaml
binary_mirror:
  auth: none                # none | allowlist | mtls
  allowlist:                # CIDR ranges allowed when auth=allowlist
    - 10.0.0.0/8
```

| Mode        | Behaviour                                                                             |
| ----------- | ------------------------------------------------------------------------------------- |
| `none`      | No access control (default). Suitable for internal networks.                          |
| `allowlist` | Allow only clients whose IP falls within one of the configured CIDR blocks.           |
| `mtls`      | Require a verified TLS client certificate; the subject CN is logged (no scope check). |

When `auth=allowlist`, the client IP is resolved using the same `trusted_proxies` rules
described in the Server section.

---

## Policy Engine (OPA / Rego)

An optional OPA/Rego policy engine that can warn on or block actions. Disabled by
default (no-op; all actions allowed).

```yaml
policy:
  enabled: false
  mode: warn                          # warn (log and continue) | block (reject)
  bundle_url: ""                      # HTTP/HTTPS URL of the .tar.gz Rego bundle
  bundle_refresh_interval: 0          # seconds between background bundle re-fetches; 0 = no refresh
```

---

## CVE Polling (OSV.dev)

Scheduled vulnerability polling against OSV.dev for advisories affecting Terraform/OpenTofu
binaries, registered providers, and the configured scanner binary. Opt-in (disabled by
default).

```yaml
cve:
  enabled: false
  interval_hours: 24                  # how often the poll job runs
  osv_endpoint: https://api.osv.dev   # OSV.dev base URL
  email_recipients: []                # addresses notified on new advisories (requires notifications.enabled)
  poll_binaries: true
  poll_providers: true
  poll_scanner: true
```

---

## mTLS (Client-Certificate Auth)

Mutual TLS client authentication that maps a client certificate subject (CN or full DN)
to scopes. Configured under `security.mtls`. Subject mappings are a list of structs and so
must be set in `config.yaml` (env vars cannot express the list).

When `security.mtls.enabled` is true, the server loads `client_ca_file` into the TLS
listener's client CA pool and sets `ClientAuth = VerifyClientCertIfGiven`: a client
certificate is verified against this CA whenever one is presented, but presenting one is
not required — callers without a client cert fall through to the existing JWT/API-key/OIDC/
SAML/LDAP auth paths on the same listener.

**mTLS requires this process to terminate TLS itself (`security.tls.enabled: true`).** It
cannot work behind a TLS-terminating ingress or load balancer: client certificates are part
of the TLS handshake, so once TLS is terminated upstream this process never sees the
handshake and has nothing to verify. If your registry sits behind such an ingress, either
have the ingress terminate mTLS and forward a trusted identity header (not implemented
here), or terminate TLS at the registry itself.

```yaml
security:
  mtls:
    enabled: false
    client_ca_file: /etc/registry/client-ca.pem
    mappings:
      - subject: "CN=ci-runner"
        scopes: ["modules:read", "providers:read"]
```

---

## Per-Principal Rate-Limit Overrides

Custom rate limits for a specific user or API key, under
`security.rate_limiting.principal_overrides`. Keys are `user:<id>` or `apikey:<id>`. This
is a map of structs and so must be set in `config.yaml`.

```yaml
security:
  rate_limiting:
    principal_overrides:
      "user:00000000-0000-0000-0000-000000000001":
        requests_per_minute: 1000
        burst: 200
```

---

## Identity Database

Optionally points the identity schema at a separate or shared database. Any unset field
falls back to the main `database` config, so a fully unset `identity_database` uses the app
database (the standalone default). Set `TFR_IDENTITY_DATABASE_*` (same field names as
`TFR_DATABASE_*`) to share one identity store across the suite.

```yaml
identity_database:
  host: identity-db.example.com
  port: 5432
  name: identity
  user: registry
  password: ${IDENTITY_DB_PASSWORD}
```

---

## Suite Coupling

Optional runtime coupling to a sibling Suite app (Terraform State Manager). With
`sibling_url` empty (the default) the registry is fully standalone and nothing is polled.

| Variable                          | Type     | Default | Description                                                                                                                                                                                                                                                  |
| --------------------------------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `TFR_SUITE_SIBLING_URL`           | string   | —       | Sibling app URL (e.g. `https://tfstate.example.com`). Empty = standalone.                                                                                                                                                                                    |
| `TFR_SUITE_POLL_INTERVAL`         | duration | `60s`   | How often the sibling manifest is polled.                                                                                                                                                                                                                    |
| `TFR_SUITE_ROLE_SEED_OWNER`       | string   | `self`  | Which app seeds shared identity role templates: `self`, `registry`, or `tsm`. With a shared identity DB, exactly one app must own the seed.                                                                                                                  |
| `TFR_SUITE_IDENTITY_SHARED_STORE` | bool     | `false` | Operator assertion that this app uses the shared identity store + single IdP (advertised in the manifest).                                                                                                                                                   |
| `TFR_SUITE_SIBLING_TOKEN`         | string   | —       | Shared secret (`X-Suite-Service-Token`) for cross-app reads (the "Consumed by" panel). Set to the same value as the sibling's service token.                                                                                                                 |
| `TFR_SUITE_TRUSTED_ISSUERS`       | []string | `[]`    | Comma-separated additional JWT `iss` values this app accepts, on top of its own (`terraform-registry`). Only relevant when `TFR_JWT_SECRET` is shared with a sibling app — without an entry here, a sibling's tokens are rejected even with the same secret. |

**A shared `TFR_JWT_SECRET` alone does not grant cross-app trust.** JWT validation always
pins `iss` to this app's own issuer plus whatever `TFR_SUITE_TRUSTED_ISSUERS` lists — a
token minted by another app sharing the secret is rejected until its issuer is added here.

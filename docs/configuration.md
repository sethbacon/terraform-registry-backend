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

| Variable | Type | Default | Required | Description |
| --- | --- | --- | --- | --- |
| `TFR_DATABASE_HOST` | string | `localhost` | Yes | PostgreSQL host |
| `TFR_DATABASE_PORT` | int | `5432` | No | PostgreSQL port |
| `TFR_DATABASE_NAME` | string | `terraform_registry` | Yes | Database name |
| `TFR_DATABASE_USER` | string | `registry` | Yes | Database user |
| `TFR_DATABASE_PASSWORD` | string | — | Yes | Database password |
| `TFR_DATABASE_SSL_MODE` | string | `prefer` | No | `disable`, `require`, `verify-full` |
| `TFR_DATABASE_MAX_CONNECTIONS` | int | `25` | No | Connection pool size |
| `TFR_SERVER_HOST` | string | `0.0.0.0` | No | Bind address |
| `TFR_SERVER_PORT` | int | `8080` | No | HTTP listen port |
| `TFR_SERVER_BASE_URL` | string | `http://localhost:8080` | Yes | Public URL (used in redirect and download URLs) |
| `TFR_SERVER_READ_TIMEOUT` | duration | `30s` | No | HTTP read timeout |
| `TFR_SERVER_WRITE_TIMEOUT` | duration | `30s` | No | HTTP write timeout |
| `TFR_STORAGE_DEFAULT_BACKEND` | string | `local` | No | `local`, `azure`, `s3`, `gcs` |
| `TFR_JWT_SECRET` | string | — | Yes (prod) | JWT signing secret, min 32 chars |
| `ENCRYPTION_KEY` | string | — | Yes | 32-byte key for SCM OAuth token encryption |
| `TFR_AUTH_API_KEYS_ENABLED` | bool | `true` | No | Enable API key authentication |
| `TFR_AUTH_OIDC_ENABLED` | bool | `false` | No | Enable generic OIDC |
| `TFR_AUTH_AZURE_AD_ENABLED` | bool | `false` | No | Enable Azure AD / Entra ID |
| `TFR_MULTI_TENANCY_ENABLED` | bool | `false` | No | Enable multi-organization mode |
| `TFR_LOG_LEVEL` | string | `info` | No | `debug`, `info`, `warn`, `error` |
| `TFR_LOG_FORMAT` | string | `json` | No | `json`, `text` |
| `TFR_TELEMETRY_ENABLED` | bool | `true` | No | Enable telemetry subsystem |
| `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` | int | `9090` | No | Prometheus metrics port |

---

## Database

PostgreSQL 14 or later is required.

```yaml
database:
  host: localhost
  port: 5432
  name: terraform_registry
  user: registry
  password: ${DATABASE_PASSWORD}   # use env var; never commit credentials
  ssl_mode: prefer                 # prefer for local, require or verify-full in production
  max_connections: 25              # tune based on your PostgreSQL max_connections setting
```

### SSL Mode Options

| Value | Description |
| --- | --- |
| `disable` | No TLS. Use only in isolated internal networks. |
| `prefer` | Use TLS if available, fall back to plain. Suitable for development. |
| `require` | Require TLS but do not verify the server certificate. |
| `verify-ca` | Require TLS and verify the certificate is signed by a trusted CA. |
| `verify-full` | Require TLS, verify certificate, and verify the hostname matches. Recommended for production. |

### Connection Pool

`max_connections` controls the size of the connection pool. Set it to roughly `PostgreSQL max_connections / number_of_backend_instances`, leaving headroom for migrations and admin connections. A value of 25 per instance is a safe starting point.

---

## Server

```yaml
server:
  host: 0.0.0.0         # bind to all interfaces; use 127.0.0.1 to restrict to localhost
  port: 8080
  base_url: https://registry.example.com   # IMPORTANT: must be the public URL
  read_timeout: 30s
  write_timeout: 30s
```

### Why `base_url` Matters

`base_url` is injected into URLs that are returned to the Terraform CLI — specifically
module download redirect targets and provider download URLs. If this is set incorrectly,
`terraform init` will follow broken redirects and fail. Always set this to the public
hostname that Terraform clients will reach (e.g., the load balancer or ingress URL).

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

| Variable | Description |
| --- | --- |
| `TFR_STORAGE_AZURE_ACCOUNT_NAME` | Storage account name (visible in Azure Portal) |
| `TFR_STORAGE_AZURE_ACCOUNT_KEY` | Primary or secondary access key |
| `TFR_STORAGE_AZURE_CONTAINER_NAME` | Blob container name. Must exist before first use. |
| `TFR_STORAGE_AZURE_CDN_URL` | Optional CDN endpoint URL for high-performance downloads |
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

| Method | When to Use |
| --- | --- |
| `default` | **Recommended for AWS.** Uses the AWS credential chain: env vars → shared credentials file → EC2 instance profile → ECS task role → EKS IRSA. Zero-credential configuration for cloud deployments. |
| `static` | Explicit access key and secret. Use only for local development against MinIO or for S3-compatible services that don't support IAM. Never use in production AWS deployments. |
| `oidc` | Web Identity / OIDC token file (e.g., EKS Pod Identity, GitHub Actions OIDC). The registry assumes a role by exchanging an OIDC token. Keyless — no long-lived credentials. |
| `assume_role` | AssumeRole for cross-account access. The current identity (from the `default` chain) assumes a specified role ARN. Use `external_id` when required by the role's trust policy. |

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

| Method | When to Use |
| --- | --- |
| `default` | **Recommended for GCP.** Uses Application Default Credentials (ADC): env var `GOOGLE_APPLICATION_CREDENTIALS` → gcloud CLI credentials → GCE/GKE metadata server. Zero-config for GKE deployments. |
| `service_account` | Service account key file or inline JSON. Use for non-GCP environments or when ADC is not available. Rotate keys regularly; prefer Workload Identity when on GKE. |
| `workload_identity` | Keyless federation via GKE Workload Identity or GitHub Actions with GCP Workload Identity Federation. No long-lived credentials; the provider identity is verified by Google. |

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

  azure_ad:
    enabled: false
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
    redirect_url: https://registry.example.com/auth/azure/callback
```

For detailed OIDC provider setup (Azure AD, Okta, Keycloak, Auth0, Google Workspace),
see [OIDC Configuration](oidc_configuration.md).

---

## Security

### JWT Secret

```bash
export TFR_JWT_SECRET=$(openssl rand -hex 32)
```

The JWT secret signs authentication tokens. In production:

- Minimum 32 characters. The server refuses to start without a sufficient secret when `TFR_DEV_MODE` is not set.
- Rotate by replacing the secret and restarting. All existing sessions will be invalidated — users will need to log in again.
- Store in a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), not in environment files checked into source control.

### Encryption Key

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 16)   # generates 32 hex chars = 16 bytes; use hex 32 for 32 bytes
```

The encryption key protects SCM OAuth tokens stored in the database (AES-256). It is separate
from the JWT secret because OAuth tokens have different sensitivity and lifetime characteristics.
If this key is lost, all SCM connections will need to be re-authorized — the encrypted tokens
cannot be recovered.

### CORS

```yaml
security:
  cors:
    allowed_origins:
      - https://registry.example.com   # add your frontend origin
    allowed_methods: [GET, POST, PUT, DELETE, OPTIONS]
```

Restrict `allowed_origins` to your actual frontend URL(s) in production. The default
configuration includes `localhost` origins for development only.

### Rate Limiting

```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_minute: 60   # per-IP limit for most endpoints
    burst: 10                  # allow short bursts above the per-minute limit
```

Rate limiting applies per client IP. Increase `requests_per_minute` if you have
many Terraform agents running concurrently from the same IP (e.g., behind a NAT gateway).

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

## Logging

```yaml
logging:
  level: info        # debug | info | warn | error
  format: json       # json (structured, for log aggregators) | text (human-readable)
  output: stdout     # stdout | /var/log/registry.log
```

Use `json` format in production so log aggregators (Splunk, Datadog, ELK) can parse
structured fields. Use `text` format locally for readability.

Set `TFR_LOG_LEVEL=debug` to see detailed request tracing, including authentication
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
export TFR_DEV_MODE=true
```

Dev mode enables:

- A bypass login endpoint (`POST /auth/dev/login`) that creates a session without OIDC
- Relaxed JWT secret validation (allows short secrets)
- Additional debug logging

**Never set `TFR_DEV_MODE=true` in production.** The dev login endpoint allows anyone
to authenticate as any user without credentials.

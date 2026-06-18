<!-- markdownlint-disable MD013 -->
# Architecture

This document describes the design of the Enterprise Terraform Registry — what the components are, how they interact, and why key architectural decisions were made.

## Overview

The registry implements three HashiCorp Terraform protocols, plus a binary mirror facility:

- **Module Registry Protocol** — hosting, versioning, and downloading Terraform modules
- **Provider Registry Protocol** — hosting platform-specific provider binaries
- **Provider Network Mirror Protocol** — caching provider binaries from upstream registries
- **Terraform Binary Mirror** — multi-config mirror for Terraform and OpenTofu release binaries, served at `/terraform/binaries/:name/`

Beyond the Terraform protocols, the API package also exposes additional surfaces that have their own detailed docs: an **OCI** distribution endpoint group, **SCIM 2.0** user/group provisioning (gated by the dedicated `scim:provision` scope), and **security advisories** (CVE) endpoints. A security review scoping the full attack surface should account for these in addition to the protocol routes.

Design goals: protocol correctness first, then security, then operational simplicity. The system is stateless at the application layer (all state lives in PostgreSQL and the configured storage backend), which makes horizontal scaling straightforward.

---

## Repository Structure

The project is split across two repositories:

| Repository | Contents | Docker image |
| --- | --- | --- |
| [`terraform-registry-backend`](https://github.com/sethbacon/terraform-registry-backend) | Go backend, all deployment configs (Helm, K8s, Terraform IaC, cloud scripts) | `ghcr.io/sethbacon/terraform-registry-backend` |
| [`terraform-registry-frontend`](https://github.com/sethbacon/terraform-registry-frontend) | React SPA, nginx, E2E tests | `ghcr.io/sethbacon/terraform-registry-frontend` |

All deployment infrastructure lives in this (backend) repository. Frontend-only issues and the React source are tracked in `terraform-registry-frontend`.

---

## Component Diagram

```txt
┌─────────────────────────────────────────────────────────────┐
│                   Terraform CLI / terraform init            │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────┐
│            Ingress / Reverse Proxy (nginx / ALB / etc.)     │
│  Terminates TLS, routes /v1/* and /api/* to backend,        │
│  serves frontend static assets from /                       │
└──────────┬───────────────────────────────────┬──────────────┘
           │                                   │
           ▼                                   ▼
┌──────────────────────┐           ┌───────────────────────────┐
│   Go Backend (Gin)   │           │   React SPA (nginx CDN)   │
│   :8080              │           │   :80                     │
│                      │           │                           │
│  Protocol routes:    │           │  Pages:                   │
│  GET /v1/modules/*   │◄──────────│  /modules, /providers     │
│  GET /v1/providers/* │  REST API │  /admin/*, /login         │
│  GET /v1/mirror/*    │           │  /api-docs (ReDoc)        │
│  GET /terraform/     │           └───────────────────────────┘
│    binaries/:name/* │ ← Binary mirror downloads
│  Admin API:          │
│  /api/v1/admin/*     │
│  /api/v1/modules/*   │
│  /api/v1/providers/* │
│  /api-docs/          │ ← Backend-served Swagger UI
│  /swagger.json       │ ← Embedded OpenAPI spec
└──────────┬───────────┘
           │
     ┌─────┴────────────┐
     │                  │
     ▼                  ▼
┌──────────────┐  ┌──────────────────────┐
│  PostgreSQL  │  │   Storage Backend    │
│   (state)    │  │  Local / Azure /     │
└──────────────┘  │  S3 / GCS           │
                  └──────────────────────┘
```

---

## Backend Layer Architecture

Every HTTP request flows through a fixed middleware chain before reaching the handler:

```txt
Gin Router
  └─► Security Middleware     (security headers, CSP, CORS)
        └─► Rate Limit Middleware
              └─► Auth Middleware        (JWT or API key → user + scopes)
                    └─► RBAC Middleware  (required scope present?)
                          └─► Audit Middleware  (log mutating actions)
                                └─► Handler
                                      └─► Repository  (DB queries via sqlx)
                                            └─► Storage Backend (file I/O)
```

This ordering is intentional:

- **Security headers** are applied before any application logic so they appear on all responses, including error responses.
- **Rate limiting** runs before authentication to prevent credential-stuffing attacks from exhausting resources.
- **Authentication** populates the user identity and scopes on the Gin context. All subsequent middleware and handlers read from this context — they never re-authenticate.
- **RBAC** uses the scopes set by Auth. Running it after Auth (not inline in Auth) keeps the two concerns separate and allows endpoint-level scope requirements to be declared at route-registration time.
- **Audit logging** runs after RBAC so only successfully authorized mutations are logged as successful actions. Failed authorization attempts are still logged, but with a different outcome code.

Handlers follow the **repository pattern**: they call repository methods (in `internal/db/repositories/`) rather than constructing SQL directly. This keeps SQL in one place, makes it testable in isolation, and prevents accidental N+1 queries in handlers.

---

## Authentication Flow

The system supports several credential types: **JWT** (for browser sessions), **API keys** (for automation), and SSO login flows via **OIDC/Azure AD**, **SAML**, **LDAP**, and **mTLS** (client-certificate) providers.

Browser sessions do not use a `Bearer` header. After login the JWT is set as an **HttpOnly `tfr_auth_token` cookie** (inaccessible to page JavaScript), and the middleware tags such requests with `auth_method = jwt_cookie` so the **CSRF middleware** can require a `tfr_csrf` double-submit token on cookie-authenticated mutations. Programmatic clients send `Authorization: Bearer <token>` (JWT or API key) and bypass CSRF. The token-resolution order is: (1) `Authorization: Bearer` header — tried as JWT first, then API key; (2) `tfr_auth_token` cookie — tried as JWT only.

### Why JWT Is Tried First

JWT validation is stateless — it requires only a cryptographic check against the JWT secret. API key validation always requires a database round-trip (prefix lookup + bcrypt comparison). So JWT is attempted first as the lower-latency path:

```txt
Bearer token arrives
  │
  ├─► Try JWT validation (no DB needed)
  │     ├─► Valid → load user from DB, set context, continue
  │     └─► Invalid → fall through to API key path
  │
  └─► API key path
        ├─► Extract key prefix (first 10 chars)
        ├─► SELECT from api_keys WHERE prefix = ? (fast indexed lookup)
        ├─► bcrypt.CompareHashAndPassword(stored_hash, full_key)
        └─► Valid → load user, set context, continue
```

### API Key Design

API keys are never stored in plaintext. When a key is created:

1. A random 32-byte value is generated
2. The first 10 characters become the **prefix** (stored plaintext for fast lookup)
3. The full key is bcrypt-hashed and stored as `key_hash`
4. Only the raw key is shown to the user once at creation time

At authentication time, the prefix narrows the candidate set to a small number of rows before the expensive bcrypt comparison. Without the prefix, every authentication attempt would require a full-table scan with bcrypt on each row — catastrophically slow at scale.

The `UpdateLastUsed` call is made in a background goroutine (fire-and-forget) because last-used tracking is best-effort and intentionally non-blocking. Adding a synchronous DB write to every authenticated request would increase P99 latency across all endpoints.

---

## Role-Based Access Control (RBAC)

### Scope-Based, Not Role-Based

The RBAC system checks **scopes** (granular permission strings like `modules:write`) rather than role names (`admin`). This means:

- New permission granularities can be added without changing the role model
- A user's effective permissions are the union of their scopes
- Scopes are checked at request time, not embedded in the JWT

### Role Templates

Users are assigned **role templates** within organizations. A role template is a named set of scopes (e.g., "Publisher" = `modules:write`, `providers:write`). When a user's role template is updated, the change takes effect on the next request — there is no need to reissue JWTs or invalidate sessions. This is the key reason scopes are loaded from the database at request time rather than cached in the token.

### Scope Hierarchy

Key scopes and their write-implies-read relationship:

| Scope | Grants |
| --- | --- |
| `modules:read` | Read module metadata and download modules |
| `modules:write` | Upload and manage modules (implies `modules:read`) |
| `providers:read` | Read provider metadata and download providers |
| `providers:write` | Upload and manage providers (implies `providers:read`) |
| `mirrors:read` | View mirror configurations and sync history |
| `mirrors:manage` | Create/update/delete mirrors and trigger syncs (implies `mirrors:read`) |
| `admin:*` | Full administrative access (implies all scopes) |

### Shared identity module

The core identity primitives — JWT issuance/validation (the `TokenManager`), API
key generation/validation, and the generic scope-evaluation logic (wildcard
`admin` + write-implies-read) — are owned by the shared
`github.com/sethbacon/terraform-suite-identity` module. The files under
`internal/auth` (`jwt.go`, `apikey.go`, `scopes.go`) are thin shims that delegate
to that module, with the registry injecting its own registry-specific scope set
and read/write pairs. So when looking for the implementation of these primitives,
expect to find it in the shared suite-identity module rather than in this repo.

---

## Storage Abstraction

### Interface Design

All storage backends implement the `storage.Storage` interface:

```go
type Storage interface {
    Upload(ctx, path, reader, size) (*UploadResult, error)  // computes and returns the checksum
    Download(ctx, path) (io.ReadCloser, error)
    Delete(ctx, path) error
    GetURL(ctx, path, ttl) (string, error)  // returns a signed/presigned URL
    Exists(ctx, path) (bool, error)
    GetMetadata(ctx, path) (*FileMetadata, error)
}
```

`GetURL` is the key method: for cloud backends it returns a time-limited presigned/SAS URL so the client downloads directly from cloud storage without proxying through the registry. For local storage it returns the direct serving URL.

### Factory Registration

Backends register themselves via Go's `init()` mechanism:

```go
// In storage/s3/s3.go
func init() {
    factory.Register("s3", func(cfg *config.Config) (Storage, error) {
        return NewS3Backend(cfg)
    })
}
```

The router package (`internal/api/router.go`) imports each backend with a blank import (`_ "github.com/.../storage/s3"`), which triggers `init()`. Adding a new backend requires only implementing the interface and registering in `init()` — no changes to the factory or main package are needed.

---

## SCM Integration

### Immutable Publishing

SCM-linked module versions are pinned to a specific **commit SHA**, not a tag. Tags are mutable (they can be moved); commit SHAs are immutable. The workflow is:

1. User creates a Git tag (e.g., `v1.2.0`)
2. Webhook fires → registry resolves the tag to its current commit SHA immediately
3. Registry clones the repository at that exact commit SHA
4. Registry creates the version record with the commit SHA stored alongside the version
5. If the tag is later moved, the registry detects this as a tampering event (tag movement violation)

This prevents supply chain attacks where an attacker moves a tag to point at malicious code after a version has been reviewed and trusted.

### OAuth Token Storage

SCM OAuth tokens (GitHub, GitLab, Azure DevOps access tokens) are stored encrypted in the database using AES-256. A separate `ENCRYPTION_KEY` environment variable is used (distinct from `TFR_JWT_SECRET`) because OAuth tokens are long-lived and have different sensitivity than authentication tokens.

---

## Provider Mirroring Architecture

### Upstream Client

The `internal/mirror` package implements a client for upstream Terraform registries following the same Provider Registry Protocol that Terraform uses. It makes two categories of HTTP calls:

- **API calls** (service discovery, version enumeration): 30-second timeout. These should be fast; a long timeout here indicates a misconfigured upstream URL.
- **Binary downloads** (provider zip files, checksums, signatures): 10-minute timeout. Provider binaries can be hundreds of megabytes. A 30-second timeout would cause legitimate downloads to fail.

Two separate `http.Client` instances are used rather than sharing one with a configurable timeout because the timeout must differ by an order of magnitude between the two use cases.

### Sync Job

The background mirror sync job runs every 10 minutes. This interval was chosen as a balance between freshness (Terraform provider releases are not frequent) and upstream registry rate limits (registry.terraform.io has rate limiting on unauthenticated requests). Operator-triggered manual syncs are available for immediate updates.

Sync history is recorded in the `mirror_sync_history` table so operators can diagnose failures without inspecting logs.

### Version Approval Gate

When a mirror config has `requires_approval` enabled, each newly synced version
is recorded with `approval_status = pending_approval` and is hidden from the
protocol listing endpoints until an administrator approves it. Optional
auto-approve rules (`internal/mirror/auto_approve.go`) can approve low-risk
versions at sync time. See [version-approval.md](version-approval.md) and
[ADR 011](adr/011-version-approval-gate.md) for the full design.

---

## Background Jobs

| Job | Trigger | Purpose |
| --- | --- | --- |
| Mirror Sync (`mirror_sync.go`) | Periodic (configurable) | Poll upstream registries and download new provider versions |
| Terraform Binary Mirror Sync (`terraform_mirror_sync.go`) | Periodic (configurable) | Keep enabled Terraform/OpenTofu binary mirrors current from their upstreams |
| Tag Verifier (`tag_verifier.go`) | On webhook / periodic | Verify that SCM tags haven't moved since the version was published |
| Module Scanner (`module_scanner_job.go`) | Periodic (`scan_interval_mins`) | Process pending module security scans (see [ADR 008](adr/008-module-scanning-architecture.md)) |
| Webhook Retry (`webhook_retry_job.go`) | Periodic | Retry failed webhook deliveries with exponential backoff (see [ADR 005](adr/005-fire-and-forget-webhooks.md)) |
| API Key Expiry Notifier (`api_key_expiry_notifier.go`) | Periodic | Email owners of API keys approaching expiry (once per key) |
| CVE Poll (`cve_poll.go`) | Periodic | Query OSV.dev for advisories affecting binaries, providers, and the scanner |
| Audit Cleanup (`audit_cleanup_job.go`) | Periodic | Delete audit-log entries older than the configured retention period |
| Backup (`backup_job.go`) | Scheduled | Store encrypted `pg_dump` output in the configured object storage backend |
| Releases Key Refresh (`releases_key_refresh_job.go`) | Periodic | Re-fetch tool release-signing GPG keys with fingerprint pinning |

The list above is the full set of registered jobs (`internal/jobs/`). Jobs run in goroutines started at server startup. They use the same database connection pool as request handlers. Job panics are recovered and logged but do not crash the server.

---

## Database Design

### Key Decisions

**UUID primary keys** are used throughout (not sequential integers). This allows records to be created across distributed instances without coordination and avoids leaking record counts to external consumers.

**JSONB columns** are used for fields whose schema is flexible or evolving: `scopes` on API keys and role templates, `config` on storage configurations, and `protocols` on provider versions. JSONB allows these to evolve without schema migrations for each change.

**Migration-based schema**: all schema changes go through numbered migration files (`internal/db/migrations/`). The migration system runs on startup so deployments are self-applying. Never edit existing migration files — the migration runner tracks which files have been applied by their version number, and editing an applied file causes a "dirty" state error.

### Key Table Relationships

```txt
organizations
  ├── users (via organization_members)
  ├── modules
  │     └── module_versions
  │           └── scm linkage (module_scm_repos)
  ├── providers
  │     └── provider_versions
  │           └── provider_platforms
  └── api_keys

role_templates (system-level and org-level)
  └── organization_members.role_template_id
```

---

## Security Model

Defense-in-depth layers, from outer to inner:

1. **TLS** (at ingress) — encrypts all traffic
2. **Rate limiting** — prevents brute-force and enumeration attacks
3. **Input validation** — semver format, archive structure, path traversal prevention
4. **Authentication** — JWT (header or HttpOnly cookie), API key, or an SSO provider (OIDC/Azure AD/SAML/LDAP/mTLS) required for all non-protocol endpoints
5. **CSRF protection** — cookie-authenticated (browser) mutations require a `tfr_csrf` double-submit token
6. **RBAC** — scope checking before any state mutation
7. **Audit logging** — immutable record of all mutating actions
8. **Bcrypt for API keys** — keys stored as bcrypt hashes; compromise of the database does not expose working keys
9. **GPG verification** — all provider binaries are verified against the publisher's GPG public key
10. **SHA256 checksums** — file integrity checked on upload and download
11. **Commit SHA pinning** — SCM-linked versions are immutable by design

### Swagger UI and Content Security Policy

The Swagger UI is served from CDN (`cdnjs.cloudflare.com`) and uses inline `<script>` blocks that cannot be authorized via hash-based CSP (the hash would change with every CDN version update). A **nonce-based CSP** is used instead: the backend generates a fresh cryptographic nonce per request and includes it in both the `Content-Security-Policy` header and the inline `<script>` tag. This allows the CDN scripts to execute while preventing unauthorized script injection.

---

## Observability Architecture

The observability stack is intentionally isolated from the public API surface to prevent accidental exposure of internal metrics.

### Port Separation

The backend starts two additional `http.ServeMux` listeners beside the main Gin server:

| Port (default) | Surface | Config key |
| --- | --- | --- |
| `9090` | Prometheus `/metrics` (promhttp handler) | `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` |
| `6060` | pprof `/debug/pprof/` | `TFR_TELEMETRY_PROFILING_PORT` |

Neither port is exposed through the public Nginx/load-balancer ingress. They are internal-only and should be firewalled to the monitoring network (Prometheus scraper, ops bastion).

### Metrics Collection Points

Metrics are collected at three layers:

- **Middleware** (`MetricsMiddleware`, `LoggerMiddleware`) — HTTP request counts, latency histograms, and structured JSON logs are recorded for every request in the main Gin middleware chain.
- **Background jobs** (`MirrorSync`, `APIKeyExpiryNotifier`) — job-level counters (syncs attempted/succeeded/failed, keys expiring, notification errors) are incremented directly within the job implementations.
- **Database collector** (`DBStatsCollector`) — a Prometheus custom collector wraps `sql.DB.Stats()` and exposes connection pool metrics (open connections, in-use, idle, wait count) on every scrape.

### Structured Logging

All log output is written to stdout as JSON (configurable via `LOG_FORMAT`). Each log line includes `request_id`, `method`, `path`, `status`, `latency_ms`, `user_id` (when authenticated), and the module/provider fields relevant to the request. The `request_id` is set by `RequestIDMiddleware` (using `X-Request-ID` if provided by the upstream proxy, otherwise a new UUID) and propagated via `context.Context` through the call stack so repository-layer log lines can be correlated with the originating HTTP request.

For the full metric catalogue, PromQL examples, alert rules, Grafana setup, and configuration reference, see the [Observability Reference](observability.md).

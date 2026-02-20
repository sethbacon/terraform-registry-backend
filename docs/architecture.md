# Architecture

This document describes the design of the Enterprise Terraform Registry — what the components are, how they interact, and why key architectural decisions were made.

## Overview

The registry implements three HashiCorp Terraform protocols:

- **Module Registry Protocol** — hosting, versioning, and downloading Terraform modules
- **Provider Registry Protocol** — hosting platform-specific provider binaries
- **Provider Network Mirror Protocol** — caching provider binaries from upstream registries

Design goals: protocol correctness first, then security, then operational simplicity. The system is stateless at the application layer (all state lives in PostgreSQL and the configured storage backend), which makes horizontal scaling straightforward.

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
│                      │           └───────────────────────────┘
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
┌─────────┐    ┌────────────────────┐
│ PostgreSQL│   │   Storage Backend  │
│ (state)  │   │ Local / Azure /    │
└─────────┘    │ S3 / GCS           │
               └────────────────────┘
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

The system supports three credential types: **JWT** (for browser sessions), **API keys** (for automation), and **OIDC/Azure AD** (for SSO login flows).

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

---

## Storage Abstraction

### Interface Design

All storage backends implement the `storage.Backend` interface:

```go
type Backend interface {
    Upload(ctx, path, reader, size, checksum) (UploadResult, error)
    Download(ctx, path) (io.ReadCloser, error)
    Delete(ctx, path) error
    GetURL(ctx, path, ttl) (string, error)  // returns a signed/presigned URL
    Exists(ctx, path) (bool, error)
    GetMetadata(ctx, path) (FileMetadata, error)
}
```

`GetURL` is the key method: for cloud backends it returns a time-limited presigned/SAS URL so the client downloads directly from cloud storage without proxying through the registry. For local storage it returns the direct serving URL.

### Factory Registration

Backends register themselves via Go's `init()` mechanism:

```go
// In storage/s3/s3.go
func init() {
    factory.Register("s3", func(cfg *config.Config) (Backend, error) {
        return NewS3Backend(cfg)
    })
}
```

The main package imports each backend with a blank import (`_ "github.com/.../storage/s3"`), which triggers `init()`. Adding a new backend requires only implementing the interface and registering in `init()` — no changes to the factory or main package are needed.

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

---

## Background Jobs

| Job | Interval | Purpose |
| --- | --- | --- |
| Mirror Sync | 10 minutes | Poll upstream registries and download new provider versions |
| Tag Verifier | On webhook | Verify that SCM tags haven't moved since the version was published |

Jobs run in goroutines started at server startup. They use the same database connection pool as request handlers. Job panics are recovered and logged but do not crash the server.

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
4. **Authentication** — JWT or API key required for all non-protocol endpoints
5. **RBAC** — scope checking before any state mutation
6. **Audit logging** — immutable record of all mutating actions
7. **Bcrypt for API keys** — keys stored as bcrypt hashes; compromise of the database does not expose working keys
8. **GPG verification** — all provider binaries are verified against the publisher's GPG public key
9. **SHA256 checksums** — file integrity checked on upload and download
10. **Commit SHA pinning** — SCM-linked versions are immutable by design

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
| `6060` | pprof `/debug/pprof/` | `TFR_TELEMETRY_PPROF_PORT` |

Neither port is exposed through the public Nginx/load-balancer ingress. They are internal-only and should be firewalled to the monitoring network (Prometheus scraper, ops bastion).

### Metrics Collection Points

Metrics are collected at three layers:

- **Middleware** (`MetricsMiddleware`, `LoggerMiddleware`) — HTTP request counts, latency histograms, and structured JSON logs are recorded for every request in the main Gin middleware chain.
- **Background jobs** (`MirrorSync`, `APIKeyExpiryNotifier`) — job-level counters (syncs attempted/succeeded/failed, keys expiring, notification errors) are incremented directly within the job implementations.
- **Database collector** (`DBStatsCollector`) — a Prometheus custom collector wraps `sql.DB.Stats()` and exposes connection pool metrics (open connections, in-use, idle, wait count) on every scrape.

### Structured Logging

All log output is written to stdout as JSON (configurable via `LOG_FORMAT`). Each log line includes `request_id`, `method`, `path`, `status`, `latency_ms`, `user_id` (when authenticated), and the module/provider fields relevant to the request. The `request_id` is set by `RequestIDMiddleware` (using `X-Request-ID` if provided by the upstream proxy, otherwise a new UUID) and propagated via `context.Context` through the call stack so repository-layer log lines can be correlated with the originating HTTP request.

For the full metric catalogue, PromQL examples, alert rules, Grafana setup, and configuration reference, see the [Observability Reference](observability.md).

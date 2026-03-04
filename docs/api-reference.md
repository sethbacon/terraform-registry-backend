# API Reference

The Enterprise Terraform Registry provides a live, interactive API reference that is always
synchronized with the running codebase. This document explains how to access and use those
tools, and gives a conceptual overview of the API surface.

## Interactive API Documentation

Two interactive viewers are available, both backed by the same OpenAPI 2.0 (Swagger) spec:

### ReDoc — Browsing and Reading

```url
http(s)://your-registry/api-docs
```

ReDoc renders the full API spec as a clean, three-panel reference:

- Left panel: endpoint index with search
- Center panel: full endpoint documentation with parameters, request/response schemas
- Right panel: request/response examples

Supports dark and light mode. This is the best tool for reading and understanding the API.

### Swagger UI — Interactive Testing

```url
http(s)://your-registry/api-docs/
```

Swagger UI allows you to make live API calls directly from the browser. To authenticate:

1. Click the **Authorize** button (lock icon, top right)
2. In the "Bearer" field, enter your API key or JWT token (without the `Bearer` prefix — the UI adds it)
3. Click **Authorize**, then **Close**
4. Expand any endpoint and click **Try it out** → **Execute**

Swagger UI is served by the Go backend and reflects the exact version of the running binary.

### Raw OpenAPI Spec

```url
GET http(s)://your-registry/swagger.json
```

Machine-readable OpenAPI 2.0 JSON. Use this to generate client SDKs, import into Postman,
or integrate with API gateways. The spec includes runtime metadata (contact, license)
configured via `TFR_API_DOCS_*` environment variables.

---

## Authentication

All admin and upload endpoints require a `Bearer` token. Terraform protocol endpoints
(`/v1/modules/`, `/v1/providers/`, `/v1/mirror/`) are intentionally unauthenticated
to match the HashiCorp protocol specification — Terraform does not send credentials
when fetching module/provider metadata.

### API Key

```bash
curl -H "Authorization: Bearer tfr_your_api_key" \
     https://registry.example.com/api/v1/modules
```

### JWT (browser session)

```bash
# Login to obtain a JWT
curl -X POST https://registry.example.com/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "..."}'

# Use the returned token
curl -H "Authorization: Bearer eyJ..." \
     https://registry.example.com/api/v1/modules
```

---

## API Groups Overview

The full endpoint list (104 endpoints) is in the interactive docs above. Here is a
conceptual map of the major groups:

### Terraform Protocol Endpoints (unauthenticated)

These endpoints implement the HashiCorp protocols that `terraform init` and `terraform providers mirror` use. Terraform expects them to be publicly accessible.

| Group | Path Prefix | Purpose |
| --- | --- | --- |
| Service Discovery | `/.well-known/terraform.json` | Declares module and provider endpoint bases |
| Module Registry | `/v1/modules/` | List versions, download redirects |
| Provider Registry | `/v1/providers/` | List versions, platform download info |
| Network Mirror | `/v1/mirror/` | Provider index and version JSON for `terraform providers mirror` |
| Binary Mirror Downloads | `/terraform/binaries/:name/` | List and download mirrored Terraform/OpenTofu binaries by config name |

### Admin API (authentication required)

| Group | Path Prefix | Required Scope |
| --- | --- | --- |
| Module Management | `/api/v1/modules` | `modules:read` / `modules:write` |
| Provider Management | `/api/v1/providers` | `providers:read` / `providers:write` |
| Module Upload | `POST /api/v1/modules` | `modules:write` |
| Provider Upload | `POST /api/v1/providers` | `providers:write` |
| Users | `/api/v1/admin/users` | `admin:users` |
| Organizations | `/api/v1/admin/organizations` | `admin:organizations` |
| API Keys | `/api/v1/apikeys` | `admin:apikeys` |
| RBAC / Role Templates | `/api/v1/admin/roles` | `admin:roles` |
| Mirror Configuration | `/api/v1/admin/mirrors` | `mirrors:manage` |
| Terraform Binary Mirror Configs | `/api/v1/admin/terraform-mirrors` | `mirrors:read` / `mirrors:manage` |
| SCM Providers | `/api/v1/admin/scm-providers` | `admin:scm` |
| SCM OAuth Flows | `/api/v1/admin/scm-oauth` | `admin:scm` |
| Storage Configuration | `/api/v1/storage` | `admin:storage` |
| System Stats | `/api/v1/admin/stats` | `admin:*` |

### Webhook Receivers

| Path                                    | Purpose                                         |
|-----------------------------------------|-------------------------------------------------|
| `POST /webhooks/scm/:module_id/:secret` | Receives push and tag events from SCM providers |

### Terraform Binary Mirror (public, unauthenticated)

Mirror configurations are identified by their `name` slug.  The download endpoints are free of
authentication so CI pipelines and Terraform clients can fetch binaries without API keys.

| Method | Path | Description |
| -------- | ------ | ------------- |
| `GET` | `/terraform/binaries/:name/versions` | List all synced versions for this mirror |
| `GET` | `/terraform/binaries/:name/versions/latest` | Return the latest synced version |
| `GET` | `/terraform/binaries/:name/versions/:version` | List available platforms for a version |
| `GET` | `/terraform/binaries/:name/versions/:version/:os/:arch` | Download binary (redirect or stream) |

The `:name` parameter matches the `name` field set when the mirror config was created in the
admin UI.  A 404 is returned if no config with that name exists or if no binary has been synced
for the requested version/platform combination.

---

## Observability Endpoints

These endpoints are served by dedicated HTTP servers on separate ports and are **not**
part of the Gin router or the OpenAPI spec.  They should be bound to internal network
interfaces only and must not be exposed through the public ingress.

### Prometheus Metrics — `GET /metrics`

| Property       | Value                                                       |
|----------------|-------------------------------------------------------------|
| Port           | `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` (default: **9090**) |
| Enabled by     | `TFR_TELEMETRY_METRICS_ENABLED=true` (default: true)        |
| Content-Type   | `text/plain; version=0.0.4; charset=utf-8`                  |
| Authentication | None — restrict at network level                            |

Returns current metric values in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
Scrape every 15–60 seconds.  See [Observability Reference](observability.md) for the
complete metric catalogue, example PromQL queries, and Grafana dashboard setup.

```bash
# Quick manual check
curl -s http://localhost:9090/metrics | grep '^http_requests_total'
```

### pprof Profiling — `GET /debug/pprof/`

| Property       | Value                                                       |
|----------------|-------------------------------------------------------------|
| Port           | `TFR_TELEMETRY_PROFILING_PORT` (default: **6060**)          |
| Enabled by     | `TFR_TELEMETRY_PROFILING_ENABLED=true` (default: **false**) |

Standard Go `net/http/pprof` endpoints.  When enabled in response to a performance
issue, use `go tool pprof` to download profiles:

```bash
# 30-second CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile

# Current heap snapshot
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine dump
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

> **Warning:** Never expose port 6060 publicly.  Enable pprof only when needed and
> disable it again after profiling is complete.

---

## Common Patterns

### Pagination

List endpoints accept `page` (1-based) and `per_page` (default 20, max 100) query parameters:

```bash
GET /api/v1/modules?page=2&per_page=50
```

### Error Responses

All errors return JSON with a `status` field matching the HTTP status code and a `message` field:

```json
{
  "status": 400,
  "message": "Invalid version format: must be semver (e.g., 1.2.3)"
}
```

### Scopes in API Keys

When creating an API key via the UI or API, specify the scopes it should carry:

```json
{
  "name": "CI Publisher",
  "scopes": ["modules:write", "providers:write"]
}
```

A key with only `modules:write` cannot list users or manage mirrors — scope minimization
reduces blast radius if a key is compromised.

---

## Regenerating the OpenAPI Spec

The spec is generated from `// @` annotation comments in Go handler source files and embedded
in the binary at compile time. To regenerate after adding or changing annotations:

```bash
cd backend

# Install swag if not present
go install github.com/swaggo/swag/cmd/swag@latest

# Regenerate swagger.json (also produces swagger.yaml)
swag init -g cmd/server/main.go --outputTypes json

# Rebuild the binary to embed the updated spec
go build ./cmd/server
```

See [swagger_annotation_checklist.md](swagger_annotation_checklist.md) for the full
list of annotated endpoints and annotation rules.

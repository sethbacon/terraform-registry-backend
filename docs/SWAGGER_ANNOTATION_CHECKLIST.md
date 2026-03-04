# Swagger Annotation Checklist

## Overview

This checklist tracks Swagger/OpenAPI annotation progress for all API endpoints in the Terraform Registry.

**Target**: 100% API coverage with Swagger annotations

**Current Status**: ✅ 104/104 annotated (100%) — All Gin-router endpoints complete

See the **Out-of-Band Endpoints** section at the bottom for observability endpoints that live
on dedicated ports and are deliberately excluded from the OpenAPI spec.

---

## Phase 1: Core Authentication & Key Management

### Authentication

- [x] `GET /api/v1/auth/login` - Initiate OAuth login
- [x] `GET /api/v1/auth/callback` - OAuth callback handler
- [x] `POST /api/v1/auth/refresh` - Refresh JWT token
- [x] `GET /api/v1/auth/me` - Get current user

**File**: `backend/internal/api/admin/auth.go`
**Progress**: 4/4 annotated ✅

### API Key Management

- [x] `POST /api/v1/apikeys` - Create API key
- [x] `GET /api/v1/apikeys` - List API keys
- [x] `GET /api/v1/apikeys/:id` - Get specific API key
- [x] `PUT /api/v1/apikeys/:id` - Update API key
- [x] `POST /api/v1/apikeys/:id/rotate` - Rotate API key
- [x] `DELETE /api/v1/apikeys/:id` - Delete API key

**File**: `backend/internal/api/admin/apikeys.go`
**Progress**: 6/6 annotated ✅

---

## Phase 2: User & Organization Management

### User Management

- [x] `GET /api/v1/users` - List all users
- [x] `GET /api/v1/users/search` - Search users
- [x] `GET /api/v1/users/:id` - Get user details
- [x] `GET /api/v1/users/me/memberships` - Get current user memberships
- [x] `GET /api/v1/users/:id/memberships` - Get user memberships
- [x] `POST /api/v1/users` - Create user
- [x] `PUT /api/v1/users/:id` - Update user
- [x] `DELETE /api/v1/users/:id` - Delete user

**File**: `backend/internal/api/admin/users.go`
**Progress**: 8/8 annotated ✅

### Organization Management

- [x] `GET /api/v1/organizations` - List organizations
- [x] `GET /api/v1/organizations/search` - Search organizations
- [x] `GET /api/v1/organizations/:id` - Get organization
- [x] `GET /api/v1/organizations/:id/members` - List members
- [x] `POST /api/v1/organizations` - Create organization
- [x] `PUT /api/v1/organizations/:id` - Update organization
- [x] `DELETE /api/v1/organizations/:id` - Delete organization
- [x] `POST /api/v1/organizations/:id/members` - Add member
- [x] `PUT /api/v1/organizations/:id/members/:user_id` - Update member role
- [x] `DELETE /api/v1/organizations/:id/members/:user_id` - Remove member

**File**: `backend/internal/api/admin/organizations.go`
**Progress**: 10/10 annotated ✅

---

## Phase 3: Module & Provider Registry

### Module Registry

- [x] `GET /v1/modules/:namespace/:name/:system/versions` - List module versions (public)
- [x] `GET /v1/modules/:namespace/:name/:system/:version/download` - Download module (public)
- [x] `GET /api/v1/modules/search` - Search modules (public)
- [x] `POST /api/v1/modules` - Upload module
- [x] `GET /api/v1/modules/:namespace/:name/:system` - Get module details
- [x] `DELETE /api/v1/modules/:namespace/:name/:system` - Delete module
- [x] `DELETE /api/v1/modules/:namespace/:name/:system/versions/:version` - Delete version
- [x] `POST /api/v1/modules/:namespace/:name/:system/versions/:version/deprecate` - Deprecate version
- [x] `DELETE /api/v1/modules/:namespace/:name/:system/versions/:version/deprecate` - Remove deprecation
- [x] `POST /api/v1/admin/modules/create` - Create module record

**Files**: `backend/internal/api/modules/versions.go`, `download.go`, `search.go`, `upload.go`, `backend/internal/api/admin/modules.go`
**Progress**: 10/10 annotated ✅

### Provider Registry

- [x] `GET /v1/providers/:namespace/:type/versions` - List provider versions (public)
- [x] `GET /v1/providers/:namespace/:type/:version/download/:os/:arch` - Download provider (public)
- [x] `GET /api/v1/providers/search` - Search providers (public)
- [x] `POST /api/v1/providers` - Upload provider
- [x] `GET /api/v1/providers/:namespace/:type` - Get provider details
- [x] `DELETE /api/v1/providers/:namespace/:type` - Delete provider
- [x] `DELETE /api/v1/providers/:namespace/:type/versions/:version` - Delete version
- [x] `POST /api/v1/providers/:namespace/:type/versions/:version/deprecate` - Deprecate version
- [x] `DELETE /api/v1/providers/:namespace/:type/versions/:version/deprecate` - Remove deprecation

**Files**: `backend/internal/api/providers/versions.go`, `download.go`, `search.go`, `upload.go`, `backend/internal/api/admin/providers.go`
**Progress**: 9/9 annotated ✅

---

## Phase 4: Storage & Configuration

### Setup & Storage Configuration

- [x] `GET /api/v1/setup/status` - Get setup status
- [x] `GET /api/v1/storage/config` - Get active storage config
- [x] `GET /api/v1/storage/configs` - List all storage configs
- [x] `GET /api/v1/storage/configs/:id` - Get specific config
- [x] `POST /api/v1/storage/configs` - Create config
- [x] `PUT /api/v1/storage/configs/:id` - Update config
- [x] `DELETE /api/v1/storage/configs/:id` - Delete config
- [x] `POST /api/v1/storage/configs/:id/activate` - Activate config
- [x] `POST /api/v1/storage/configs/test` - Test config connectivity

**File**: `backend/internal/api/admin/storage.go`
**Progress**: 9/9 annotated ✅

---

## Phase 5: SCM Integration

### SCM Provider Management

- [x] `GET /api/v1/scm-providers` - List SCM providers
- [x] `GET /api/v1/scm-providers/:id` - Get SCM provider
- [x] `POST /api/v1/scm-providers` - Create SCM provider
- [x] `PUT /api/v1/scm-providers/:id` - Update SCM provider
- [x] `DELETE /api/v1/scm-providers/:id` - Delete SCM provider
- [x] `GET /api/v1/scm-providers/:id/oauth/authorize` - Get OAuth authorization URL
- [x] `GET /api/v1/scm-providers/:id/oauth/token` - Get OAuth token status
- [x] `POST /api/v1/scm-providers/:id/oauth/refresh` - Refresh OAuth token
- [x] `DELETE /api/v1/scm-providers/:id/oauth/token` - Revoke OAuth token
- [x] `POST /api/v1/scm-providers/:id/token` - Save PAT token (Bitbucket)
- [x] `GET /api/v1/scm-providers/:id/repositories` - List repositories
- [x] `GET /api/v1/scm-providers/:id/oauth/callback` - OAuth callback (public)

**Files**: `backend/internal/api/admin/scm_providers.go`, `backend/internal/api/admin/scm_oauth.go`
**Progress**: 12/12 annotated ✅

### Module SCM Linking

- [x] `POST /api/v1/admin/modules/:id/scm` - Link module to SCM
- [x] `GET /api/v1/admin/modules/:id/scm` - Get module SCM link
- [x] `PUT /api/v1/admin/modules/:id/scm` - Update SCM link
- [x] `DELETE /api/v1/admin/modules/:id/scm` - Delete SCM link
- [x] `POST /api/v1/admin/modules/:id/scm/sync` - Manually sync module
- [x] `GET /api/v1/admin/modules/:id/scm/events` - Get webhook events

**File**: `backend/internal/api/modules/scm_linking.go`
**Progress**: 6/6 annotated ✅

---

## Phase 6: Mirror Management

- [x] `GET /api/v1/admin/mirrors` - List mirrors
- [x] `GET /api/v1/admin/mirrors/:id` - Get mirror
- [x] `GET /api/v1/admin/mirrors/:id/status` - Get mirror sync status
- [x] `POST /api/v1/admin/mirrors` - Create mirror
- [x] `PUT /api/v1/admin/mirrors/:id` - Update mirror
- [x] `DELETE /api/v1/admin/mirrors/:id` - Delete mirror
- [x] `POST /api/v1/admin/mirrors/:id/sync` - Trigger mirror sync
- [x] `GET /terraform/providers/:hostname/:namespace/:type/index.json` - Mirror index (public)
- [x] `GET /terraform/providers/:hostname/:namespace/:type/:versionfile` - Mirror version file (public)

**Files**: `backend/internal/api/admin/mirror.go`, `backend/internal/api/mirror/index.go`, `backend/internal/api/mirror/platform_index.go`
**Progress**: 9/9 annotated ✅

---

## Phase 7: RBAC & Advanced Features

### Role Templates

- [x] `GET /api/v1/admin/role-templates` - List role templates
- [x] `GET /api/v1/admin/role-templates/:id` - Get role template
- [x] `POST /api/v1/admin/role-templates` - Create role template
- [x] `PUT /api/v1/admin/role-templates/:id` - Update role template
- [x] `DELETE /api/v1/admin/role-templates/:id` - Delete role template

**File**: `backend/internal/api/admin/rbac.go`
**Progress**: 5/5 annotated ✅

### Approval Requests

- [x] `GET /api/v1/admin/approvals` - List approval requests
- [x] `GET /api/v1/admin/approvals/:id` - Get approval request
- [x] `POST /api/v1/admin/approvals` - Create approval request
- [x] `PUT /api/v1/admin/approvals/:id/review` - Review approval (approve/reject)

**File**: `backend/internal/api/admin/rbac.go`
**Progress**: 4/4 annotated ✅

### Mirror Policies

- [x] `GET /api/v1/admin/policies` - List mirror policies
- [x] `GET /api/v1/admin/policies/:id` - Get mirror policy
- [x] `POST /api/v1/admin/policies` - Create mirror policy
- [x] `PUT /api/v1/admin/policies/:id` - Update mirror policy
- [x] `DELETE /api/v1/admin/policies/:id` - Delete mirror policy
- [x] `POST /api/v1/admin/policies/evaluate` - Evaluate policy

**File**: `backend/internal/api/admin/rbac.go`
**Progress**: 6/6 annotated ✅

---

## Phase 8: Utilities

- [x] `GET /api/v1/admin/stats/dashboard` - Get dashboard statistics
- [x] `POST /webhooks/scm/:module_source_repo_id/:secret` - SCM webhook (public)
- [x] `GET /health` - Health check (public)
- [x] `GET /ready` - Readiness check (public)
- [x] `GET /version` - Version info (public)
- [x] `GET /.well-known/terraform.json` - Service discovery (public)

**Files**: `backend/internal/api/router.go`, `backend/internal/api/webhooks/scm_webhook.go`, `backend/internal/api/admin/stats.go`
**Progress**: 6/6 annotated ✅

---

## Out-of-Band Observability Endpoints

The following endpoints are served by dedicated HTTP server instances started in
`backend/cmd/server/main.go`.  They are **not** registered on the Gin router and
therefore do not appear in the OpenAPI/Swagger spec.  They are documented here for
complete operational coverage.

### Prometheus Metrics  (`:9090/metrics`)

- [x] `GET /metrics` — Prometheus text exposition format
  - Enabled: `TFR_TELEMETRY_METRICS_ENABLED=true` (default: true)
  - Port:    `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` (default: 9090)
  - Content-Type: `text/plain; version=0.0.4; charset=utf-8`
  - No authentication — bind only to an internal / non-public network interface
  - Response is Prometheus exposition format; not JSON and not part of the OpenAPI spec

**File**: `backend/cmd/server/main.go` — inline `http.ListenAndServe` inside `serve()`
**Swagger tag**: annotated in the `@tag.name Observability` block in `main.go`
**Reference**: [docs/observability.md](observability.md)

### pprof Profiling  (`:6060/debug/pprof/`)

- [x] `GET /debug/pprof/`          — pprof index
- [x] `GET /debug/pprof/cmdline`   — process command-line
- [x] `GET /debug/pprof/profile`   — 30-second CPU profile
- [x] `GET /debug/pprof/symbol`    — symbol lookup
- [x] `GET /debug/pprof/trace`     — execution trace
- [x] `GET /debug/pprof/goroutine` — goroutine stack dump
- [x] `GET /debug/pprof/heap`      — heap snapshot
- [x] `GET /debug/pprof/allocs`    — allocation profile
- [x] `GET /debug/pprof/block`     — blocking events
- [x] `GET /debug/pprof/mutex`     — mutex contention
  - Enabled: `TFR_TELEMETRY_PROFILING_ENABLED=true` (default: false)
  - Port:    `TFR_TELEMETRY_PROFILING_PORT` (default: 6060)
  - Registered via `import _ "net/http/pprof"` init side-effects
  - **NEVER** expose this port publicly in production

**File**: `backend/cmd/server/main.go` — guarded `http.ListenAndServe` inside `serve()`

---

```txt
Total Gin-router Endpoints: 104
Annotated: 104
Remaining: 0
Completion: 100% ✅

Out-of-Band Endpoints (not in OpenAPI spec):
  GET /metrics           (port 9090, Prometheus)
  GET /debug/pprof/*    (port 6060, pprof, disabled by default)

Phase Breakdown:
  Phase 1 (Auth & API Keys):      10/10 (100%) ✅
  Phase 2 (Users & Orgs):         18/18 (100%) ✅
  Phase 3 (Modules & Providers):  19/19 (100%) ✅
  Phase 4 (Storage):               9/9  (100%) ✅
  Phase 5 (SCM):                  18/18 (100%) ✅
  Phase 6 (Mirror):                9/9  (100%) ✅
  Phase 7 (RBAC):                 15/15 (100%) ✅
  Phase 8 (Utilities):             6/6  (100%) ✅

@Tags used (all title-cased):
  Authentication, API Keys, Users, Organizations,
  Modules, Providers, Storage, SCM Providers,
  SCM OAuth, SCM Linking, Mirror, Mirror Protocol,
  RBAC, Stats, System, Observability, Webhooks
```

---

## How to Regenerate Swagger JSON

```bash
cd backend
swag init -g cmd/server/main.go --outputTypes json
```

Then visit `https://localhost/api-docs` to verify in the Swagger UI.

---

**Last Updated**: 2026-02-20
**Status**: ✅ All 104 Gin-router endpoints annotated — 100% complete; out-of-band observability endpoints documented in-checklist

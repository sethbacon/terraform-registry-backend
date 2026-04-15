# API Migration Guide

This document tracks API changes introduced across development phases of the Terraform
Registry backend. Each change is classified as **additive** (backward-compatible) or
**breaking**. Use this guide when upgrading to a new version to understand what has
changed and whether your integration code needs updating.

---

## Table of Contents

1. [Webhook Retry Columns](#webhook-retry-columns)
2. [Search Parameters (Sort, Order, FTS)](#search-parameters)
3. [Module Deprecation Endpoints](#module-deprecation-endpoints)
4. [Provider Deprecation Endpoints](#provider-deprecation-endpoints)
5. [Scanning Setup Endpoints](#scanning-setup-endpoints)
6. [Storage Migration Endpoints](#storage-migration-endpoints)
7. [Audit Retention and Export Endpoints](#audit-retention-and-export-endpoints)
8. [Migration Summary](#migration-summary)

---

## Webhook Retry Columns

**Type:** Additive (backward-compatible)

Database migration `000019_webhook_retry` adds new columns to the `scm_webhook_events`
table:

| Column | Type | Default | Description |
| --- | --- | --- | --- |
| `retry_count` | `INTEGER` | `0` | Number of retry attempts so far |
| `max_retries` | `INTEGER` | `0` | Maximum retries allowed for this event |
| `next_retry_at` | `TIMESTAMP WITH TIME ZONE` | `NULL` | When the next retry should be attempted |

**Impact on API consumers:**

- Webhook event responses from `GET /api/v1/admin/webhooks/events` now include
  `retry_count`, `max_retries`, and `next_retry_at` fields.
- Existing integrations that consume webhook event responses will see new fields but
  are not required to handle them. JSON consumers that ignore unknown fields are
  unaffected.
- The retry behavior is controlled by `webhooks.max_retries` and
  `webhooks.retry_interval_mins` in the configuration. See
  [Configuration Reference](configuration.md#webhooks).

**Migration steps:** None required. Run database migrations (`migrate up`) and the new
columns are added with safe defaults. Existing webhook events will have `retry_count=0`
and `max_retries=0` (no retries for historical events).

---

## Search Parameters

**Type:** Additive (backward-compatible)

Module and provider search endpoints now accept additional query parameters for sorting
and pagination:

### Module Search

`GET /api/v1/modules/search`

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `q` | string | Yes | -- | Search query |
| `namespace` | string | No | -- | Filter by namespace |
| `system` | string | No | -- | Filter by provider system |
| `sort` | string | No | `relevance` | Sort field: `relevance`, `name`, `downloads`, `created`, `updated` |
| `order` | string | No | `desc` | Sort order: `asc` or `desc` |
| `limit` | int | No | `20` | Results per page |
| `offset` | int | No | `0` | Pagination offset |

### Provider Search

`GET /api/v1/providers/search`

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `q` | string | Yes | -- | Search query |
| `namespace` | string | No | -- | Filter by namespace |
| `sort` | string | No | `relevance` | Sort field: `relevance`, `name`, `downloads`, `created`, `updated` |
| `order` | string | No | `desc` | Sort order: `asc` or `desc` |
| `limit` | int | No | `20` | Results per page |
| `offset` | int | No | `0` | Pagination offset |

**Impact on API consumers:**

- Existing search requests without `sort`/`order`/`offset` parameters continue to
  work identically.
- The `sort=relevance` option uses full-text search ranking when the query matches
  module/provider names or descriptions.
- Invalid `sort` values now return HTTP 400 instead of silently ignoring the parameter.

**Migration steps:** None required. Existing API calls are unaffected. Update your
client code to use the new parameters only if you need sorted or paginated results.

---

## Module Deprecation Endpoints

**Type:** Additive (backward-compatible)

New endpoints for marking module versions as deprecated:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/v1/modules/:namespace/:name/:system/versions/:version/deprecate` | Mark a module version as deprecated |
| `DELETE` | `/api/v1/modules/:namespace/:name/:system/versions/:version/deprecate` | Remove deprecation from a module version |

**Request body** (POST, optional):

```json
{
  "message": "Use v2.0.0 instead — this version has a known security issue."
}
```

**Response fields added to module/version listings:**

| Field | Type | Description |
| --- | --- | --- |
| `deprecated` | bool | Whether the version is deprecated |
| `deprecated_at` | string (ISO 8601) | When the version was deprecated (null if not deprecated) |
| `deprecation_message` | string | Optional message explaining the deprecation |

**Impact on API consumers:**

- Module version list responses now include `deprecated`, `deprecated_at`, and
  `deprecation_message` fields. Clients that ignore unknown fields are unaffected.
- Deprecated modules still appear in search results and version listings; clients
  should check the `deprecated` field to warn users.

**Required scope:** `modules:publish`

**Migration steps:** None required. The new fields appear automatically after migration.

---

## Provider Deprecation Endpoints

**Type:** Additive (backward-compatible)

New endpoints for marking provider versions as deprecated:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/v1/providers/:namespace/:type/versions/:version/deprecate` | Mark a provider version as deprecated |
| `DELETE` | `/api/v1/providers/:namespace/:type/versions/:version/deprecate` | Remove deprecation from a provider version |

**Request body** (POST, optional):

```json
{
  "message": "Superseded by v4.0.0."
}
```

**Response fields added to provider/version listings:**

| Field | Type | Description |
| --- | --- | --- |
| `deprecated` | bool | Whether the version is deprecated |
| `deprecated_at` | string (ISO 8601) | When the version was deprecated |
| `deprecation_message` | string | Optional deprecation message |

**Impact on API consumers:** Same as module deprecation -- new fields in responses,
no breaking changes. Clients that ignore unknown fields are unaffected.

**Required scope:** `providers:publish`

**Migration steps:** None required.

---

## Scanning Setup Endpoints

**Type:** Additive (backward-compatible)

New endpoints for configuring module security scanning through the setup wizard:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/v1/setup/scanning/test` | Test a scanning configuration (validates binary path/version) |
| `POST` | `/api/v1/setup/scanning` | Save scanning configuration to the database |
| `GET` | `/api/v1/admin/scanning/config` | View the current scanning configuration (sensitive fields excluded) |

**Authentication:**

- Setup endpoints (`/api/v1/setup/*`) require the one-time setup token
  (`Authorization: SetupToken <token>`). These endpoints are permanently disabled
  after setup completes.
- The admin config endpoint (`/api/v1/admin/scanning/config`) requires JWT/API key
  authentication with `admin:*` scope.

**Impact on API consumers:**

- These are entirely new endpoints. Existing integrations are unaffected.
- Scanning configuration stored in the database takes precedence over config file
  values and supports runtime changes without restart.

**Migration steps:** None required. If you previously configured scanning via config
file, that continues to work. The setup wizard provides an alternative configuration
path.

---

## Storage Migration Endpoints

**Type:** Additive (backward-compatible)

New endpoints for migrating artifacts between storage backends without downtime:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/v1/admin/storage/migrations/plan` | Plan a migration (counts artifacts to move) |
| `POST` | `/api/v1/admin/storage/migrations` | Start a background migration |
| `GET` | `/api/v1/admin/storage/migrations` | List all migrations |
| `GET` | `/api/v1/admin/storage/migrations/:id` | Get status of a specific migration |
| `POST` | `/api/v1/admin/storage/migrations/:id/cancel` | Cancel a running migration |

**Required scope:** `admin:*`

**Impact on API consumers:**

- These are entirely new endpoints. Existing integrations are unaffected.
- During a migration, reads transparently fall back to the old storage backend for
  artifacts that have not yet been copied. No downtime is required.

**Migration steps:** None required. Use these endpoints when you want to change
storage backends (e.g., from local filesystem to S3) on a running instance.

---

## Audit Retention and Export Endpoints

**Type:** Additive (backward-compatible)

New endpoint for exporting audit logs:

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/v1/admin/audit-logs/export` | Export audit logs as JSON, with optional date range filtering |

**Query parameters:**

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `start_date` | string (ISO 8601) | No | Start of the export date range |
| `end_date` | string (ISO 8601) | No | End of the export date range |

**Required scope:** `admin:*`

**Impact on API consumers:**

- This is an entirely new endpoint. Existing integrations are unaffected.
- Audit log retention (automatic deletion of old entries) is configured via
  `audit_retention.retention_days` in the config file. See
  [Configuration Reference](configuration.md#audit-log-retention).

**Migration steps:** None required.

---

## Migration Summary

| Change | Type | Breaking | Action Required |
| --- | --- | --- | --- |
| Webhook retry columns | Schema (additive) | No | Run `migrate up` |
| Search sort/order/offset parameters | API (additive) | No | None |
| Module deprecation endpoints | API (additive) | No | None |
| Provider deprecation endpoints | API (additive) | No | None |
| Scanning setup endpoints | API (additive) | No | None |
| Storage migration endpoints | API (additive) | No | None |
| Audit export endpoint | API (additive) | No | None |
| Audit retention config | Config (additive) | No | None |
| Webhook retry config | Config (additive) | No | None |

**No breaking changes have been introduced.** All changes are additive. Existing API
clients, Terraform CLI integrations, and configuration files continue to work without
modification after upgrading.

### Upgrade Procedure

1. **Back up your database** before upgrading (see [Deployment Guide](deployment.md#backup--restore)).
2. **Update the binary or container image** to the new version.
3. **Run database migrations**: `migrate up` (or let the server auto-migrate on startup).
4. **Optionally configure new features** (webhook retries, audit retention, scanning) via
   config file or environment variables.
5. **Verify** the deployment with the [post-deployment smoke tests](deployment.md#7-post-deployment-smoke-tests).

# Observability Reference

The Terraform Registry exposes structured logs, a Prometheus metrics endpoint, and an
optional pprof profiling server.  This document is the complete reference for all three
surfaces: what each metric means, how to query it, example alert rules, and how to set
up the bundled Prometheus + Grafana stack.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prometheus Metrics Endpoint](#prometheus-metrics-endpoint)
3. [Metric Catalogue](#metric-catalogue)
   - [HTTP Metrics](#http-metrics)
   - [Terraform Protocol Metrics](#terraform-protocol-metrics)
   - [Mirror Sync Metrics](#mirror-sync-metrics)
   - [Terraform Binary Mirror Metrics](#terraform-binary-mirror-metrics)
   - [API Key Notification Metrics](#api-key-notification-metrics)
   - [Rate Limiting Metrics](#rate-limiting-metrics)
   - [Application Info Metrics](#application-info-metrics)
   - [Security Scanning Metrics](#security-scanning-metrics)
   - [Webhook Metrics](#webhook-metrics)
   - [Cleanup Job Metrics](#cleanup-job-metrics)
   - [Database Metrics](#database-metrics)
4. [PromQL Examples](#promql-examples)
5. [Recommended Alert Rules](#recommended-alert-rules)
6. [Grafana Dashboard Setup](#grafana-dashboard-setup)
7. [Structured Logging](#structured-logging)
8. [pprof Profiling](#pprof-profiling)
9. [Configuration Reference](#configuration-reference)

---

## Architecture Overview

For a full description of how observability integrates into the overall system design — port separation rationale, middleware collection points, structured log correlation — see [Architecture → Observability Architecture](architecture.md#observability-architecture).

The diagram below shows the data-flow from the Go backend to Prometheus and Grafana:

```txt
                      ┌──────────────────────────────────────┐
                      │         Go Backend (Gin)              │
  :8080  ─────────────►  Main API + Middleware chain          │
                      │  ┌───────────────────────────────┐   │
                      │  │ RequestIDMiddleware            │   │
                      │  │ MetricsMiddleware   ←──────────┼───┼── records to default
                      │  │ LoggerMiddleware    ←──────────┼───┼── registry (promauto)
                      │  └───────────────────────────────┘   │
                      └──────────────┬───────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
       :9090 (metrics)        :6060 (pprof)         Background jobs:
       GET /metrics           /debug/pprof/          MirrorSync
       promhttp.Handler()     net/http/pprof         APIKeyExpiryNotifier
              │                      │               DBStatsCollector
              ▼                      ▼
       Prometheus ──scrape──► Stores time-series
       Grafana    ──query──►  Visualises dashboards
```

Metrics and pprof are each served by a lightweight `http.ServeMux` on a **dedicated
port** that is never reachable through the public Nginx/load-balancer ingress.  This
prevents any risk of exposing internal metrics to anonymous internet traffic.

---

## Prometheus Metrics Endpoint

| Property        | Value                                                        |
|-----------------|--------------------------------------------------------------|
| Path            | `GET /metrics`                                               |
| Port            | `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` (default: **9090**)  |
| Protocol        | HTTP (not HTTPS — keep on internal network only)             |
| Format          | Prometheus text exposition format v0.0.4                     |
| Authentication  | None — restrict at the network/firewall level                |
| Scrape interval | 15 s recommended; 60 s acceptable for low-traffic installs   |

### Verify the endpoint is live

```bash
curl -s http://localhost:9090/metrics | head -30
```

Expected output (excerpt):

```txt
# HELP http_requests_total Total number of HTTP requests processed, by method, route template, and status code.
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/health",status="200"} 42
http_requests_total{method="GET",path="/v1/modules/:namespace/:name/:system/versions",status="200"} 1337
# HELP http_request_duration_seconds Histogram of HTTP request latencies, by method and route template.
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",path="/health",le="0.005"} 40
...
# HELP db_open_connections Current number of open database connections in the pool.
# TYPE db_open_connections gauge
db_open_connections 3
```

### Prometheus scrape configuration

```yaml
# prometheus.yml snippet — already pre-configured in deployments/prometheus.yml
scrape_configs:
  - job_name: terraform-registry
    static_configs:
      - targets: ['backend:9090']  # internal Docker network hostname
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /metrics
```

---

## Metric Catalogue

### HTTP Metrics

#### `http_requests_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | `method` (GET, POST, …), `path` (Gin route template), `status` (HTTP status code string) |
| Source | `internal/middleware/metrics.go` → `MetricsMiddleware` |
| Updated | After every request completes |

The `path` label holds the **Gin route template**, not the raw URL.  This keeps
cardinality bounded regardless of how many unique module names, versions, or UUIDs
appear in requests.

Examples of `path` values:

- `/health`
- `/v1/modules/:namespace/:name/:system/versions`
- `/api/v1/providers/:namespace/:type`
- `<no-route>` — unmatched requests (404/405)

---

#### `http_request_duration_seconds`

| Property | Value |
| --- | --- |
| Type | Histogram |
| Labels | `method`, `path` (Gin route template) |
| Buckets | 5 ms, 10 ms, 25 ms, 50 ms, 100 ms, 250 ms, 500 ms, 1 s, 2.5 s, 5 s, 10 s, 30 s |
| Source | `internal/middleware/metrics.go` → `MetricsMiddleware` |
| Updated | After every request completes |

Use `histogram_quantile` to compute percentile latencies per route.  The fine-grained
buckets at the low end (5 ms–100 ms) are designed for health check and protocol
discovery endpoints; the high end (5 s–30 s) covers large module/provider uploads.

---

### Terraform Protocol Metrics

#### `module_downloads_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | `namespace`, `system` |
| Source | `internal/api/modules/` download handlers |
| Updated | On each successful module download redirect |

Tracks how many times Terraform fetched a module download URL.  The `system` label
holds the root module system identifier (e.g. `aws`, `azurerm`, `kubernetes`).

---

#### `provider_downloads_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | `namespace`, `type`, `os`, `arch` |
| Source | `internal/api/providers/` download handlers |
| Updated | On each successful provider binary download redirect |

The `os` and `arch` labels (e.g. `linux`/`amd64`, `darwin`/`arm64`) are useful for
understanding which platforms are actively used and for planning build matrix coverage.

---

### Mirror Sync Metrics

#### `mirror_sync_duration_seconds`

| Property | Value |
| --- | --- |
| Type | Histogram |
| Labels | `mirror_id` (UUID of the mirror configuration row), `mirror_type` (`provider` or `terraform`) |
| Buckets | Prometheus default: 5 ms to 10 s |
| Source | `internal/jobs/` mirror sync job |
| Updated | Once per completed sync cycle for each mirror configuration |

The `mirror_type` label distinguishes provider mirrors from Terraform binary mirrors,
enabling separate duration tracking per mirror kind.

---

#### `mirror_sync_errors_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | `mirror_id` (UUID of the mirror configuration row) |
| Source | `internal/jobs/` mirror sync job |
| Updated | On each failed sync attempt for a given mirror |

The `mirror_id` label lets you build per-mirror error rate dashboards and route alerts
to the team responsible for a specific upstream.

---

### Terraform Binary Mirror Metrics

#### `terraform_binary_downloads_total`

| Property | Value |
| --- | --- |
| Type | Counter (CounterVec) |
| Labels | `version` (semver string), `os` (e.g. `linux`, `darwin`, `windows`), `arch` (e.g. `amd64`, `arm64`) |
| Source | `internal/api/terraform_binaries/` — `DownloadBinary` handler |
| Updated | On each successful binary download (or redirect) |

Counts how many times a Terraform or OpenTofu binary was served through the binary mirror
download endpoint.  Use the `version`, `os`, and `arch` labels to understand which
combinations are actively consumed and which platform builds are never requested.

Example queries:

```promql
# Total binary downloads in the last 5 minutes
sum(rate(terraform_binary_downloads_total[5m]))

# Downloads broken down by OS
sum by (os) (rate(terraform_binary_downloads_total[5m]))

# Most popular versions
sum by (version) (increase(terraform_binary_downloads_total[24h]))
```

---

### API Key Notification Metrics

#### `apikey_expiry_notifications_sent_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | None |
| Source | `internal/jobs/api_key_expiry_notifier.go` |
| Updated | Once per email successfully delivered |

A stalling counter while keys are approaching expiry is an indicator of SMTP delivery
failure.  Pair this metric with an alert on `apikey_expiry_notifications_sent_total`
increase being zero during the expected notification window.

---

### Rate Limiting Metrics

#### `rate_limit_rejections_total`

| Property | Value |
| --- | --- |
| Type | Counter (CounterVec) |
| Labels | `tier` (`individual` or `organization`), `key_type` (`user`, `apikey`, `ip`, or `org`) |
| Source | `internal/middleware/ratelimit.go` |
| Updated | Each time a request is rejected with HTTP 429 |

Tracks every request rejected by the rate limiting middleware. The `tier` label
distinguishes individual (per-user/IP) rejections from organization-level rejections.
Use `key_type` to identify whether rejections are hitting anonymous IP-based clients
or authenticated users/API keys.

Example queries:

```promql
# Rejection rate by tier
sum by (tier) (rate(rate_limit_rejections_total[5m]))

# Alert on high org-level rejections
rate(rate_limit_rejections_total{tier="organization"}[5m]) > 10
```

---

### Application Info Metrics

#### `terraform_registry_info`

| Property | Value |
| --- | --- |
| Type | Gauge (GaugeVec) |
| Labels | `version` (application semver), `go_version` (Go runtime version), `build_date` |
| Source | `internal/telemetry/metrics.go` → set at startup |
| Updated | Once at startup; value is always `1` |

Exposes build metadata as Prometheus labels. The gauge value is always `1`; the useful
information is in the label values. Use this to verify which version is running across
replicas and to correlate deployments with metric changes.

Example queries:

```promql
# Show build info
terraform_registry_info

# Count replicas per version (useful during rolling updates)
count by (version) (terraform_registry_info)
```

---

### Security Scanning Metrics

#### `terraform_registry_scan_queue_depth`

| Property | Value |
| --- | --- |
| Type | Gauge |
| Labels | None |
| Source | Scanning subsystem |
| Updated | Whenever a module is enqueued or dequeued for scanning |

Tracks how many modules are waiting for a security scan. A persistently rising value
indicates the scan workers cannot keep up with upload volume. Consider increasing
`scanning.worker_count`.

---

#### `terraform_registry_scan_duration_seconds`

| Property | Value |
| --- | --- |
| Type | Histogram (HistogramVec) |
| Labels | `tool` (scanner backend name, e.g. `trivy`), `status` (scan result status) |
| Buckets | Prometheus default: 5 ms to 10 s |
| Source | Scanning subsystem |
| Updated | After each completed scan |

Records the wall-clock time of each module security scan. Use `tool` and `status`
labels to identify slow or failing scanner backends.

Example queries:

```promql
# p95 scan duration
histogram_quantile(0.95, rate(terraform_registry_scan_duration_seconds_bucket[1h]))

# Scan duration by tool
histogram_quantile(0.95, sum by (tool, le) (rate(terraform_registry_scan_duration_seconds_bucket[1h])))
```

---

### Webhook Metrics

#### `terraform_registry_webhook_retries_total`

| Property | Value |
| --- | --- |
| Type | Counter (CounterVec) |
| Labels | `outcome` (`success`, `failure`, `exhausted`) |
| Source | Webhook retry processor |
| Updated | On each retry attempt |

Tracks webhook delivery retry attempts. `success` means the retry delivered
successfully, `failure` means it failed but will be retried again, and `exhausted`
means all retries have been used with no success. A rising `exhausted` count indicates
unreachable webhook endpoints that need investigation.

Example queries:

```promql
# Retry success rate over the last hour
rate(terraform_registry_webhook_retries_total{outcome="success"}[1h])

# Exhausted retries in the last day (webhooks permanently failing)
increase(terraform_registry_webhook_retries_total{outcome="exhausted"}[24h])
```

---

### Cleanup Job Metrics

#### `terraform_registry_jwt_revoked_tokens_cleaned_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | None |
| Source | JWT revoked token cleanup job |
| Updated | Each time expired revoked tokens are removed from the database |

Counts the number of expired revoked JWT tokens that have been cleaned from the
`revoked_tokens` table. A healthy system will show a steady increase. If this counter
stops growing while new tokens are being revoked, the cleanup job may have stalled.

---

#### `terraform_registry_audit_logs_cleaned_total`

| Property | Value |
| --- | --- |
| Type | Counter |
| Labels | None |
| Source | Audit log retention cleanup job |
| Updated | Each time expired audit log entries are deleted |

Counts the number of audit log entries removed by the retention cleanup job. The job
runs periodically and deletes entries older than `audit_retention.retention_days`.

Example queries:

```promql
# Rows cleaned per day
increase(terraform_registry_audit_logs_cleaned_total[24h])
```

---

#### `db_open_connections`

| Property | Value |
| --- | --- |
| Type | Gauge |
| Labels | None |
| Source | `internal/telemetry/metrics.go` → `StartDBStatsCollector` |
| Sampling interval | Every 30 seconds |
| Updated | By a background goroutine; not per-request |

Reflects `sql.DB.Stats().OpenConnections`.  Compare against
`TFR_DATABASE_MAX_CONNECTIONS` (default: 25) to compute pool utilisation.  If this
gauge is consistently near the maximum, increase `TFR_DATABASE_MAX_CONNECTIONS` or
investigate slow queries holding connections open.

---

## PromQL Examples

All examples assume the Prometheus job label is `job="terraform-registry"`.

### Request Rate

```promql
# Overall requests per second (5-minute rate)
sum(rate(http_requests_total{job="terraform-registry"}[5m]))

# Request rate broken down by route template
sum by (path) (rate(http_requests_total{job="terraform-registry"}[5m]))

# Request rate broken down by HTTP status class
sum by (status) (rate(http_requests_total{job="terraform-registry"}[5m]))
```

### Error Rate

```promql
# 5xx error rate as a percentage of all requests
100 * sum(rate(http_requests_total{job="terraform-registry", status=~"5.."}[5m]))
    / sum(rate(http_requests_total{job="terraform-registry"}[5m]))

# 5xx errors limited to API routes (auth required endpoints)
sum(rate(http_requests_total{job="terraform-registry", path=~"/api/.*", status=~"5.."}[5m]))

# 404 Not Found rate (may indicate misconfigured clients)
rate(http_requests_total{job="terraform-registry", status="404"}[5m])
```

### Latency Percentiles

```promql
# p50 (median) latency across all routes
histogram_quantile(0.50,
  sum by (le) (rate(http_request_duration_seconds_bucket{job="terraform-registry"}[5m]))
)

# p99 latency per route template
histogram_quantile(0.99,
  sum by (path, le) (rate(http_request_duration_seconds_bucket{job="terraform-registry"}[5m]))
)

# Average latency per route (less useful than percentiles but simple)
sum by (path) (rate(http_request_duration_seconds_sum{job="terraform-registry"}[5m]))
/ sum by (path) (rate(http_request_duration_seconds_count{job="terraform-registry"}[5m]))
```

### Downloads

```promql
# Module download rate over 1 hour, by namespace
sum by (namespace) (rate(module_downloads_total{job="terraform-registry"}[1h]))

# Total module downloads by system (top 5)
topk(5, sum by (system) (module_downloads_total{job="terraform-registry"}))

# Provider download rate by platform
sum by (os, arch) (rate(provider_downloads_total{job="terraform-registry"}[1h]))
```

### Mirror Sync

```promql
# p95 mirror sync duration over the last day
histogram_quantile(0.95,
  sum by (le) (rate(mirror_sync_duration_seconds_bucket{job="terraform-registry"}[24h]))
)

# Mirror sync error rate per mirror (errors per hour)
sum by (mirror_id) (rate(mirror_sync_errors_total{job="terraform-registry"}[1h]))

# Total errors per mirror since startup
sort_desc(sum by (mirror_id) (mirror_sync_errors_total{job="terraform-registry"}))
```

### Database Pool

```promql
# Current open connections
db_open_connections{job="terraform-registry"}

# Pool utilisation % (assuming default max of 25 — adjust if you changed TFR_DATABASE_MAX_CONNECTIONS)
db_open_connections{job="terraform-registry"} / 25 * 100
```

### Rate Limiting

```promql
# Rejection rate by tier (individual vs org)
sum by (tier) (rate(rate_limit_rejections_total{job="terraform-registry"}[5m]))

# Rejection rate by key type
sum by (key_type) (rate(rate_limit_rejections_total{job="terraform-registry"}[5m]))
```

### Security Scanning

```promql
# Current scan queue depth
terraform_registry_scan_queue_depth{job="terraform-registry"}

# p95 scan duration by tool
histogram_quantile(0.95,
  sum by (tool, le) (rate(terraform_registry_scan_duration_seconds_bucket{job="terraform-registry"}[1h]))
)
```

### Webhook Retries

```promql
# Retries by outcome over the last hour
sum by (outcome) (rate(terraform_registry_webhook_retries_total{job="terraform-registry"}[1h]))

# Permanently failed webhooks (all retries exhausted)
increase(terraform_registry_webhook_retries_total{outcome="exhausted",job="terraform-registry"}[24h])
```

### Cleanup Jobs

```promql
# Revoked JWT tokens cleaned per day
increase(terraform_registry_jwt_revoked_tokens_cleaned_total{job="terraform-registry"}[24h])

# Audit logs cleaned per day
increase(terraform_registry_audit_logs_cleaned_total{job="terraform-registry"}[24h])
```

---

## Recommended Alert Rules

The Helm chart ships a ready-to-use PrometheusRule resource at
`deployments/helm/templates/prometheusrule.yaml`. Enable it with:

```yaml
# values.yaml
prometheusRule:
  enabled: true
  labels: {}   # add labels if your Prometheus Operator uses a ruleSelector
```

The PrometheusRule includes these alerts out of the box:

| Alert | Expression (summary) | Severity |
| --- | --- | --- |
| `TerraformRegistryHighErrorRate` | 5xx rate > 5% for 5 min | critical |
| `TerraformRegistryRateLimiterExhaustion` | Rate limiter rejections > 10 req/s for 5 min | warning |
| `TerraformRegistryMirrorSyncFailure` | > 3 mirror sync errors in 30 min | warning |
| `TerraformRegistryScanFailure` | > 5 scan errors in 1 hr | warning |
| `TerraformRegistryDBConnectionPoolNearExhaustion` | DB connections > 80% of max for 5 min | warning |
| `TerraformRegistryHighP99Latency` | p99 latency > 5 s for 10 min | warning |

### Additional Recommended Alert Rules

Copy these into your Prometheus alert rules configuration or add them to the
PrometheusRule as a starting point. Tune thresholds to match your traffic patterns.

```yaml
groups:
  - name: terraform-registry
    rules:

      # ── Availability ───────────────────────────────────────────────────────

      - alert: RegistryHighErrorRate
        expr: |
          100 * sum(rate(http_requests_total{status=~"5.."}[5m]))
              / sum(rate(http_requests_total[5m])) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High 5xx error rate ({{ $value | printf \"%.1f\" }}%)"
          description: >
            More than 5% of requests are returning 5xx errors over the last 5 minutes.
            Check backend logs for stack traces.

      - alert: RegistryDown
        expr: absent(http_requests_total)
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Terraform Registry has stopped emitting metrics"
          description: >
            No http_requests_total series visible.  The metrics endpoint is unreachable
            or the backend process has crashed.

      # ── Latency ───────────────────────────────────────────────────────────

      - alert: RegistryHighP99Latency
        expr: |
          histogram_quantile(0.99,
            sum by (le) (rate(http_request_duration_seconds_bucket[5m]))
          ) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "p99 request latency > 2 s"
          description: >
            The 99th percentile request latency has exceeded 2 seconds for 5 minutes.
            Investigate slow database queries or storage backend issues.

      # ── Database ──────────────────────────────────────────────────────────

      - alert: DatabasePoolNearExhaustion
        expr: db_open_connections > 22
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool near exhaustion ({{ $value }}/25 open)"
          description: >
            More than 22 of 25 database connections are in use.  Consider increasing
            TFR_DATABASE_MAX_CONNECTIONS or investigating slow transactions.

      # ── Mirror Sync ───────────────────────────────────────────────────────

      - alert: MirrorSyncErrors
        expr: increase(mirror_sync_errors_total[30m]) > 3
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Mirror sync errors on {{ $labels.mirror_id }}"
          description: >
            More than 3 mirror sync failures in the last 30 minutes for mirror
            {{ $labels.mirror_id }}.  Check upstream registry availability and
            network connectivity.

      # ── Notifications ─────────────────────────────────────────────────────

      - alert: APIKeyNotificationsStalledDuringBusinessHours
        expr: |
          (hour() >= 8 and hour() < 20)
          and increase(apikey_expiry_notifications_sent_total[2h]) == 0
          and on() (count(up{job="terraform-registry"}) > 0)
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "No API key expiry notifications sent in 2 hours during business hours"
          description: >
            Zero notification emails have been dispatched in the last 2 hours between
            08:00 and 20:00.  Possible SMTP delivery failure.  Check TFR_NOTIFICATIONS_*
            configuration and SMTP server connectivity.
```

---

## Grafana Dashboard Setup

### With Helm Chart (Recommended for Kubernetes)

The Helm chart ships a Grafana dashboard as a ConfigMap at
`deployments/helm/templates/grafana-dashboard.yaml`. When enabled, the ConfigMap
is labelled `grafana_dashboard: "1"` so the Grafana sidecar (from the
[Grafana Helm chart](https://github.com/grafana/helm-charts/tree/main/charts/grafana))
automatically discovers and imports it.

```yaml
# values.yaml
grafanaDashboard:
  enabled: true
  labels:
    grafana_dashboard: "1"   # must match grafana.sidecar.dashboards.label
```

The bundled dashboard includes panels for:

| Panel | Metric |
| --- | --- |
| Request Rate (req/s) | `http_requests_total` |
| Error Rate (%) | `http_requests_total{status=~"5.."}` / `http_requests_total` |
| P99 Latency by Route | `http_request_duration_seconds_bucket` |
| Mirror Sync Health | `mirror_sync_duration_seconds_bucket` + `mirror_sync_errors_total` |
| Module Scan Queue Depth | `terraform_registry_scan_queue_depth` |
| Rate Limiter Rejections | `rate_limit_rejections_total` |
| DB Connection Pool | `db_open_connections` |
| Module Downloads | `module_downloads_total` |
| Build Info | `terraform_registry_info` |

#### Manual import from ConfigMap

If you are not using the Grafana sidecar, extract the dashboard JSON and import manually:

```bash
# Extract the dashboard JSON from the rendered ConfigMap
helm template terraform-registry deployments/helm/ \
  --set grafanaDashboard.enabled=true \
  | yq eval 'select(.metadata.name == "*grafana-dashboard") | .data["terraform-registry.json"]' - \
  > terraform-registry-dashboard.json

# Then import via Grafana UI: Dashboards -> Import -> Upload JSON file
```

### With Docker Compose

```bash
cd deployments

# Start registry + Prometheus + Grafana
docker-compose --profile monitoring up -d

# Grafana UI
open http://localhost:3001   # admin / admin
```

Prometheus is automatically added as a data source (URL: `http://prometheus:9090`).

### Importing a Dashboard

1. Log into Grafana at `http://localhost:3001`
2. Go to **Dashboards → Import**
3. Paste the JSON from `deployments/grafana/terraform-registry.json` (if present) or
   create a new dashboard with the queries below

### Suggested Dashboard Panels

| Panel | PromQL |
| --- | --- |
| Request rate (req/s) | `sum(rate(http_requests_total[5m]))` |
| Error rate (%) | `100 * sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))` |
| p50 / p95 / p99 latency | `histogram_quantile(0.99, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))` |
| DB connections | `db_open_connections` |
| Module downloads / hr | `sum(increase(module_downloads_total[1h]))` |
| Provider downloads / hr | `sum(increase(provider_downloads_total[1h]))` |
| Binary mirror downloads / hr | `sum(increase(terraform_binary_downloads_total[1h]))` |
| Mirror sync errors | `sum(rate(mirror_sync_errors_total[1h]))` |
| Mirror sync p95 duration | `histogram_quantile(0.95, sum by(le) (rate(mirror_sync_duration_seconds_bucket[1h])))` |
| Rate limiter rejections | `sum by (tier) (rate(rate_limit_rejections_total[5m]))` |
| Scan queue depth | `terraform_registry_scan_queue_depth` |
| Scan duration p95 | `histogram_quantile(0.95, rate(terraform_registry_scan_duration_seconds_bucket[1h]))` |
| Webhook retry exhaustions | `increase(terraform_registry_webhook_retries_total{outcome="exhausted"}[24h])` |
| Build info | `terraform_registry_info` |

### Without Docker Compose

Point any Prometheus 2.x server at the registry's metrics port:

```yaml
scrape_configs:
  - job_name: terraform-registry
    static_configs:
      - targets: ['<registry-host>:9090']
```

Then add it as a data source in Grafana and build dashboards using the queries above.

---

## Structured Logging

The backend uses the Go standard library `log/slog` package.  The global default logger
is configured in `internal/telemetry/slog.go` and called from `main.go` before the
HTTP server starts.

### Log format

| `TFR_LOGGING_FORMAT` | Handler | Best for |
| --- | --- | --- |
| `json` (default) | `slog.JSONHandler` | Production (machine-parseable; Loki, CloudWatch, Datadog) |
| `text` | `slog.NewTextHandler` | Local development (human-readable key=value) |

### Log level

Set `TFR_LOGGING_LEVEL` to `debug`, `info` (default), `warn`, or `error`.

`debug` level additionally adds source file and line number to every log record.

### Log record structure (JSON format)

```json
{
  "time": "2026-02-20T14:23:01.123456789Z",
  "level": "INFO",
  "msg": "http request",
  "method": "GET",
  "path": "/v1/modules/hashicorp/consul/aws/1.0.0/download",
  "query": "",
  "status": 200,
  "size": 128,
  "latency": "1.234ms",
  "ip": "10.0.0.1",
  "request_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "user_agent": "Terraform/1.5.7"
}
```

### Correlating logs with traces

The `request_id` field matches the value from the `X-Request-ID` response header.
Clients that include `X-Request-ID` in their request see the same value echoed back
and in all server-side log records for that request.

### Shipping logs to Loki

```yaml
# Promtail scrape config for Docker
scrape_configs:
  - job_name: terraform-registry
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
    relabel_configs:
      - source_labels: [__meta_docker_container_name]
        target_label: container
    pipeline_stages:
      - json:
          expressions:
            level: level
            request_id: request_id
            status: status
      - labels:
          level:
          status:
```

---

## pprof Profiling

pprof is disabled by default.  Enable it only when investigating a performance problem
and disable it immediately afterwards.

### Enable

```bash
export TFR_TELEMETRY_PROFILING_ENABLED=true
export TFR_TELEMETRY_PROFILING_PORT=6060   # default
```

### Available endpoints

| Path | Description |
| --- | --- |
| `/debug/pprof/` | Index of all profiles |
| `/debug/pprof/profile?seconds=30` | 30-second CPU profile |
| `/debug/pprof/heap` | Heap snapshot |
| `/debug/pprof/goroutine?debug=1` | All goroutine stacks |
| `/debug/pprof/allocs` | Memory allocation profile |
| `/debug/pprof/block` | Goroutine blocking events |
| `/debug/pprof/mutex` | Mutex contention |
| `/debug/pprof/trace?seconds=5` | 5-second execution trace |

### Example workflow: investigate high CPU

```bash
# 1. Port-forward if running in Kubernetes
kubectl port-forward deployment/terraform-registry 6060:6060

# 2. Capture a 30-second CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# In the pprof CLI:
(pprof) top 20          # top 20 functions by CPU
(pprof) web             # open flame graph in browser (requires graphviz)
(pprof) peek <func>     # inspect a specific function
```

### Example workflow: investigate memory leak

```bash
# Capture a heap snapshot
go tool pprof http://localhost:6060/debug/pprof/heap

# In the pprof CLI:
(pprof) top 20 -cum     # cumulative allocation by function
(pprof) list <func>     # annotated source for a function
```

### Example workflow: goroutine leak

```bash
# Dump current goroutine stacks
curl -s http://localhost:6060/debug/pprof/goroutine?debug=2

# Or open the index in a browser
open http://localhost:6060/debug/pprof/
```

> **Security note:** Never expose port 6060 via a public load balancer or Nginx
> virtual host.  pprof responses contain heap contents and full goroutine stacks
> that may include sensitive data (tokens, connection strings).

---

## Configuration Reference

All variables follow the `TFR_` prefix convention and can be set as environment
variables or in `backend/config.yaml` under the `telemetry:` and `logging:` keys.

| Environment Variable | Config Key | Default | Description |
| --- | --- | --- | --- |
| `TFR_TELEMETRY_METRICS_ENABLED` | `telemetry.metrics.enabled` | `true` | Expose `/metrics` endpoint |
| `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` | `telemetry.metrics.prometheus_port` | `9090` | Port for the Prometheus scrape endpoint |
| `TFR_TELEMETRY_PROFILING_ENABLED` | `telemetry.profiling.enabled` | `false` | Enable pprof endpoint |
| `TFR_TELEMETRY_PROFILING_PORT` | `telemetry.profiling.port` | `6060` | Port for the pprof endpoint |
| `TFR_LOGGING_FORMAT` | `logging.format` | `json` | Log format: `json` or `text` |
| `TFR_LOGGING_LEVEL` | `logging.level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `TFR_DATABASE_MAX_CONNECTIONS` | `database.max_connections` | `25` | Maximum DB connections in pool |
| `TFR_DATABASE_MIN_IDLE_CONNECTIONS` | `database.min_idle_connections` | `5` | Minimum idle DB connections kept warm |

See [Configuration Reference](configuration.md) for the complete list of all `TFR_*`
variables.

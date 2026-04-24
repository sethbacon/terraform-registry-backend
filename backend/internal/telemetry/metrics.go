// Package telemetry provides application-level observability for the Terraform Registry.
//
// # Prometheus Metrics Endpoint
//
// All metrics are registered against the default Prometheus registry and are
// automatically available on the side-channel HTTP server started by main.go:
//
//	GET http(s)://<host>:<TFR_TELEMETRY_METRICS_PROMETHEUS_PORT>/metrics
//
// Default port: 9090.  The endpoint returns data in the Prometheus text exposition
// format (Content-Type: text/plain; version=0.0.4) and is intended to be scraped by
// a Prometheus server every 15–60 seconds.  It is NOT served by the Gin router and
// is therefore absent from the OpenAPI/Swagger spec.
//
// # Metric Groups
//
//   - HTTP request counters and latency histograms (labelled by route template, not raw URL)
//   - Module and provider binary download counters
//   - Provider mirror sync duration and error counters
//   - API key expiry notification counters
//   - Database connection pool gauge (polled every 30 s)
//
// # Label Cardinality
//
// HTTP metrics use c.FullPath() (route template such as /v1/modules/:namespace/:name)
// rather than the raw request URL to prevent unbounded label cardinality from
// user-supplied path segments such as module names or version strings.
//
// # Usage
//
// Import the package for side effects so metrics are registered before the HTTP server
// starts listening:
//
//	import _ "github.com/terraform-registry/terraform-registry/internal/telemetry"
//
// Or import it directly and use an exported var:
//
//	telemetry.ModuleDownloadsTotal.WithLabelValues(namespace, system).Inc()
package telemetry

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HTTP metrics — labelled by method, route template, and status code.
//
// HTTPRequestsTotal is a CounterVec with labels {method, path, status}.
// The path label holds the Gin route template (e.g. /v1/modules/:namespace/:name/:system/:version/download),
// NOT the raw URL, to prevent unbounded cardinality.
//
// Example PromQL queries:
//   - Request rate (req/s, 5 m window):  rate(http_requests_total[5m])
//   - Error rate (%):                    sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100
//   - Requests by route:                 sum by (path) (rate(http_requests_total[5m]))
//
// HTTPRequestDuration is a HistogramVec with labels {method, path} and exponential-ish
// buckets from 5 ms to 30 s.  Use histogram_quantile to compute latency percentiles.
//
// Example PromQL queries:
//   - p99 latency per route:             histogram_quantile(0.99, sum by (path, le) (rate(http_request_duration_seconds_bucket[5m])))
//   - Average latency:                   rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])
var (
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests processed, by method, route template, and status code.",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Histogram of HTTP request latencies, by method and route template.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
		[]string{"method", "path"},
	)
)

// Terraform protocol download metrics — used by module, provider, and binary mirror download handlers.
//
// ModuleDownloadsTotal is a CounterVec with labels {namespace, system} incremented
// whenever a client fetches a module download URL.  "system" is the Terraform system
// identifier (e.g. "aws", "azurerm").
//
// Example PromQL queries:
//   - Download rate by namespace:  sum by (namespace) (rate(module_downloads_total[1h]))
//   - Most popular systems:        topk(5, sum by (system) (module_downloads_total))
//
// ProviderDownloadsTotal is a CounterVec with labels {namespace, type, os, arch}
// incremented on each provider binary download redirect.  Useful for understanding
// platform popularity and build matrix coverage.
//
// Example PromQL queries:
//   - Downloads by platform:  sum by (os, arch) (rate(provider_downloads_total[1h]))
//   - Downloads by namespace: sum by (namespace) (rate(provider_downloads_total[1h]))
//
// TerraformBinaryDownloadsTotal is a CounterVec with labels {version, os, arch}
// incremented whenever a client fetches a Terraform official binary download URL via
// the binary mirror.  Useful for understanding which Terraform versions and platforms
// are most actively used.
//
// Example PromQL queries:
//   - Downloads by version:   sum by (version) (rate(terraform_binary_downloads_total[1h]))
//   - Downloads by platform:  sum by (os, arch) (rate(terraform_binary_downloads_total[1h]))
var (
	ModuleDownloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "module_downloads_total",
			Help: "Total number of module version downloads, by namespace and system.",
		},
		[]string{"namespace", "system"},
	)

	ProviderDownloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "provider_downloads_total",
			Help: "Total number of provider binary downloads, by namespace, type, OS, and arch.",
		},
		[]string{"namespace", "type", "os", "arch"},
	)

	TerraformBinaryDownloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "terraform_binary_downloads_total",
			Help: "Total number of Terraform official binary downloads from the mirror, by version, OS, and arch.",
		},
		[]string{"version", "os", "arch"},
	)
)

// Mirror sync metrics — recorded by the mirror sync background job.
//
// Business-event publish metrics — incremented by upload handlers on successful publish.
//
// ModulePublishesTotal is a CounterVec with labels {namespace, system} incremented
// when a new module version is successfully published (uploaded or ingested via SCM).
//
// ProviderPublishesTotal is a CounterVec with labels {namespace, type} incremented
// when a new provider version is published.
//
// Example PromQL queries:
//   - Publish rate by namespace:  sum by (namespace) (rate(registry_module_publishes_total[1h]))
//   - Provider publishes/day:     increase(registry_provider_publishes_total[24h])
var (
	ModulePublishesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_module_publishes_total",
			Help: "Total number of module versions published, by namespace and system.",
		},
		[]string{"namespace", "system"},
	)

	ProviderPublishesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_provider_publishes_total",
			Help: "Total number of provider versions published, by namespace and type.",
		},
		[]string{"namespace", "type"},
	)
)

// Mirror sync metrics — recorded by the mirror sync background job.
//
// MirrorSyncDuration is a HistogramVec with labels {mirror_id, mirror_type}.
// Each observation represents one complete sync cycle for a single mirror configuration.
// The mirror_id label is the UUID of the mirror configuration record and mirror_type
// is either "provider" or "terraform" to distinguish provider mirrors from binary mirrors.
//
// Example PromQL queries:
//   - p95 sync duration:  histogram_quantile(0.95, rate(mirror_sync_duration_seconds_bucket[1h]))
//   - Average sync time:  rate(mirror_sync_duration_seconds_sum[1h]) / rate(mirror_sync_duration_seconds_count[1h])
//   - Duration by type:   histogram_quantile(0.95, sum by (mirror_type, le) (rate(mirror_sync_duration_seconds_bucket[1h])))
//
// MirrorSyncErrorsTotal is a CounterVec with label {mirror_id} (UUID of the mirror
// configuration record).  An alert on rate(mirror_sync_errors_total[1h]) > 0 is
// recommended to catch upstream registry outages early.
//
// Example PromQL queries:
//   - Error rate by mirror:  rate(mirror_sync_errors_total[1h])
//   - Alert expression:      increase(mirror_sync_errors_total[30m]) > 3
var (
	MirrorSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mirror_sync_duration_seconds",
			Help:    "Duration of a single provider mirror sync operation.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"mirror_id", "mirror_type"},
	)

	MirrorSyncErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mirror_sync_errors_total",
			Help: "Total number of failed mirror sync attempts, by mirror configuration ID.",
		},
		[]string{"mirror_id"},
	)
)

// APIKeyExpiryNotificationsSentTotal is a plain Counter (no labels) incremented once
// per email successfully delivered by the api_key_expiry_notifier background job.
// A stalled counter combined with api keys approaching expiry is a useful alert signal
// for SMTP delivery failures.
//
// Example PromQL queries:
//   - Rate of notifications sent:  rate(apikey_expiry_notifications_sent_total[24h])
var APIKeyExpiryNotificationsSentTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apikey_expiry_notifications_sent_total",
		Help: "Total number of API key expiry warning emails successfully sent.",
	},
)

// RateLimitRejectionsTotal is a CounterVec with labels {tier, key_type} incremented
// each time a request is rejected (HTTP 429) by the rate limiting middleware.
// tier is "individual" or "organization"; key_type is "user", "apikey", "ip", or "org".
//
// Example PromQL queries:
//   - Rejection rate by tier:     sum by (tier) (rate(rate_limit_rejections_total[5m]))
//   - Alert on high org rejections: rate(rate_limit_rejections_total{tier="organization"}[5m]) > 10
var RateLimitRejectionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "rate_limit_rejections_total",
		Help: "Total number of requests rejected by rate limiting, by tier and key type.",
	},
	[]string{"tier", "key_type"},
)

// AppInfo is a GaugeVec that exposes build information as Prometheus labels.
// Set once at startup with value 1 so the info is available via the /metrics endpoint.
//
// Example PromQL queries:
//   - Build info:  terraform_registry_info
var AppInfo = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "terraform_registry_info",
		Help: "Application build information",
	},
	[]string{"version", "go_version", "build_date"},
)

// ModuleScanQueueDepth tracks how many modules are awaiting a security scan.
// Updated by the scanning subsystem whenever a module is enqueued or dequeued.
var ModuleScanQueueDepth = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "terraform_registry_scan_queue_depth",
		Help: "Number of modules awaiting security scan",
	},
)

// ModuleScanDuration is a HistogramVec recording the time taken for each security scan,
// labelled by scanner tool and result status.
//
// Example PromQL queries:
//   - p95 scan duration:  histogram_quantile(0.95, rate(terraform_registry_scan_duration_seconds_bucket[1h]))
var ModuleScanDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "terraform_registry_scan_duration_seconds",
		Help:    "Duration of module security scans",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"tool", "status"},
)

// JWTRevokedTokensCleanedTotal counts expired revoked JWT tokens removed during cleanup.
var JWTRevokedTokensCleanedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "terraform_registry_jwt_revoked_tokens_cleaned_total",
		Help: "Total number of expired revoked JWT tokens cleaned up",
	},
)

// AuditLogsCleanedTotal counts expired audit log entries removed by the cleanup job.
//
// Example PromQL queries:
//   - Rows cleaned per day: increase(terraform_registry_audit_logs_cleaned_total[24h])
var AuditLogsCleanedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "terraform_registry_audit_logs_cleaned_total",
		Help: "Total number of expired audit log entries deleted by the cleanup job.",
	},
)

// WebhookRetriesTotal is a CounterVec with label {outcome} tracking webhook retry
// attempts. Possible outcome values: "success", "failure", "exhausted".
//
// Example PromQL queries:
//   - Retry success rate:  rate(terraform_registry_webhook_retries_total{outcome="success"}[1h])
//   - Exhausted retries:   increase(terraform_registry_webhook_retries_total{outcome="exhausted"}[24h])
var WebhookRetriesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "terraform_registry_webhook_retries_total",
		Help: "Total webhook retry attempts by outcome.",
	},
	[]string{"outcome"},
)

// PolicyEvaluationsTotal counts policy evaluations with labels {result} where result is
// "allowed", "warn", or "blocked".
//
// Example PromQL:
//
//	rate(registry_policy_evaluations_total{result="blocked"}[5m])
var PolicyEvaluationsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "registry_policy_evaluations_total",
		Help: "Total number of policy evaluations by result (allowed, warn, blocked).",
	},
	[]string{"result"},
)

// DBOpenConnections is a Gauge that tracks the number of open connections currently
// held by the sql.DB connection pool.  It is sampled every 30 seconds by
// StartDBStatsCollector rather than per-request to avoid the overhead of sql.DB.Stats().
//
// Example PromQL queries:
//   - Pool utilisation (%): db_open_connections / <TFR_DATABASE_MAX_CONNECTIONS> * 100
//   - Alert on near-exhaustion: db_open_connections > 20  (for max_connections=25)
var DBOpenConnections = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "db_open_connections",
		Help: "Current number of open database connections in the pool.",
	},
)

// StartDBStatsCollector launches a background goroutine that samples sql.DB connection
// pool statistics every 30 seconds and updates the DBOpenConnections gauge.
func StartDBStatsCollector(db *sql.DB) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.Ping(); err != nil {
				slog.Warn("db stats collector: database unreachable, stopping collector", "error", err)
				return
			}
			DBOpenConnections.Set(float64(db.Stats().OpenConnections))
		}
	}()
}

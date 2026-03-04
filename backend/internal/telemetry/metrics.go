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
// MirrorSyncDuration is a Histogram using the default Prometheus buckets (5 ms–10 s).
// Each observation represents one complete sync cycle for a single mirror configuration.
//
// Example PromQL queries:
//   - p95 sync duration:  histogram_quantile(0.95, rate(mirror_sync_duration_seconds_bucket[1h]))
//   - Average sync time:  rate(mirror_sync_duration_seconds_sum[1h]) / rate(mirror_sync_duration_seconds_count[1h])
//
// MirrorSyncErrorsTotal is a CounterVec with label {mirror_id} (UUID of the mirror
// configuration record).  An alert on rate(mirror_sync_errors_total[1h]) > 0 is
// recommended to catch upstream registry outages early.
//
// Example PromQL queries:
//   - Error rate by mirror:  rate(mirror_sync_errors_total[1h])
//   - Alert expression:      increase(mirror_sync_errors_total[30m]) > 3
var (
	MirrorSyncDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "mirror_sync_duration_seconds",
			Help:    "Duration of a single provider mirror sync operation.",
			Buckets: prometheus.DefBuckets,
		},
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
// The goroutine exits cleanly when the database becomes unreachable (db.Ping fails),
// which happens automatically when the application shuts down and defers db.Close().
//
// Call this once, immediately after db.Connect() succeeds in main.go:
//
//	telemetry.StartDBStatsCollector(database)
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

// Package middleware provides Gin HTTP middleware components for the Terraform Registry.
// All middleware in this package is registered in internal/api/router.go before any
// route handlers so that every request is covered regardless of handler.
package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// MetricsMiddleware returns a Gin handler that records two Prometheus metrics for every
// request that passes through the router.
//
// Recorded metrics:
//   - http_requests_total{method, path, status}    — CounterVec
//   - http_request_duration_seconds{method, path}  — HistogramVec
//
// The path label is set from c.FullPath(), which returns the matched Gin route template
// (e.g. /v1/modules/:namespace/:name/:system/:version/download) rather than the raw URL.
// Requests that do not match any registered route (404/405) use the literal string
// "<no-route>" so unhandled paths do not inflate label cardinality.
//
// This middleware must be registered AFTER gin.Recovery() and RequestIDMiddleware so that
// the response status set by error handlers is captured correctly:
//
//	router.Use(gin.Recovery())
//	router.Use(RequestIDMiddleware())
//	router.Use(MetricsMiddleware())
//
// See telemetry.HTTPRequestsTotal and telemetry.HTTPRequestDuration for example PromQL
// queries and alert rules.
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Resolve the route template; fall back for 404/405 situations.
		path := c.FullPath()
		if path == "" {
			path = "<no-route>"
		}

		duration := time.Since(start).Seconds()
		method := c.Request.Method
		status := fmt.Sprintf("%d", c.Writer.Status())

		telemetry.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		telemetry.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}

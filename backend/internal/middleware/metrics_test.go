package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// collectCounter reads the current value from a CounterVec for the given label values.
// Returns -1 if no matching series is found (metric not yet observed).
func collectCounter(cv *prometheus.CounterVec, labels prometheus.Labels) float64 {
	ch := make(chan prometheus.Metric, 10)
	cv.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		match := true
		for k, want := range labels {
			found := false
			for _, lp := range dm.GetLabel() {
				if lp.GetName() == k && lp.GetValue() == want {
					found = true
					break
				}
			}
			if !found {
				match = false
				break
			}
		}
		if match {
			return dm.GetCounter().GetValue()
		}
	}
	return -1
}

// collectHistogramCount returns the sample count from a HistogramVec for the given labels.
func collectHistogramCount(hv *prometheus.HistogramVec, labels prometheus.Labels) uint64 {
	ch := make(chan prometheus.Metric, 10)
	hv.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		match := true
		for k, want := range labels {
			found := false
			for _, lp := range dm.GetLabel() {
				if lp.GetName() == k && lp.GetValue() == want {
					found = true
					break
				}
			}
			if !found {
				match = false
				break
			}
		}
		if match {
			return dm.GetHistogram().GetSampleCount()
		}
	}
	return 0
}

// newMetricsRouter builds a minimal Gin engine with MetricsMiddleware and one test route.
func newMetricsRouter(handler gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(MetricsMiddleware())
	r.GET("/test/:id", handler)
	return r
}

// ---------------------------------------------------------------------------
// MetricsMiddleware tests
// ---------------------------------------------------------------------------

func TestMetricsMiddleware_RecordsHTTPRequestsTotal(t *testing.T) {
	// Flush any stale state by noting the counter before the request.
	labels := prometheus.Labels{"method": "GET", "path": "/test/:id", "status": "200"}
	before := collectCounter(telemetry.HTTPRequestsTotal, labels)

	r := newMetricsRouter(func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test/42", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	after := collectCounter(telemetry.HTTPRequestsTotal, labels)
	if before < 0 {
		before = 0
	}
	if after-before < 1 {
		t.Errorf("http_requests_total increment not observed: before=%.0f after=%.0f", before, after)
	}
}

func TestMetricsMiddleware_RecordsHTTPRequestDuration(t *testing.T) {
	labels := prometheus.Labels{"method": "GET", "path": "/test/:id"}
	before := collectHistogramCount(telemetry.HTTPRequestDuration, labels)

	r := newMetricsRouter(func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test/99", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	after := collectHistogramCount(telemetry.HTTPRequestDuration, labels)
	if after <= before {
		t.Errorf("http_request_duration_seconds sample count did not increase: before=%d after=%d", before, after)
	}
}

func TestMetricsMiddleware_UsesRouteTemplate_NotRawURL(t *testing.T) {
	// The metric label should contain ":id" (route template) not the concrete "42".
	r := newMetricsRouter(func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test/42", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	ch := make(chan prometheus.Metric, 20)
	telemetry.HTTPRequestsTotal.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		for _, lp := range dm.GetLabel() {
			if lp.GetName() == "path" && lp.GetValue() == "/test/42" {
				t.Error("MetricsMiddleware used raw URL /test/42 as path label; expected route template /test/:id")
			}
		}
	}
}

func TestMetricsMiddleware_NoRouteLabel(t *testing.T) {
	// Requests to unregistered paths should record the sentinel "<no-route>", not a raw URL.
	r := gin.New()
	r.Use(MetricsMiddleware())
	// No routes registered → every request is a 404.

	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	found := false
	ch := make(chan prometheus.Metric, 20)
	telemetry.HTTPRequestsTotal.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		for _, lp := range dm.GetLabel() {
			if lp.GetName() == "path" && lp.GetValue() == "<no-route>" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected path label to be <no-route> for unmatched request, but it was not found")
	}
}

func TestMetricsMiddleware_RecordsErrorStatus(t *testing.T) {
	labels := prometheus.Labels{"method": "GET", "path": "/test/:id", "status": "500"}
	before := collectCounter(telemetry.HTTPRequestsTotal, labels)

	r := newMetricsRouter(func(c *gin.Context) {
		c.Status(http.StatusInternalServerError)
	})

	req := httptest.NewRequest(http.MethodGet, "/test/err", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	after := collectCounter(telemetry.HTTPRequestsTotal, labels)
	if before < 0 {
		before = 0
	}
	if after-before < 1 {
		t.Errorf("http_requests_total for status=500 not incremented: before=%.0f after=%.0f", before, after)
	}
}

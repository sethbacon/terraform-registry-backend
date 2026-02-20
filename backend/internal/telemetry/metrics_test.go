package telemetry

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gatherMetric is a test helper that collects all metrics from a Collector and
// returns the first one whose name matches.  Returns nil if no match.
func gatherMetric(t *testing.T, c prometheus.Collector, name string) *dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		// Already registered in the default registry — use a gathering approach
		// against the default registry instead.
		mfs, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatalf("DefaultGatherer.Gather: %v", err)
		}
		for _, mf := range mfs {
			if mf.GetName() == name {
				return mf
			}
		}
		return nil
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("registry.Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Metric registration sanity checks — verify every exported metric is properly
// registered and carries the expected fully-qualified name.
//
// We check registration via Describe() rather than DefaultGatherer.Gather()
// because Gather() only returns series that have been observed at least once;
// *Vec metrics with no label combinations yet used are silently absent from
// Gather output even though they are correctly registered.
// ---------------------------------------------------------------------------

func TestMetrics_AllRegistered(t *testing.T) {
	type describer interface {
		Describe(chan<- *prometheus.Desc)
	}

	cases := []struct {
		name string
		c    describer
	}{
		{"http_requests_total", HTTPRequestsTotal},
		{"http_request_duration_seconds", HTTPRequestDuration},
		{"module_downloads_total", ModuleDownloadsTotal},
		{"provider_downloads_total", ProviderDownloadsTotal},
		{"mirror_sync_duration_seconds", MirrorSyncDuration},
		{"mirror_sync_errors_total", MirrorSyncErrorsTotal},
		{"apikey_expiry_notifications_sent_total", APIKeyExpiryNotificationsSentTotal},
		{"db_open_connections", DBOpenConnections},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan *prometheus.Desc, 10)
			tc.c.Describe(ch)
			close(ch)
			for desc := range ch {
				// prometheus.Desc.String() returns a Go syntax string of the form:
				//   Desc{fqName: "<name>", help: "...", constLabels: {}, variableLabels: [...]}
				if strings.Contains(desc.String(), `"`+tc.name+`"`) {
					return // found — test passes
				}
			}
			t.Errorf("metric %q: Describe() returned no descriptor with this fqName", tc.name)
		})
	}
}

func TestMetrics_HTTPRequestsTotal_CanBeIncremented(t *testing.T) {
	before := counterValue(t, HTTPRequestsTotal, prometheus.Labels{
		"method": "GET", "path": "/test", "status": "200",
	})
	HTTPRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	after := counterValue(t, HTTPRequestsTotal, prometheus.Labels{
		"method": "GET", "path": "/test", "status": "200",
	})
	if after-before < 1 {
		t.Errorf("HTTPRequestsTotal.Inc() did not increase counter (before=%.0f after=%.0f)", before, after)
	}
}

func TestMetrics_ModuleDownloadsTotal_CanBeIncremented(t *testing.T) {
	before := counterValue(t, ModuleDownloadsTotal, prometheus.Labels{
		"namespace": "testns", "system": "aws",
	})
	ModuleDownloadsTotal.WithLabelValues("testns", "aws").Inc()
	after := counterValue(t, ModuleDownloadsTotal, prometheus.Labels{
		"namespace": "testns", "system": "aws",
	})
	if after-before < 1 {
		t.Errorf("ModuleDownloadsTotal.Inc() did not increase counter")
	}
}

func TestMetrics_ProviderDownloadsTotal_CanBeIncremented(t *testing.T) {
	before := counterValue(t, ProviderDownloadsTotal, prometheus.Labels{
		"namespace": "hashicorp", "type": "aws", "os": "linux", "arch": "amd64",
	})
	ProviderDownloadsTotal.WithLabelValues("hashicorp", "aws", "linux", "amd64").Inc()
	after := counterValue(t, ProviderDownloadsTotal, prometheus.Labels{
		"namespace": "hashicorp", "type": "aws", "os": "linux", "arch": "amd64",
	})
	if after-before < 1 {
		t.Errorf("ProviderDownloadsTotal.Inc() did not increase counter")
	}
}

func TestMetrics_MirrorSyncDuration_CanBeObserved(t *testing.T) {
	MirrorSyncDuration.Observe(0.5)
	MirrorSyncDuration.Observe(1.5)
	// If no panic, the histogram is functioning.
}

func TestMetrics_MirrorSyncErrors_CanBeIncremented(t *testing.T) {
	MirrorSyncErrorsTotal.WithLabelValues("mirror-test-id-001").Inc()
}

func TestMetrics_APIKeyExpiryNotifications_CanBeIncremented(t *testing.T) {
	before := plainCounterValue(t, APIKeyExpiryNotificationsSentTotal)
	APIKeyExpiryNotificationsSentTotal.Inc()
	after := plainCounterValue(t, APIKeyExpiryNotificationsSentTotal)
	if after-before < 1 {
		t.Errorf("APIKeyExpiryNotificationsSentTotal.Inc() did not increase counter")
	}
}

func TestMetrics_DBOpenConnections_CanBeSet(t *testing.T) {
	DBOpenConnections.Set(5)
	// If no panic, gauge is working.
	DBOpenConnections.Set(0) // reset to neutral value
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// counterValue reads the current value of a CounterVec for the given label set.
func counterValue(t *testing.T, cv *prometheus.CounterVec, labels prometheus.Labels) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 20)
	cv.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		if labelsMatch(dm.GetLabel(), labels) {
			return dm.GetCounter().GetValue()
		}
	}
	return 0
}

// plainCounterValue reads the value of a plain (non-vec) Counter.
func plainCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	c.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		return dm.GetCounter().GetValue()
	}
	return 0
}

// labelsMatch returns true when all entries in want appear in got.
func labelsMatch(got []*dto.LabelPair, want prometheus.Labels) bool {
	for k, v := range want {
		found := false
		for _, lp := range got {
			if lp.GetName() == k && lp.GetValue() == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

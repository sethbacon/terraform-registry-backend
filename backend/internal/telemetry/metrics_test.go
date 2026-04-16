package telemetry

import (
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricRegistration(t *testing.T) {
	// Importing this package triggers all promauto.New* declarations.
	// These assertions verify every exported metric var was initialized.
	tests := []struct {
		name   string
		metric prometheus.Collector
	}{
		{"HTTPRequestsTotal", HTTPRequestsTotal},
		{"HTTPRequestDuration", HTTPRequestDuration},
		{"ModuleDownloadsTotal", ModuleDownloadsTotal},
		{"ProviderDownloadsTotal", ProviderDownloadsTotal},
		{"TerraformBinaryDownloadsTotal", TerraformBinaryDownloadsTotal},
		{"MirrorSyncDuration", MirrorSyncDuration},
		{"MirrorSyncErrorsTotal", MirrorSyncErrorsTotal},
		{"APIKeyExpiryNotificationsSentTotal", APIKeyExpiryNotificationsSentTotal},
		{"RateLimitRejectionsTotal", RateLimitRejectionsTotal},
		{"AppInfo", AppInfo},
		{"ModuleScanQueueDepth", ModuleScanQueueDepth},
		{"ModuleScanDuration", ModuleScanDuration},
		{"JWTRevokedTokensCleanedTotal", JWTRevokedTokensCleanedTotal},
		{"AuditLogsCleanedTotal", AuditLogsCleanedTotal},
		{"WebhookRetriesTotal", WebhookRetriesTotal},
		{"DBOpenConnections", DBOpenConnections},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.metric == nil {
				t.Errorf("%s is nil", tt.name)
			}
		})
	}
}

func TestHTTPRequestsTotalLabels(t *testing.T) {
	// Verify we can record with the expected label set without panicking.
	HTTPRequestsTotal.WithLabelValues("GET", "/v1/modules", "200").Inc()
}

func TestHTTPRequestDurationLabels(t *testing.T) {
	HTTPRequestDuration.WithLabelValues("GET", "/v1/modules").Observe(0.042)
}

func TestModuleDownloadsTotalLabels(t *testing.T) {
	ModuleDownloadsTotal.WithLabelValues("hashicorp", "aws").Inc()
}

func TestProviderDownloadsTotalLabels(t *testing.T) {
	ProviderDownloadsTotal.WithLabelValues("hashicorp", "aws", "linux", "amd64").Inc()
}

func TestTerraformBinaryDownloadsTotalLabels(t *testing.T) {
	TerraformBinaryDownloadsTotal.WithLabelValues("1.9.0", "linux", "amd64").Inc()
}

func TestMirrorSyncDurationLabels(t *testing.T) {
	MirrorSyncDuration.WithLabelValues("mirror-1", "provider").Observe(12.5)
}

func TestMirrorSyncErrorsTotalLabels(t *testing.T) {
	MirrorSyncErrorsTotal.WithLabelValues("mirror-1").Inc()
}

func TestRateLimitRejectionsTotalLabels(t *testing.T) {
	RateLimitRejectionsTotal.WithLabelValues("individual", "apikey").Inc()
}

func TestAppInfoLabels(t *testing.T) {
	AppInfo.WithLabelValues("1.0.0", "go1.24", "2026-01-01").Set(1)
}

func TestModuleScanDurationLabels(t *testing.T) {
	ModuleScanDuration.WithLabelValues("trivy", "pass").Observe(3.2)
}

func TestWebhookRetriesTotalLabels(t *testing.T) {
	WebhookRetriesTotal.WithLabelValues("success").Inc()
}

func TestStartDBStatsCollector(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// Expect at least one Ping from the collector goroutine.
	mock.ExpectPing()

	// StartDBStatsCollector should not panic.
	StartDBStatsCollector(db)

	// We don't wait for the goroutine to tick (30s); the test just verifies
	// the function starts without error and the goroutine is launched.
}

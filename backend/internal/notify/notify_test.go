package notify

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

func TestMailer_Send_NilConfig(t *testing.T) {
	m := New(nil)
	if err := m.Send([]string{"a@example.com"}, "subj", "body"); err == nil {
		t.Error("Send with a nil config should error")
	}
}

func TestMailer_Send_EmptyHost(t *testing.T) {
	m := New(&config.SMTPConfig{})
	if err := m.Send([]string{"a@example.com"}, "subj", "body"); err == nil {
		t.Error("Send with an empty host should error")
	}
}

func TestEventConstants_MatchNotificationEventsConfigKeys(t *testing.T) {
	// These four strings are persisted (system_settings.notifications_config,
	// notification_channels.events) and must never change without a migration.
	want := map[string]string{
		"EventModulePublished":        "module_published",
		"EventApprovalPending":        "approval_pending",
		"EventCVEDetected":            "cve_detected",
		"EventScannerUpdateAvailable": "scanner_update_available",
	}
	got := map[string]string{
		"EventModulePublished":        EventModulePublished,
		"EventApprovalPending":        EventApprovalPending,
		"EventCVEDetected":            EventCVEDetected,
		"EventScannerUpdateAvailable": EventScannerUpdateAvailable,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

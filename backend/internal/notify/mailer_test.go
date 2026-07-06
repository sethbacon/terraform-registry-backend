package notify

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// TestNew_HoldsLivePointer verifies that Mailer stores the *config.SMTPConfig
// by reference: mutating the referenced struct after construction is observed
// by the Mailer, without recreating it. This is the fix that lets a runtime
// admin config update reach background jobs that built their Mailer once at
// startup.
func TestNew_HoldsLivePointer(t *testing.T) {
	cfg := &config.SMTPConfig{Host: "old.example.com", From: "old@example.com"}
	m := New(cfg)

	cfg.Host = "new.example.com"
	cfg.From = "new@example.com"

	if m.cfg.Host != "new.example.com" {
		t.Errorf("m.cfg.Host = %q, want %q (live pointer not observed)", m.cfg.Host, "new.example.com")
	}
	if m.cfg.From != "new@example.com" {
		t.Errorf("m.cfg.From = %q, want %q (live pointer not observed)", m.cfg.From, "new@example.com")
	}
}

// TestSend_NilConfig_ReturnsError verifies the nil guard at the top of Send.
func TestSend_NilConfig_ReturnsError(t *testing.T) {
	m := &Mailer{cfg: nil}

	err := m.Send([]string{"to@example.com"}, "subject", "body")
	if err == nil {
		t.Fatal("expected error for nil smtp config, got nil")
	}
	if err.Error() != "mailer: nil smtp config" {
		t.Errorf("err = %q, want %q", err.Error(), "mailer: nil smtp config")
	}
}

// TestSanitizeHeader verifies CR/LF are stripped so a crafted subject or
// recipient cannot inject additional SMTP headers (email header injection).
func TestSanitizeHeader(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "Weekly digest", "Weekly digest"},
		{"crlf header injection", "Subject\r\nBcc: victim@example.com", "SubjectBcc: victim@example.com"},
		{"lf only", "line1\nline2", "line1line2"},
		{"cr only", "a\rb", "ab"},
		{"address injection", "user@example.com\r\nRCPT TO:<evil@x>", "user@example.comRCPT TO:<evil@x>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeHeader(tt.in); got != tt.want {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Package notify is a thin adapter over the shared
// github.com/sethbacon/terraform-suite-identity/identity/notify package. All
// real logic (SMTP transport, channel fan-out, SSRF-safe delivery, secret
// redaction) lives in the shared package now — this file exists only to
// preserve this repo's existing call-site ergonomics (notify.New(cfg).Send(...),
// notify.Event{Type: notify.EventXxx}) across the many jobs/handlers that use
// them, per the cross-app notification parity effort.
package notify

import (
	"context"
	"fmt"

	identitymailer "github.com/sethbacon/terraform-suite-identity/identity/mailer"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Notifier fans an Event out to admin-configured notification channels.
// Aliased directly to the shared type: SendTest/SendTestEmail/Notify are all
// defined there.
type Notifier = identitynotify.Notifier

// NewNotifier is aliased to the shared constructor.
var NewNotifier = identitynotify.NewNotifier

// Event is a single alert-worthy occurrence to fan out to subscribed channels.
type Event = identitynotify.Event

// Options carries the small pieces of copy/identity that differ between
// consuming apps (used by the router.go NewNotifier call site).
type Options = identitynotify.Options

// Event types that can be routed to notification channels. APIKeyExpiring is
// intentionally excluded: it is a personal notice to the affected key owner,
// not an admin-facing broadcast, so it is never routed through channels. The
// string values match config.NotificationEventsConfig's JSON keys.
const (
	EventModulePublished        = "module_published"
	EventApprovalPending        = "approval_pending"
	EventCVEDetected            = "cve_detected"
	EventScannerUpdateAvailable = "scanner_update_available"
)

// ParseRecipients is aliased to the shared implementation.
var ParseRecipients = identitynotify.ParseRecipients

// Mailer sends plain-text notification emails through the shared SMTP relay
// (identity/mailer), preserving the Send(to, subject, body) method call shape
// used throughout this repo's jobs and handlers.
type Mailer struct {
	cfg *config.SMTPConfig
}

// New constructs a Mailer for the given SMTP configuration. cfg is stored by
// reference; callers should pass a pointer to the live config struct (e.g.
// &cfg.Notifications.SMTP) so runtime updates are reflected in Send.
func New(cfg *config.SMTPConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

// Send composes an RFC 5322 message and delivers it to all recipients via the
// shared identity/mailer transport.
// coverage:skip:integration-only — calls the shared mailer, which requires live SMTP.
func (m *Mailer) Send(to []string, subject, body string) error {
	if m.cfg == nil || m.cfg.Host == "" {
		return fmt.Errorf("mailer: smtp not configured")
	}
	mc := identitymailer.Config{
		Host:     m.cfg.Host,
		Port:     m.cfg.Port,
		From:     m.cfg.From,
		Username: m.cfg.Username,
		Password: m.cfg.Password,
		UseTLS:   m.cfg.UseTLS,
	}
	msg := identitynotify.BuildMessage(mc.From, to, subject, body)
	return identitymailer.Send(context.Background(), mc, to, msg)
}

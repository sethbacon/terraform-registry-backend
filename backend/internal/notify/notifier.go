// notifier.go implements Notifier, which fans a notification Event out to
// admin-configured delivery channels (webhook, Slack, Microsoft Teams, or an
// ad-hoc email recipient list) — in addition to the shared SMTP recipients
// list used directly by the CVE poll, scanner update, module-publish, and
// approval-pending notifications. Channel targets are stored encrypted (via
// the shared token cipher) and decrypted only here at send time.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

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

// Event is a single alert-worthy occurrence to fan out to subscribed channels.
type Event struct {
	Type    string
	Title   string
	Message string
}

// Notifier fans an Event out to the channels subscribed to it.
type Notifier struct {
	repo        *repositories.NotificationChannelRepository
	mailer      *Mailer
	tokenCipher *crypto.TokenCipher
	client      *http.Client
	logger      *slog.Logger
}

// NewNotifier builds a Notifier over the channel repository. mailer delivers
// "email" channel targets through the shared SMTP relay; tokenCipher decrypts
// channel targets at send time. guard applies the deployment's egress policy
// (security.egress.allowlist) to every webhook/Slack/Teams POST — the channel
// target is an admin-configured URL, so it MUST route through the same
// dial-time SSRF guard as every other outbound client in this process
// (metadata endpoints, loopback, and RFC 1918 ranges are blocked unless
// explicitly allow-listed). A nil guard yields the strict default policy.
func NewNotifier(repo *repositories.NotificationChannelRepository, mailer *Mailer, tokenCipher *crypto.TokenCipher, guard *httpsafe.Guard) *Notifier {
	return &Notifier{
		repo:        repo,
		mailer:      mailer,
		tokenCipher: tokenCipher,
		client:      httpsafe.NewClient(10*time.Second, guard),
		logger:      slog.With("component", "notify"),
	}
}

// Notify delivers ev to every enabled channel subscribed to ev.Type.
// Best-effort: a failing channel is logged and recorded but never blocks the
// others. Safe to call in a goroutine; pass a context with its own deadline.
// A nil Notifier (channels not wired up, e.g. in tests) is a no-op.
func (n *Notifier) Notify(ctx context.Context, ev Event) {
	if n == nil {
		return
	}
	channels, err := n.repo.ListEnabledForEvent(ctx, ev.Type)
	if err != nil {
		n.logger.Error("failed to load notification channels", "event", ev.Type, "error", err)
		return
	}
	for i := range channels {
		_ = n.deliver(ctx, &channels[i], ev.Title, ev.Message)
	}
}

// SendTest delivers a fixed test message to one channel (the admin UI "test" button).
func (n *Notifier) SendTest(ctx context.Context, channelID uuid.UUID) error {
	if n == nil {
		return fmt.Errorf("notifications are not available")
	}
	ch, err := n.repo.GetByID(ctx, channelID)
	if err != nil {
		return err
	}
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	return n.deliver(ctx, ch, "Test notification", "This is a test from the Terraform Registry.")
}

func (n *Notifier) deliver(ctx context.Context, ch *models.NotificationChannel, title, message string) error {
	target, err := n.decryptTarget(ch)
	if err != nil {
		n.record(ctx, ch.ID, err)
		return err
	}
	// Email targets are recipient address(es) sent through the shared relay;
	// the other types POST to the decrypted destination URL.
	var sendErr error
	if ch.Type == "email" {
		sendErr = n.sendEmail(target, title, message)
	} else {
		sendErr = n.send(ctx, ch.Type, target, title, message)
	}
	if sendErr != nil {
		n.logger.Warn("notification delivery failed", "channel", ch.Name, "error", sendErr)
		n.record(ctx, ch.ID, sendErr)
		return sendErr
	}
	n.record(ctx, ch.ID, nil)
	return nil
}

func (n *Notifier) decryptTarget(ch *models.NotificationChannel) (string, error) {
	if ch.EncryptedTarget == "" {
		return "", fmt.Errorf("channel has no target configured")
	}
	pt, err := n.tokenCipher.Open(ch.EncryptedTarget)
	if err != nil {
		return "", fmt.Errorf("decrypt channel target: %w", err)
	}
	return pt, nil
}

func (n *Notifier) send(ctx context.Context, channelType, url, title, message string) error {
	var payload any
	switch channelType {
	case "slack":
		// Slack incoming-webhook format.
		payload = map[string]string{"text": title + "\n" + message}
	case "teams":
		// Microsoft Teams via a Power Automate "Workflows" incoming webhook, which
		// expects an Adaptive Card message envelope (the classic Office 365
		// connector MessageCard format is being retired).
		payload = teamsPayload(title, message)
	default:
		// Generic JSON webhook.
		payload = map[string]any{"title": title, "message": message, "source": "terraform-registry"}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	// The URL is an admin-configured channel target (decrypted above), not user input.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		// The channel target is a capability-bearing secret (e.g. a Slack
		// incoming-webhook URL), so it is encrypted at rest and never returned
		// by the API. http.Client.Do returns a *url.Error whose message embeds
		// the full request URL; surfacing that verbatim in last_error (which
		// the admin API returns) would leak the secret. Strip the URL and keep
		// only the underlying transport error.
		return fmt.Errorf("send: %w", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("destination returned status %d", resp.StatusCode)
	}
	return nil
}

// redactURLError unwraps a *url.Error so the resulting message carries only the
// underlying transport error (e.g. "dial tcp ...: connection refused" or the
// egress-policy rejection) without the request URL, which is a capability
// secret for webhook/Slack/Teams channels.
func redactURLError(err error) error {
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// teamsPayload builds the Adaptive Card message envelope a Teams "Workflows"
// incoming webhook accepts: a single text card with a bold title over the body.
func teamsPayload(title, message string) map[string]any {
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true},
					{"type": "TextBlock", "text": message, "wrap": true},
				},
			},
		}},
	}
}

// sendEmail delivers the alert to the channel's recipient(s) through the
// shared SMTP relay — the same Mailer used by the direct CVE poll / scanner
// update / module-publish / approval-pending sends.
func (n *Notifier) sendEmail(recipients, title, message string) error {
	to, err := ParseRecipients(recipients)
	if err != nil {
		return err
	}
	return n.mailer.Send(to, title, message)
}

// ParseRecipients splits a comma-separated recipient list and validates each
// as an RFC 5322 address. Shared by the admin API (channel validation) and
// the email sender so both agree on what a valid target looks like.
func ParseRecipients(list string) ([]string, error) {
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		addr := strings.TrimSpace(p)
		if addr == "" {
			continue
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("invalid email address %q", addr)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one recipient email is required")
	}
	return out, nil
}

// record stamps the outcome of a delivery attempt. Errors are logged only —
// a failure to record delivery status must never surface as a notify failure.
func (n *Notifier) record(ctx context.Context, channelID uuid.UUID, sendErr error) {
	status, msg := "sent", ""
	if sendErr != nil {
		status, msg = "failed", sendErr.Error()
	}
	if err := n.repo.RecordDelivery(ctx, channelID, status, msg, time.Now()); err != nil {
		n.logger.Error("failed to record delivery", "channel_id", channelID, "error", err)
	}
}

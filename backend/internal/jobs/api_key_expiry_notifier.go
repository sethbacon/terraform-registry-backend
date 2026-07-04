// api_key_expiry_notifier.go implements the APIKeyExpiryNotifier background job, which
// periodically scans for API keys approaching their expiry date and sends a warning email
// to the owning user. Notification state is persisted in the database
// (expiry_notification_sent_at column) so emails are sent exactly once even across
// server restarts. The job is a no-op when notifications.enabled is false or when
// the SMTP host is not configured, so it is always safe to start regardless of
// deployment environment.
package jobs

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

// APIKeyExpiryNotifier periodically emails users whose API keys are about to expire.
type APIKeyExpiryNotifier struct {
	apiKeyRepo *repositories.APIKeyRepository
	userRepo   *repositories.UserRepository
	cfg        *config.NotificationsConfig
	mailer     *notify.Mailer
	interval   time.Duration
	stopChan   chan struct{}
}

// NewAPIKeyExpiryNotifier creates a new APIKeyExpiryNotifier.
// intervalHours controls how often the check runs (default 24h).
func NewAPIKeyExpiryNotifier(
	apiKeyRepo *repositories.APIKeyRepository,
	userRepo *repositories.UserRepository,
	cfg *config.NotificationsConfig,
) *APIKeyExpiryNotifier {
	hours := cfg.APIKeyExpiryCheckIntervalHours
	if hours <= 0 {
		hours = 24
	}
	return &APIKeyExpiryNotifier{
		apiKeyRepo: apiKeyRepo,
		userRepo:   userRepo,
		cfg:        cfg,
		mailer:     notify.New(cfg.SMTP),
		interval:   time.Duration(hours) * time.Hour,
		stopChan:   make(chan struct{}),
	}
}

// Start begins the background expiry-notification loop.
// It runs an initial check immediately, then repeats on the configured interval.
// The loop exits when ctx is cancelled or Stop() is called.
func (n *APIKeyExpiryNotifier) Start(ctx context.Context) {
	if !n.cfg.Enabled {
		log.Println("API key expiry notifier: disabled (notifications.enabled=false)")
		return
	}
	if n.cfg.SMTP.Host == "" {
		log.Println("API key expiry notifier: disabled (notifications.smtp.host not set)")
		return
	}

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	log.Printf("API key expiry notifier started (check interval: %v, warning window: %d days)",
		n.interval, n.cfg.APIKeyExpiryWarningDays)

	// Run once immediately on startup
	n.runCheck(ctx)

	for {
		select {
		case <-ticker.C:
			n.runCheck(ctx)
		case <-n.stopChan:
			log.Println("API key expiry notifier stopped")
			return
		case <-ctx.Done():
			log.Println("API key expiry notifier context cancelled")
			return
		}
	}
}

// Stop signals the background loop to exit.
func (n *APIKeyExpiryNotifier) Stop() {
	close(n.stopChan)
}

// runCheck queries for expiring keys and sends notification emails.
func (n *APIKeyExpiryNotifier) runCheck(ctx context.Context) {
	warningDays := n.cfg.APIKeyExpiryWarningDays
	if warningDays <= 0 {
		warningDays = 7
	}

	keys, err := n.apiKeyRepo.FindExpiringKeys(ctx, warningDays)
	if err != nil {
		log.Printf("API key expiry notifier: failed to query expiring keys: %v", err)
		return
	}

	if len(keys) == 0 {
		return
	}

	log.Printf("API key expiry notifier: found %d key(s) approaching expiry", len(keys))

	for _, key := range keys {
		if key.UserID == nil {
			continue
		}

		user, err := n.userRepo.GetUserByID(ctx, *key.UserID)
		if err != nil {
			log.Printf("API key expiry notifier: could not retrieve user %s for key %s: %v",
				*key.UserID, key.ID, err)
			continue
		}
		if user.Email == "" {
			continue
		}

		if err := n.sendExpiryEmail(user.Email, user.Name, key.Name, key.KeyPrefix, *key.ExpiresAt); err != nil {
			log.Printf("API key expiry notifier: failed to send email to %s: %v", user.Email, err)
			continue
		}

		if err := n.apiKeyRepo.MarkExpiryNotificationSent(ctx, key.ID); err != nil {
			log.Printf("API key expiry notifier: failed to mark notification sent for key %s: %v", key.ID, err)
		}
	}
}

// sendExpiryEmail composes and delivers a plain-text warning email via SMTP.
func (n *APIKeyExpiryNotifier) sendExpiryEmail(toEmail, userName, keyName, keyPrefix string, expiresAt time.Time) error {
	daysLeft := int(time.Until(expiresAt).Hours()/24) + 1
	if daysLeft < 0 {
		daysLeft = 0
	}

	subject := fmt.Sprintf("Action Required: API key '%s' expires in %d day(s)", keyName, daysLeft)
	body := strings.Join([]string{
		fmt.Sprintf("Hello %s,", userName),
		"",
		fmt.Sprintf("Your Terraform Registry API key '%s' (%s...) will expire on %s (%d day(s) from now).",
			keyName, keyPrefix, expiresAt.UTC().Format(time.RFC1123), daysLeft),
		"",
		"To avoid service disruption, please create a replacement key before the expiry date:",
		"  1. Log in to the Terraform Registry admin UI.",
		"  2. Navigate to Admin → API Keys.",
		"  3. Create a new key with the same scopes and update your CI/CD pipelines.",
		"  4. Delete or let the old key expire.",
		"",
		"If you no longer need this key, no action is required.",
		"",
		"— Terraform Registry",
	}, "\r\n")

	return n.mailer.Send([]string{toEmail}, subject, body)
}

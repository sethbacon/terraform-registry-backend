// webhook_retry_job.go implements a background job that retries failed webhook
// events with exponential backoff.
package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/services"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// WebhookRetryJob polls for failed webhook events and retries them with
// exponential backoff.  It follows the same Start/Stop pattern as
// ModuleScannerJob and APIKeyExpiryNotifier.
type WebhookRetryJob struct {
	cfg         *config.WebhooksConfig
	scmRepo     *repositories.SCMRepository
	moduleRepo  *repositories.ModuleRepository
	publisher   *services.SCMPublisher
	tokenCipher *crypto.TokenCipher
	stopChan    chan struct{}
}

// NewWebhookRetryJob constructs a WebhookRetryJob.
func NewWebhookRetryJob(
	cfg *config.WebhooksConfig,
	scmRepo *repositories.SCMRepository,
	moduleRepo *repositories.ModuleRepository,
	publisher *services.SCMPublisher,
	tokenCipher *crypto.TokenCipher,
) *WebhookRetryJob {
	return &WebhookRetryJob{
		cfg:         cfg,
		scmRepo:     scmRepo,
		moduleRepo:  moduleRepo,
		publisher:   publisher,
		tokenCipher: tokenCipher,
		stopChan:    make(chan struct{}),
	}
}

// Start begins the retry polling loop.  It is a no-op when MaxRetries is 0.
func (j *WebhookRetryJob) Start(ctx context.Context) {
	if j.cfg.MaxRetries == 0 {
		slog.Info("webhook retry job: disabled (webhooks.max_retries=0)")
		return
	}

	interval := time.Duration(j.cfg.RetryIntervalMins) * time.Minute
	if interval == 0 {
		interval = 2 * time.Minute
	}

	slog.Info("webhook retry job: started", "max_retries", j.cfg.MaxRetries, "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately before entering the ticker loop.
	j.runRetryCycle(ctx)

	for {
		select {
		case <-ticker.C:
			j.runRetryCycle(ctx)
		case <-j.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Stop signals the job to exit gracefully.
func (j *WebhookRetryJob) Stop() {
	select {
	case <-j.stopChan:
		// already stopped
	default:
		close(j.stopChan)
	}
}

// runRetryCycle queries for retryable webhook events and processes each one.
// coverage:skip:requires-database
func (j *WebhookRetryJob) runRetryCycle(ctx context.Context) {
	events, err := j.scmRepo.GetRetryableWebhookEvents(ctx, 10)
	if err != nil {
		slog.Error("webhook retry job: failed to query retryable events", "error", err)
		return
	}
	if len(events) == 0 {
		return
	}

	slog.Info("webhook retry job: processing retryable events", "count", len(events))
	for _, event := range events {
		j.retryOne(ctx, event)
	}
}

// retryOne attempts to re-process a single failed webhook event.
// coverage:skip:requires-database
func (j *WebhookRetryJob) retryOne(ctx context.Context, event *scm.SCMWebhookLogRecord) {
	// Load ModuleSCMRepo by its own ID (event.ModuleSCMRepoID).
	moduleSCMRepo, err := j.scmRepo.GetModuleSourceRepoByID(ctx, event.ModuleSCMRepoID)
	if err != nil || moduleSCMRepo == nil {
		j.failRetry(ctx, event, fmt.Sprintf("failed to load module SCM repo: %v", err))
		return
	}

	// Load SCMProvider.
	provider, err := j.scmRepo.GetProvider(ctx, moduleSCMRepo.SCMProviderID)
	if err != nil || provider == nil {
		j.failRetry(ctx, event, fmt.Sprintf("failed to load SCM provider: %v", err))
		return
	}

	// Decrypt the provider's client secret.
	clientSecret, err := j.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		j.failRetry(ctx, event, fmt.Sprintf("failed to decrypt client secret: %v", err))
		return
	}

	// Build connector.
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}
	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    clientSecret,
		CallbackURL:     "",
	})
	if err != nil {
		j.failRetry(ctx, event, fmt.Sprintf("failed to build connector: %v", err))
		return
	}

	// Reconstruct IncomingHook from the stored event fields.
	hook := &scm.IncomingHook{
		Type: event.EventType,
	}
	if event.EventID != nil {
		hook.ID = *event.EventID
	}
	if event.Ref != nil {
		hook.Ref = *event.Ref
	}
	if event.CommitSHA != nil {
		hook.CommitSHA = *event.CommitSHA
	}
	if event.TagName != nil {
		hook.TagName = *event.TagName
	}
	hook.Payload = event.Payload

	// Re-process the tag push.
	j.publisher.ProcessTagPush(ctx, event.ID, moduleSCMRepo, hook, connector)

	// Check the event state after processing — if it's now completed, count success.
	updated, err := j.scmRepo.GetWebhookLog(ctx, event.ID)
	if err == nil && updated != nil && updated.Processed && updated.Error == nil {
		telemetry.WebhookRetriesTotal.WithLabelValues("success").Inc()
		slog.Info("webhook retry job: retry succeeded", "event_id", event.ID, "retry_count", event.RetryCount+1)
		return
	}

	// Still failed — update retry state with exponential backoff.
	newRetryCount := event.RetryCount + 1
	lastErr := "unknown error"
	if updated != nil && updated.LastError != nil {
		lastErr = *updated.LastError
	} else if updated != nil && updated.Error != nil {
		lastErr = *updated.Error
	}

	if newRetryCount >= j.cfg.MaxRetries {
		telemetry.WebhookRetriesTotal.WithLabelValues("exhausted").Inc()
		slog.Warn("webhook retry job: retries exhausted",
			"event_id", event.ID, "retry_count", newRetryCount, "error", lastErr)
		// Set retry_count to max so the event won't be picked up again.
		_ = j.scmRepo.SetWebhookRetryState(ctx, event.ID, newRetryCount, lastErr, time.Now())
		return
	}

	telemetry.WebhookRetriesTotal.WithLabelValues("failure").Inc()
	nextRetry := time.Now().Add(calculateBackoff(newRetryCount))
	_ = j.scmRepo.SetWebhookRetryState(ctx, event.ID, newRetryCount, lastErr, nextRetry)
	slog.Info("webhook retry job: scheduled next retry",
		"event_id", event.ID, "retry_count", newRetryCount, "next_retry_at", nextRetry)
}

// failRetry records a retry failure and schedules the next attempt (or marks exhausted).
// coverage:skip:requires-database
func (j *WebhookRetryJob) failRetry(ctx context.Context, event *scm.SCMWebhookLogRecord, errMsg string) {
	newRetryCount := event.RetryCount + 1
	if newRetryCount >= j.cfg.MaxRetries {
		telemetry.WebhookRetriesTotal.WithLabelValues("exhausted").Inc()
		slog.Warn("webhook retry job: retries exhausted",
			"event_id", event.ID, "retry_count", newRetryCount, "error", errMsg)
		_ = j.scmRepo.SetWebhookRetryState(ctx, event.ID, newRetryCount, errMsg, time.Now())
		return
	}

	telemetry.WebhookRetriesTotal.WithLabelValues("failure").Inc()
	nextRetry := time.Now().Add(calculateBackoff(newRetryCount))
	_ = j.scmRepo.SetWebhookRetryState(ctx, event.ID, newRetryCount, errMsg, nextRetry)
	slog.Info("webhook retry job: scheduled next retry",
		"event_id", event.ID, "retry_count", newRetryCount, "next_retry_at", nextRetry)
}

// calculateBackoff returns the backoff duration for the given retry count.
// The formula is 2^retryCount minutes: 1m, 2m, 4m, 8m, ...
func calculateBackoff(retryCount int) time.Duration {
	return time.Minute * time.Duration(1<<uint(retryCount)) // #nosec G115 -- retryCount is bounded by maxRetries (5)
}

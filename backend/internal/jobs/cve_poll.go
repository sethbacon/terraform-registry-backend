// cve_poll.go implements the CVEPollJob background job, which periodically queries
// OSV.dev for vulnerabilities affecting Terraform/OpenTofu binaries, registered
// providers, and the configured scanner binary. Newly discovered advisories are
// written to the database and an optional notification email is sent.
package jobs

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/cve"
	"github.com/terraform-registry/terraform-registry/internal/cve/osv"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

// digestThreshold is the minimum number of new advisories that triggers a single
// digest email instead of one email per advisory.
const digestThreshold = 3

// CVEPollJob periodically queries OSV.dev and persists discovered advisories.
type CVEPollJob struct {
	matcher   *cve.Matcher
	cveRepo   *repositories.CVERepository
	auditRepo *repositories.AuditRepository
	cveCfg    *config.CVEConfig
	notifCfg  *config.NotificationsConfig
	mailer    *notify.Mailer
	stopChan  chan struct{}
	manualCh  chan struct{}
}

// NewCVEPollJob constructs and returns a CVEPollJob.
func NewCVEPollJob(
	cveRepo *repositories.CVERepository,
	auditRepo *repositories.AuditRepository,
	scanCfg *config.ScanningConfig,
	cveCfg *config.CVEConfig,
	notifCfg *config.NotificationsConfig,
) *CVEPollJob {
	endpoint := cveCfg.OSVEndpoint
	if endpoint == "" {
		endpoint = "https://api.osv.dev"
	}
	client := osv.NewClient(endpoint)
	matcher := cve.NewMatcher(client, cveRepo, scanCfg)

	return &CVEPollJob{
		matcher:   matcher,
		cveRepo:   cveRepo,
		auditRepo: auditRepo,
		cveCfg:    cveCfg,
		notifCfg:  notifCfg,
		mailer:    notify.New(&notifCfg.SMTP),
		stopChan:  make(chan struct{}),
		manualCh:  make(chan struct{}, 1),
	}
}

// Start begins the background polling loop. It runs an initial poll immediately
// on startup, then repeats on the configured interval. The loop exits when ctx
// is cancelled or Stop() is called.
func (j *CVEPollJob) Start(ctx context.Context) {
	if !j.cveCfg.Enabled {
		log.Println("[cve-poll] disabled (cve.enabled=false)")
		return
	}

	intervalHours := j.cveCfg.IntervalHours
	if intervalHours <= 0 {
		intervalHours = 24
	}
	interval := time.Duration(intervalHours) * time.Hour

	log.Printf("[cve-poll] started (interval: %v)", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately at startup.
	j.runPoll(ctx)

	for {
		select {
		case <-ticker.C:
			j.runPoll(ctx)
		case <-j.manualCh:
			log.Println("[cve-poll] manual trigger received")
			j.runPoll(ctx)
		case <-j.stopChan:
			log.Println("[cve-poll] stopped")
			return
		case <-ctx.Done():
			log.Println("[cve-poll] context cancelled")
			return
		}
	}
}

// TriggerPoll sends a non-blocking signal to run a poll immediately.
// If a poll is already queued, this call is a no-op.
func (j *CVEPollJob) TriggerPoll() {
	select {
	case j.manualCh <- struct{}{}:
	default:
	}
}

// Stop signals the background loop to exit.
func (j *CVEPollJob) Stop() {
	close(j.stopChan)
}

// runPoll executes a single CVE polling pass.
func (j *CVEPollJob) runPoll(ctx context.Context) {
	log.Println("[cve-poll] starting poll pass")
	start := time.Now()

	result, err := j.matcher.Run(ctx,
		j.cveCfg.PollBinaries,
		j.cveCfg.PollProviders,
		j.cveCfg.PollScanner,
	)
	if err != nil {
		log.Printf("[cve-poll] poll error: %v", err)
		return
	}

	elapsed := time.Since(start)
	log.Printf("[cve-poll] poll complete: %d new advisories, %d total targets affected (elapsed: %v)",
		len(result.NewAdvisories), result.Total, elapsed)

	// Emit audit log entries for new advisories.
	for _, adv := range result.NewAdvisories {
		j.emitAuditLog(ctx, adv)
	}

	// Send email notifications.
	if len(result.NewAdvisories) > 0 {
		j.sendNotifications(ctx, result.NewAdvisories)
	}
}

// emitAuditLog records a cve.discovered audit entry.
// coverage:skip:integration-only — requires a live AuditRepository (PostgreSQL).
func (j *CVEPollJob) emitAuditLog(ctx context.Context, adv models.CVEAdvisory) {
	// Determine target_kind from the advisory's first target (if any).
	targetKind := "unknown"
	if len(adv.Targets) > 0 {
		targetKind = string(adv.Targets[0].TargetKind)
	}

	resourceType := "advisory"
	advisoryID := adv.ID.String()
	al := &models.AuditLog{
		Action:       "cve.discovered",
		ResourceType: &resourceType,
		ResourceID:   &advisoryID,
		Metadata: map[string]interface{}{
			"source_id":   adv.SourceID,
			"severity":    string(adv.Severity),
			"target_kind": targetKind,
			"summary":     adv.Summary,
		},
	}
	if err := j.auditRepo.CreateAuditLog(ctx, al); err != nil {
		log.Printf("[cve-poll] failed to write audit log for advisory %s: %v", adv.SourceID, err)
	}
}

// sendNotifications delivers email notification(s) for newly discovered advisories.
// If there are >= digestThreshold new advisories, a single digest email is sent.
// Otherwise, one email is sent per advisory.
// coverage:skip:integration-only — requires live SMTP server.
func (j *CVEPollJob) sendNotifications(ctx context.Context, newAdvisories []models.CVEAdvisory) {
	if j.notifCfg == nil || !j.notifCfg.Enabled || j.notifCfg.SMTP.Host == "" {
		return
	}

	recipients := j.cveCfg.EmailRecipients
	if len(recipients) == 0 {
		// No dedicated CVE recipients configured — skip.
		return
	}

	if len(newAdvisories) >= digestThreshold {
		if err := j.sendDigestEmail(recipients, newAdvisories); err != nil {
			log.Printf("[cve-poll] failed to send digest email: %v", err)
		}
		return
	}

	for _, adv := range newAdvisories {
		if err := j.sendAdvisoryEmail(recipients, adv); err != nil {
			log.Printf("[cve-poll] failed to send advisory email for %s: %v", adv.SourceID, err)
		}
	}
}

// sendAdvisoryEmail sends a single-advisory notification to all recipients.
// coverage:skip:integration-only — requires live SMTP server.
func (j *CVEPollJob) sendAdvisoryEmail(recipients []string, adv models.CVEAdvisory) error {
	targetKind := "unknown"
	if len(adv.Targets) > 0 {
		targetKind = string(adv.Targets[0].TargetKind)
	}

	subject := fmt.Sprintf("[Security] New %s advisory: %s (%s)",
		strings.ToUpper(string(adv.Severity)), adv.SourceID, targetKind)

	lines := []string{
		fmt.Sprintf("A new %s severity advisory has been detected in your Terraform Registry.", adv.Severity),
		"",
		fmt.Sprintf("Advisory ID : %s", adv.SourceID),
		fmt.Sprintf("Severity    : %s", adv.Severity),
		fmt.Sprintf("Affects     : %s", targetKind),
		fmt.Sprintf("Summary     : %s", adv.Summary),
	}
	if len(adv.References) > 0 {
		lines = append(lines, "", "References:")
		for _, ref := range adv.References {
			lines = append(lines, "  "+ref)
		}
	}
	lines = append(lines, "", "Log in to the Terraform Registry admin UI to review affected versions.", "", "— Terraform Registry Security Monitor")

	return j.sendEmail(recipients, subject, strings.Join(lines, "\r\n"))
}

// sendDigestEmail sends a multi-advisory digest to all recipients.
// coverage:skip:integration-only — requires live SMTP server.
func (j *CVEPollJob) sendDigestEmail(recipients []string, advisories []models.CVEAdvisory) error {
	subject := fmt.Sprintf("[Security] %d new advisories detected in Terraform Registry", len(advisories))

	lines := []string{
		fmt.Sprintf("%d new security advisories have been detected in your Terraform Registry:", len(advisories)),
		"",
	}
	for _, adv := range advisories {
		targetKind := "unknown"
		if len(adv.Targets) > 0 {
			targetKind = string(adv.Targets[0].TargetKind)
		}
		lines = append(lines, fmt.Sprintf("  %-12s %-10s %-30s %s",
			strings.ToUpper(string(adv.Severity)),
			targetKind,
			adv.SourceID,
			adv.Summary,
		))
	}
	lines = append(lines, "", "Log in to the Terraform Registry admin UI to review affected versions and deprecate if necessary.", "", "— Terraform Registry Security Monitor")

	return j.sendEmail(recipients, subject, strings.Join(lines, "\r\n"))
}

// sendEmail is a thin wrapper that delegates to the shared mailer.
// coverage:skip:integration-only — calls smtp.SendMail / TLS dial; requires live SMTP.
func (j *CVEPollJob) sendEmail(to []string, subject, body string) error {
	return j.mailer.Send(to, subject, body)
}

// audit_cleanup_job.go implements a background job that periodically deletes
// audit log entries older than the configured retention period.
package jobs

import (
	"context"
	"log/slog"
	"time"

	idstore "github.com/sethbacon/terraform-suite-identity/identity/store"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// AuditCleanupJob periodically removes audit log rows older than the configured
// retention period. It follows the same Start/Stop pattern used by ModuleScannerJob.
type AuditCleanupJob struct {
	cfg       *config.AuditRetentionConfig
	auditRepo *repositories.AuditRepository
	stopChan  chan struct{}

	// sweepOpts carry the legal-hold exemption (#872). Empty means this
	// deployment sweeps without one — which router.go only allows when there
	// is no holds table to consult, because it refuses to construct this job
	// at all when a table exists but cannot be read on the sweep's connection.
	sweepOpts []idstore.AuditSweepOption
}

// NewAuditCleanupJob constructs an AuditCleanupJob.
//
// Pass idstore.WithLegalHolds(table) to exempt held rows from deletion. The
// option is variadic rather than a parameter so a deployment with no holds
// table keeps emitting the statement it always has — a NOT EXISTS against a
// table that does not exist is a parse-time error, not an empty set.
func NewAuditCleanupJob(cfg *config.AuditRetentionConfig, auditRepo *repositories.AuditRepository, sweepOpts ...idstore.AuditSweepOption) *AuditCleanupJob {
	return &AuditCleanupJob{
		cfg:       cfg,
		auditRepo: auditRepo,
		stopChan:  make(chan struct{}),
		sweepOpts: sweepOpts,
	}
}

// Name returns the human-readable job name used in logs.
func (j *AuditCleanupJob) Name() string { return "audit-cleanup" }

// Start begins the cleanup loop. It is a no-op when RetentionDays is 0 (keep forever).
// An immediate cycle is run on startup, then a 24-hour ticker drives subsequent cycles.
func (j *AuditCleanupJob) Start(ctx context.Context) error {
	if j.cfg.RetentionDays == 0 {
		slog.Info("audit cleanup: disabled (audit_retention.retention_days=0)")
		return nil
	}

	slog.Info("audit cleanup: started",
		"retention_days", j.cfg.RetentionDays,
		"batch_size", j.cfg.CleanupBatchSize,
		"legal_holds_honoured", len(j.sweepOpts) > 0)

	// Run one immediate cycle before entering the ticker loop.
	j.runCleanupCycle(ctx)

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			j.runCleanupCycle(ctx)
		case <-j.stopChan:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop signals the job to exit gracefully. It is safe to call multiple times.
func (j *AuditCleanupJob) Stop() error {
	select {
	case <-j.stopChan:
		// already stopped
	default:
		close(j.stopChan)
	}
	return nil
}

// runCleanupCycle deletes expired audit logs in batches until no more remain.
// coverage:skip:requires-database
func (j *AuditCleanupJob) runCleanupCycle(ctx context.Context) {
	cutoff := time.Now().UTC().AddDate(0, 0, -j.cfg.RetentionDays)
	batchSize := j.cfg.CleanupBatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}

	var totalDeleted int64
	for {
		deleted, err := j.auditRepo.DeleteAuditLogsBefore(ctx, cutoff, batchSize, j.sweepOpts...)
		if err != nil {
			slog.Error("audit cleanup: batch delete failed", "error", err)
			break
		}
		if deleted == 0 {
			break
		}
		totalDeleted += deleted
	}

	if totalDeleted > 0 {
		telemetry.AuditLogsCleanedTotal.Add(float64(totalDeleted))
	}
	slog.Info("audit cleanup: cycle complete", "deleted", totalDeleted, "cutoff", cutoff.Format(time.RFC3339))
}

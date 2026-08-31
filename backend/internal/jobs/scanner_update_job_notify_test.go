// scanner_update_job_notify_test.go covers notify()'s DedupKey/DedupTTL
// wiring (identity/notify#157): unlike scanner_update_job_test.go's pure-logic
// suite, this drives the real *notify.Notifier over a sqlmock database and
// asserts the exact claim query it issues -- the same technique
// identity/notify's own test suite uses for the library side of this
// primitive. A live SMTP server is never needed: the claim happens before
// notify() reaches the mailer.
package jobs

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

// dedupClaimSQL matches identity/store.NotifyDedupRepository.ClaimDedup's
// statement text.
const dedupClaimSQL = `INSERT INTO notify_dedup_claims`

// newNotifyTestJob builds a ScannerUpdateJob with a real Notifier over a
// sqlmock database, and the AutoUpdate config notify()'s TTL computation
// reads.
func newNotifyTestJob(t *testing.T, intervalHours int) (*ScannerUpdateJob, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := identitynotify.NewChannelRepository(db)
	n := notify.NewNotifier(repo, nil, nil, nil, notify.Options{})

	j := newTestScannerUpdateJob(&config.ScanningConfig{
		AutoUpdate: config.ScannerAutoUpdateConfig{IntervalHours: intervalHours},
	})
	j.SetNotifier(n)
	return j, mock
}

// TestScannerUpdateJob_Notify_DedupKeyNamesToolAndVersion is the regression
// for the fix itself: two replicas racing the same discovered version must
// claim the SAME key, or the dedup primitive protects nothing. Asserting the
// exact key text (not just "a key is set") is what would catch a future
// change that keys on something else, e.g. a random request id.
func TestScannerUpdateJob_Notify_DedupKeyNamesToolAndVersion(t *testing.T) {
	j, mock := newNotifyTestJob(t, 6)

	mock.ExpectQuery(dedupClaimSQL).
		WithArgs("scanner-update:trivy:v1.2.3", (6 * time.Hour).Seconds()).
		WillReturnError(sqlmock.ErrCancelled) // claim result irrelevant here; only the args matter
	mock.ExpectExec(`DELETE FROM notify_dedup_claims`).WillReturnResult(sqlmock.NewResult(0, 0))
	// notify() still reaches ListEnabledForEvent after a claim-store error
	// (claimDedup fails open) -- allow it to fail too; SMTP is unconfigured
	// so notify() returns before touching the mailer either way.
	mock.ExpectQuery(`FROM notification_channels`).WillReturnError(sqlmock.ErrCancelled)

	approved := models.VersionApprovalStatusApproved
	v := &models.ScannerBinaryVersion{Tool: "trivy", Version: "v1.2.3"}
	j.notify(context.Background(), v, &approved)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("notify() did not issue the expected claim query: %v", err)
	}
}

// TestScannerUpdateJob_Notify_DedupTTLDefaultsTo24h mirrors runCheck's own
// interval-default logic (IntervalHours <= 0 means 24h) so the two can't
// silently drift apart.
func TestScannerUpdateJob_Notify_DedupTTLDefaultsTo24h(t *testing.T) {
	j, mock := newNotifyTestJob(t, 0)

	mock.ExpectQuery(dedupClaimSQL).
		WithArgs("scanner-update:checkov:v3.0.0", (24 * time.Hour).Seconds()).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectExec(`DELETE FROM notify_dedup_claims`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM notification_channels`).WillReturnError(sqlmock.ErrCancelled)

	pending := models.VersionApprovalStatusPending
	v := &models.ScannerBinaryVersion{Tool: "checkov", Version: "v3.0.0"}
	j.notify(context.Background(), v, &pending)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("notify() did not default the TTL to 24h: %v", err)
	}
}

// TestScannerUpdateJob_Notify_DedupKeyIgnoresApprovalStatus proves the key
// covers the discovered occurrence, not the approval outcome: an approved
// and a pending notification for the SAME tool+version must claim the same
// key, because they are the same underlying fact from a dedup point of view.
//
// A fresh job (and so a fresh NotifyDedupRepository) per status, deliberately:
// reusing one job's dedupRepo across two notify() calls would hit its
// prune throttle on the second call, so no DELETE would be issued -- a real,
// desired effect (see maybePruneExpiredClaims) that would otherwise make this
// test about the throttle instead of about the key.
func TestScannerUpdateJob_Notify_DedupKeyIgnoresApprovalStatus(t *testing.T) {
	v := &models.ScannerBinaryVersion{Tool: "terrascan", Version: "v1.9.9"}
	approvedStatus := models.VersionApprovalStatusApproved
	pendingStatus := models.VersionApprovalStatusPending

	for _, status := range []*string{&approvedStatus, &pendingStatus} {
		j, mock := newNotifyTestJob(t, 6)
		mock.ExpectQuery(dedupClaimSQL).
			WithArgs("scanner-update:terrascan:v1.9.9", (6 * time.Hour).Seconds()).
			WillReturnError(sqlmock.ErrCancelled)
		mock.ExpectExec(`DELETE FROM notify_dedup_claims`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`FROM notification_channels`).WillReturnError(sqlmock.ErrCancelled)

		j.notify(context.Background(), v, status)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("status=%v: %v", *status, err)
		}
	}
}

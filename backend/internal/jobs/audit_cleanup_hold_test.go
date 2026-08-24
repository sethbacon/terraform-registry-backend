package jobs

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	idstore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// The sweep is the half of legal hold that can destroy something (#872). The
// predicate lives in terraform-suite-identity and is proved there against real
// PostgreSQL; what has to be proved HERE is the wiring — that the option this
// job is constructed with actually reaches the statement.
//
// Without this, removing `j.sweepOpts...` from the DeleteAuditLogsBefore call
// compiles, passes every other test in this repository, and silently returns
// the deployment to deleting held evidence. That mutation was run: nothing else
// caught it.

func newCleanupJob(t *testing.T, opts ...idstore.AuditSweepOption) (*AuditCleanupJob, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := &config.AuditRetentionConfig{RetentionDays: 30, CleanupBatchSize: 100}
	return NewAuditCleanupJob(cfg, repositories.NewAuditRepository(db), opts...), mock
}

func TestSweepCarriesTheLegalHoldExemption(t *testing.T) {
	job, mock := newCleanupJob(t, idstore.WithLegalHolds("legal_holds"))

	// Matches only a DELETE that consults the holds table. A statement without
	// the exemption fails this expectation rather than quietly deleting.
	mock.ExpectExec(`NOT EXISTS[\s\S]*legal_holds`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the sweep did not consult legal_holds: %v\n"+
			"The job was constructed WithLegalHolds, so the option must reach the statement — "+
			"otherwise held audit entries are deleted while the API reports them preserved.", err)
	}
}

// The converse, for a deployment with no holds table: the statement must not
// name one. A NOT EXISTS against a missing relation is a parse-time error, so
// this is not a stylistic preference.
func TestSweepWithoutTheExemptionNamesNoHoldsTable(t *testing.T) {
	job, mock := newCleanupJob(t)

	mock.ExpectExec(`^\s*DELETE FROM audit_logs\s+WHERE id IN \(\s+SELECT id FROM audit_logs WHERE created_at < \$1\s+ORDER BY created_at ASC LIMIT \$2\s+\)\s*$`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	job.runCleanupCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("an unexempted sweep no longer emits the plain statement: %v", err)
	}
}

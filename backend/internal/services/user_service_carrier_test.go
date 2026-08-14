package services

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// The erasure's carrier cleanup (issue #766): an erased principal's
// platform_admins row is RETIRED, with its audit intent, in one transaction.
//
// The row is what makes the floor's arithmetic honest — an inert grant that
// still looks like one is how the last real administrator gets removed against
// a count of two — so "the cleanup quietly did nothing" is a failure, not a
// tidy-up that can wait.
//
// This is also the guard on the floor predicate that call site passes. The
// carrier mechanism REFUSES a nil predicate (that is the one way a never-zero
// floor can be silently absent), so a call site that reverted to nil would fail
// before BEGIN and leave the grant behind. Every statement below is queued in
// order, and an unmet expectation is the failure.
func TestRevokePlatformAdminCarrier_RetiresTheGrantWithItsIntent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	carrier, err := platformadmin.New(db, "platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	outbox, err := auditoutbox.New(db, "audit_outbox")
	if err != nil {
		t.Fatalf("auditoutbox.New: %v", err)
	}
	svc := NewUserService(db).WithAdminFloor(nil, carrier, outbox)

	const erased = "erased-user"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM "platform_admins".*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"}).
			AddRow(erased, nil, time.Now(), nil))
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(erased).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO "audit_outbox"`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	svc.revokePlatformAdminCarrier(context.Background(), erased, "admin-user")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the erased principal's carrier grant was not retired with its audit intent: %v", err)
	}
}

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

// The user-deletion carrier cleanup (issue #766), the twin of
// services.TestRevokePlatformAdminCarrier_RetiresTheGrantWithItsIntent.
//
// platform_admins carries no foreign key to users, so nothing in the schema
// retires this row when its principal goes away; if this cleanup silently does
// nothing, the deployment keeps a row that looks like an administrator and
// elevates nobody — which is exactly what the floor has to keep skipping.
//
// It also guards the floor predicate this call site passes. The carrier
// mechanism refuses a nil predicate outright, so a call site that reverted to
// nil would fail before BEGIN and leave the grant behind; the queued statements
// below would then go unmet.
func TestRevokePlatformAdminCarrier_RetiresADeletedPrincipalsGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	h := &UserHandlers{carrier: carrierOver(t, db), outbox: outboxOver(t, db)}

	const deleted = "deleted-user"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM "platform_admins".*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows(paGrantCols).AddRow(deleted, nil, time.Now(), nil))
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(deleted).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO "audit_outbox"`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodDelete, "/users/"+deleted, nil)
	c.Set("user_id", "acting-admin")

	h.revokePlatformAdminCarrier(c, deleted)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the deleted principal's carrier grant was not retired with its audit intent: %v", err)
	}
}

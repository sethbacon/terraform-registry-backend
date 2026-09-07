package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
)

// GUARD duplicate-insert-answers-409 (issue #987).
//
// Duplicates are handled by a pre-check: read the row, answer 409 if it is
// already there. That is right in every non-racy case, and it is why a
// duplicate does not normally surface as a 500 here. But it is a
// time-of-check window -- two concurrent adds both see "not a member" and both
// insert -- and the loser's 23505 used to reach the client as a 500 with the
// constraint name in the log.
//
// This drives the race directly: the pre-check reports no membership, and the
// INSERT then fails the way Postgres fails it.

func TestAddMember_LosingTheInsertRaceIsAConflictNotAServerError(t *testing.T) {
	mock, r := newOrgScopedMemberRouter(t)
	expectOrgOwnerCeilingLookups(mock, `["modules:write"]`)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_config_id", "created_at", "updated_at"}).
			AddRow("org-1", "acme", "Acme", nil, nil, time.Now(), time.Now()))
	// The pre-check sees no membership: the other request has not committed yet.
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}))
	// By the time this insert lands, it has.
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(&pgconn.PgError{
			Code:           "23505",
			Message:        "duplicate key value violates unique constraint \"organization_members_pkey\"",
			ConstraintName: "organization_members_pkey",
		})

	body := `{"user_id":"target-1","role_template_id":"55555555-5555-5555-5555-555555555555"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/organizations/org-1/members", bytes.NewBufferString(body)))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 — losing the insert race means the member is already "+
			"there, which is the same answer the pre-check gives: body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !bytes.Contains([]byte(body), []byte("already a member")) {
		t.Fatalf("body = %s, want the same message the pre-check returns", body)
	}
	// The constraint name is an implementation detail of the schema and has no
	// business in a client response.
	if bytes.Contains(w.Body.Bytes(), []byte("organization_members_pkey")) {
		t.Fatalf("the response names the constraint: %s", w.Body.String())
	}
}

func TestAddMember_AnOrdinaryInsertFailureIsStillAServerError(t *testing.T) {
	mock, r := newOrgScopedMemberRouter(t)
	expectOrgOwnerCeilingLookups(mock, `["modules:write"]`)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_config_id", "created_at", "updated_at"}).
			AddRow("org-1", "acme", "Acme", nil, nil, time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}))
	// A foreign-key violation is not a duplicate, and must not be softened into
	// a 409 -- that would report a real fault as a routine outcome.
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(&pgconn.PgError{Code: "23503", Message: "insert violates foreign key constraint"})

	body := `{"user_id":"target-1","role_template_id":"55555555-5555-5555-5555-555555555555"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/organizations/org-1/members", bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — only a unique violation is a conflict: body=%s", w.Code, w.Body.String())
	}
}

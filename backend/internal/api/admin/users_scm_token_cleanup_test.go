package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// The user-deletion SCM token sweep (issue #883), the twin of
// TestRevokePlatformAdminCarrier_RetiresADeletedPrincipalsGrant above it.
//
// scm_oauth_tokens.user_id was declared ON DELETE CASCADE, so destroying a
// principal destroyed their SCM credentials as a side effect of the DELETE.
// Migration 000056 drops that constraint with the rest of the registry's
// foreign keys into the identity tables: scm_oauth_tokens is on the registry's
// connection while users may be in another schema or another database, so no
// constraint can span them in every topology. The cascade therefore has to be
// performed, and this is the test that it is.
//
// The rows hold access_token_encrypted and refresh_token_encrypted. Leaving
// them behind is the stranded-credential shape of #732/#736 in a family the
// credential sweeper never knew about, which is why the failure path below
// refuses the deletion rather than logging and continuing.

func scmRepoOver(t *testing.T) (*repositories.SCMRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func deleteContext(t *testing.T, userID string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/users/"+userID, nil)
	return c, rec
}

func TestDeleteSCMTokens_DestroysADeletedPrincipalsTokens(t *testing.T) {
	repo, mock := scmRepoOver(t)
	h := &UserHandlers{scmTokens: repo}
	deleted := uuid.New().String()

	// Every provider at once, not one per provider: the principal is being
	// destroyed, so a token left standing under ANY provider outlives its owner.
	mock.ExpectExec(`DELETE FROM scm_oauth_tokens WHERE user_id = \$1`).
		WithArgs(deleted).
		WillReturnResult(sqlmock.NewResult(0, 2))

	c, rec := deleteContext(t, deleted)
	if !h.deleteSCMTokens(c, deleted) {
		t.Fatalf("the sweep refused the deletion despite succeeding; response: %d %s", rec.Code, rec.Body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a deleted principal's SCM OAuth tokens were not destroyed: %v", err)
	}
}

// A failed sweep must stop the deletion. The alternative — delete the user and
// log — is exactly the orphan state: the credentials survive with no principal
// left to find them by, since nothing nulls or cascades the column any more.
func TestDeleteSCMTokens_RefusesTheDeletionWhenTheSweepFails(t *testing.T) {
	repo, mock := scmRepoOver(t)
	h := &UserHandlers{scmTokens: repo}
	deleted := uuid.New().String()

	mock.ExpectExec(`DELETE FROM scm_oauth_tokens WHERE user_id = \$1`).
		WithArgs(deleted).
		WillReturnError(errors.New("connection reset"))

	c, rec := deleteContext(t, deleted)
	if h.deleteSCMTokens(c, deleted) {
		t.Fatal("the sweep failed but the deletion was allowed to proceed, stranding live SCM credentials")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d — the caller must be told the user was NOT deleted",
			rec.Code, http.StatusInternalServerError)
	}
}

// Unwired dependency is a no-op, matching h.creds and h.carrier. Asserted so
// that "the option was not passed" never becomes a silent refusal of every
// user deletion.
func TestDeleteSCMTokens_IsANoOpWhenUnwired(t *testing.T) {
	h := &UserHandlers{}
	c, rec := deleteContext(t, uuid.New().String())
	if !h.deleteSCMTokens(c, uuid.New().String()) {
		t.Fatalf("an unwired sweep refused the deletion; response: %d %s", rec.Code, rec.Body)
	}
}

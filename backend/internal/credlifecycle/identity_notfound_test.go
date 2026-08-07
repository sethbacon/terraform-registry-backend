// identity_notfound_test.go pins what a RACED key does to a sweep's Outcome.
//
// terraform-suite-identity v0.24.0 makes RevokeAPIKey report store.ErrNotFound
// when it matches zero rows, where it previously returned nil. The org-scoped
// sweep lists keys and revokes them one at a time — it has to, because
// AuthorityRetained decides per key whether the credential over-asks — so a key
// deleted between the list and its revoke (a concurrent sweep, a user deleting
// their own key, a retry of this same sweep) surfaces as an error inside the
// loop.
//
// Outcome.Incomplete must NOT be raised for it. Incomplete is a load-bearing
// signal, not a statistic: UserHandlers.DeleteUserHandler refuses to delete the
// user when it is set, precisely because a surviving key would be promoted to an
// unattributable organization service credential. Raising Incomplete for a key
// that no longer exists would block deprovisioning on the one condition that
// proves there is nothing left to revoke.
//
// UserDeprovisioned is one set-based DELETE since identity v0.25.0 and has no
// such loop; its equivalent invariant (zero rows affected is not Incomplete)
// lives in sweeper_test.go.
package credlifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// errRevokeBoom stands in for a genuine database failure during a revoke.
var errRevokeBoom = errors.New("revoke failed")

// The org-scoped sweep carries the same guarantee, and must still revoke the
// keys that ARE present: one raced key must not stop the loop.
func TestOrgAuthorityReduced_RacedKeyDoesNotFlipIncompleteAndLoopContinues(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(akCols).
			AddRow("key-gone", "user-1", "org-1", "Raced Key", nil, "h", "tfr_a",
				[]byte(`["providers:write"]`), nil, nil, nil, time.Now(), nil).
			AddRow("key-live", "user-1", "org-1", "Live Key", nil, "h", "tfr_b",
				[]byte(`["providers:write"]`), nil, nil, nil, time.Now(), nil))
	// First key is already gone.
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-gone", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Second key must STILL be revoked — the loop may not abort or skip.
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-live", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "raced")

	if out.Incomplete {
		t.Errorf("Outcome.Incomplete = true, want false for a raced key")
	}
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1 (only the key this sweep actually deleted)", out.KeysRevoked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the loop did not reach every listed key: %v", err)
	}
}

// The counterpart that keeps the test above honest: a REAL revoke failure must
// still raise Incomplete. Without this, "never set Incomplete" would pass it.
func TestOrgAuthorityReduced_RealRevokeFailureStillReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
		WillReturnError(errRevokeBoom)

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "db down")

	if !out.Incomplete {
		t.Error("Outcome.Incomplete = false, want true: a genuine revoke failure means credentials may still be live")
	}
}

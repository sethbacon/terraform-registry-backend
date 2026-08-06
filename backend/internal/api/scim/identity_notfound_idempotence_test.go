// identity_notfound_idempotence_test.go pins the idempotence of SCIM
// deprovisioning against terraform-suite-identity v0.24.0.
//
// RemoveMember used to return nil when it matched zero rows. As of v0.24.0 it
// returns an error wrapping store.ErrNotFound, and deprovisionUser loops over
// the target's in-scope memberships calling it once per organization. Written
// naively — `if err != nil { return err }` — the loop now ABORTS on the first
// membership that is already gone.
//
// That is not a cosmetic failure. deprovisionUser owns both halves of an
// offboard: it removes memberships AND sweeps the user's JWT sessions and API
// keys (issue #736). An abort skips every later organization and the credential
// sweep entirely, so a retried or concurrently-raced deprovision leaves a user
// the IdP believes is gone holding working publish credentials — the exact
// failure the paired sweep was introduced to close.
//
// The signal is a zero rows-affected result, which is what an already-removed
// membership produces.
package scim

import (
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestSCIMDeprovision_AlreadyRemovedMembershipDoesNotAbortLoop gives the target
// TWO in-scope memberships and makes the FIRST one report "already removed".
//
// The loop must continue to the second organization and the request must
// succeed. sqlmock fails on an unexpected statement, so an abort shows up as
// the second DELETE never being issued.
func TestSCIMDeprovision_AlreadyRemovedMembershipDoesNotAbortLoop(t *testing.T) {
	r, mock := scimRouter(t)

	// The target user.
	mock.ExpectQuery("(?s)FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
			scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

	// The CALLER holds scim:provision in BOTH organizations, so both of the
	// target's memberships are in scope and the loop runs twice.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).
			AddRow(scimOrgAlpha, "Alpha", "role-1", time.Now(),
				"provisioner", "Provisioner", []byte(`["scim:provision"]`)).
			AddRow(scimOrgBeta, "Beta", "role-2", time.Now(),
				"provisioner", "Provisioner", []byte(`["scim:provision"]`)))

	// The TARGET belongs to both.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).
			AddRow(scimOrgAlpha, "Alpha", "role-1", time.Now(),
				"viewer", "Viewer", []byte(`["modules:read"]`)).
			AddRow(scimOrgBeta, "Beta", "role-2", time.Now(),
				"viewer", "Viewer", []byte(`["modules:read"]`)))

	// Alpha's membership is ALREADY gone: zero rows affected, which v0.24.0
	// reports as store.ErrNotFound.
	mock.ExpectExec("(?s)DELETE FROM organization_members").
		WithArgs(scimOrgAlpha, scimTargetID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	// Beta's membership is still present and MUST still be removed. If the
	// loop aborted on Alpha, this expectation goes unmet.
	mock.ExpectExec("(?s)DELETE FROM organization_members").
		WithArgs(scimOrgBeta, scimTargetID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scim/v2/Users/"+scimTargetID, nil))

	if w.Code >= 300 {
		t.Fatalf("status = %d, want 2xx (an already-removed membership is the desired state, not a failure): body=%s",
			w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the loop did not reach every in-scope organization: %v", err)
	}
}

// TestSCIMDeprovision_AllMembershipsAlreadyRemovedSucceeds is the fully
// idempotent replay: the whole deprovision is repeated after it already ran.
// Every removal matches zero rows and the request must still succeed, because
// the credential sweep that follows the loop is the half that still has work to
// do.
func TestSCIMDeprovision_AllMembershipsAlreadyRemovedSucceeds(t *testing.T) {
	r, mock := scimRouter(t)

	mock.ExpectQuery("(?s)FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
			scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).AddRow(
			scimOrgAlpha, "Alpha", "role-1", time.Now(),
			"provisioner", "Provisioner", []byte(`["scim:provision"]`)))

	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).AddRow(
			scimOrgAlpha, "Alpha", "role-1", time.Now(),
			"viewer", "Viewer", []byte(`["modules:read"]`)))

	mock.ExpectExec("(?s)DELETE FROM organization_members").
		WithArgs(scimOrgAlpha, scimTargetID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scim/v2/Users/"+scimTargetID, nil))

	if w.Code >= 300 {
		t.Fatalf("status = %d, want 2xx (a replayed deprovision must succeed): body=%s",
			w.Code, w.Body.String())
	}
}

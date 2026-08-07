// identity_notfound_idempotence_test.go pins the idempotence of SCIM
// deprovisioning.
//
// The original defect was a read-then-remove LOOP: deprovisionUser walked the
// target's in-scope memberships calling RemoveMember once per organization, and
// terraform-suite-identity v0.24.0 made that call report store.ErrNotFound when
// it matched zero rows. Written naively — `if err != nil { return err }` — the
// loop ABORTED on the first membership that was already gone, skipping every
// later organization AND the credential sweep, so a retried or concurrently
// raced deprovision left a user the IdP believes is gone holding working
// publish credentials.
//
// identity v0.25.0 removes the loop: RemoveAllMembershipsForUser takes the
// caller's OrgScope and does the whole strip in one statement, RETURNING the
// organizations it actually removed. The invariant is unchanged and is what
// these tests still pin — a replay must succeed and must still reach the
// credential sweep — but it is now structural rather than remembered: a bulk
// DELETE that matches zero rows is an ordinary result, so there is no
// per-membership error left for a caller to mishandle.
package scim

import (
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestSCIMDeprovision_PartiallyRemovedMembershipsStillSucceed gives the target
// TWO in-scope memberships and has the strip report only ONE of them as
// actually removed — the shape a concurrent deprovision produces.
//
// The request must succeed, and the scope handed to the credential sweep must
// be the organizations that were REALLY removed, not the ones the caller asked
// about. That is the #160 half of the contract: an organization where nothing
// was removed had no authority reduced there, so its keys stand.
func TestSCIMDeprovision_PartiallyRemovedMembershipsStillSucceed(t *testing.T) {
	r, mock := scimRouter(t)

	// The target user.
	mock.ExpectQuery("(?s)FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
			scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

	// The CALLER holds scim:provision in BOTH organizations, so both are in
	// scope and both are named in the strip's predicate.
	mock.ExpectQuery("(?s)SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).
			AddRow(scimOrgAlpha, "Alpha", "role-1", time.Now(),
				"provisioner", "Provisioner", []byte(`["scim:provision"]`)).
			AddRow(scimOrgBeta, "Beta", "role-2", time.Now(),
				"provisioner", "Provisioner", []byte(`["scim:provision"]`)))

	// Alpha's membership was already gone; only Beta's row is removed, so only
	// Beta comes back.
	mock.ExpectQuery("(?s)DELETE FROM organization_members").
		WithArgs(scimTargetID, boundScope{want: []string{scimOrgAlpha, scimOrgBeta}}).
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow(scimOrgBeta))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scim/v2/Users/"+scimTargetID, nil))

	if w.Code >= 300 {
		t.Fatalf("status = %d, want 2xx (an already-removed membership is the desired state, not a failure): body=%s",
			w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the strip did not run over every in-scope organization: %v", err)
	}
}

// TestSCIMDeprovision_AllMembershipsAlreadyRemovedSucceeds is the fully
// idempotent replay: the whole deprovision is repeated after it already ran.
// The strip removes nothing and the request must still succeed — removing zero
// rows is a legitimate no-op, not a not-found.
func TestSCIMDeprovision_AllMembershipsAlreadyRemovedSucceeds(t *testing.T) {
	r, mock := scimRouter(t)

	mock.ExpectQuery("(?s)FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
			scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

	mock.ExpectQuery("(?s)SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(scimMembershipCols).AddRow(
			scimOrgAlpha, "Alpha", "role-1", time.Now(),
			"provisioner", "Provisioner", []byte(`["scim:provision"]`)))

	mock.ExpectQuery("(?s)DELETE FROM organization_members").
		WithArgs(scimTargetID, boundScope{want: []string{scimOrgAlpha}}).
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scim/v2/Users/"+scimTargetID, nil))

	if w.Code >= 300 {
		t.Fatalf("status = %d, want 2xx (a replayed deprovision must succeed): body=%s",
			w.Code, w.Body.String())
	}
}

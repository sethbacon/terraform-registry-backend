package setup

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// Issue #766, bootstrap half: the setup wizard must establish invariant A, and
// it must be able to do so with no pre-existing administrator to check.
//
// It could not. Before PR #866 ConfigureAdmin wrote ONE thing — an
// organization_members row pointing at the `admin` role template — and nothing
// at all to platform_admins. From migration 000054 it writes exactly the
// opposite ONE thing: the carrier row, and no membership. A role template
// confers no platform-admin authority any more, so the membership would have
// been a write that did nothing — and it was the last path by which the
// platform-wide wildcard reached `organization_members` at all.
//
// That makes the carrier grant LOAD-BEARING rather than belt-and-braces, and
// the tests below say so: a failed or unwired carrier now fails setup, where it
// used to be reported beside a membership that had already conferred the
// authority.

// bootstrapEnv extends newTestEnv with the platform-admin carrier on its own
// mocked connection — the registry connection, which is where migration 000051
// puts the table and why it cannot be built from any repo the wizard already
// holds.
type bootstrapEnv struct {
	*testEnv
	carrierMock sqlmock.Sqlmock
}

func newBootstrapEnv(t *testing.T) *bootstrapEnv {
	t.Helper()
	env := newTestEnv(t)
	carrierDB, carrierMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { carrierDB.Close() })
	carrier, err := platformadmin.New(carrierDB, "platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	outbox, err := auditoutbox.New(carrierDB, "audit_outbox")
	if err != nil {
		t.Fatalf("auditoutbox.New: %v", err)
	}
	env.h.WithPlatformAdminCarrier(carrier, outbox)
	return &bootstrapEnv{testEnv: env, carrierMock: carrierMock}
}

// carrierGrantOutcome selects which of Grant's three endings to queue.
type carrierGrantOutcome int

const (
	grantLands carrierGrantOutcome = iota
	grantConflicts
	grantFails
)

// expectCarrierGrant queues the carrier grant as platformadmin.Carrier.Grant
// now performs it: in a TRANSACTION, with the audit intent written into that
// same transaction before the commit (issue #766, migration 000052).
//
// The intent write is queued explicitly rather than matched loosely, because it
// is the half migration 000052's constraint trigger enforces: a bootstrap that
// inserted the carrier row and no audit_outbox row would not commit against a
// real database, and a mock that did not expect the intent would let exactly
// that regression pass.
func expectCarrierGrant(env *bootstrapEnv, outcome carrierGrantOutcome) {
	env.carrierMock.ExpectBegin()
	switch outcome {
	case grantLands:
		env.carrierMock.ExpectQuery(`INSERT INTO "platform_admins"`).
			WillReturnRows(sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"}).
				AddRow("user-1", "user-1", time.Now(), "bootstrap administrator configured by the setup wizard"))
		env.carrierMock.ExpectExec(`INSERT INTO "audit_outbox"`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		env.carrierMock.ExpectCommit()
	case grantConflicts:
		env.carrierMock.ExpectQuery(`INSERT INTO "platform_admins"`).
			WillReturnRows(sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"}))
		env.carrierMock.ExpectRollback()
	case grantFails:
		env.carrierMock.ExpectQuery(`INSERT INTO "platform_admins"`).
			WillReturnError(errTestCarrierUnavailable)
		env.carrierMock.ExpectRollback()
	}
}

// expectBootstrapUser queues everything ConfigureAdmin does before it reaches
// the carrier, which is now only the user insert.
//
// NOTHING is queued on orgMock, and that is an assertion rather than an
// omission: sqlmock is in its default ordered mode, so a handler that went back
// to writing an organization membership would take an unexpected-query error on
// that connection instead of quietly re-establishing the carrier the rest of
// this release removed.
func expectBootstrapUser(env *bootstrapEnv) {
	env.userMock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(1, 1))
}

// TestConfigureAdmin_RecordsTheBootstrapAdminInTheCarrier is the assertion the
// missing grep would have made: the wizard writes to platform_admins.
func TestConfigureAdmin_RecordsTheBootstrapAdminInTheCarrier(t *testing.T) {
	env := newBootstrapEnv(t)
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapUser(env)
	expectCarrierGrant(env, grantLands)
	env.oidcMock.ExpectExec("UPDATE system_settings SET").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if resp := getJSON(w); resp["platform_admin_carrier_incomplete"] != nil {
		t.Fatalf("response reports platform_admin_carrier_incomplete=%v on a successful grant",
			resp["platform_admin_carrier_incomplete"])
	}
	if err := env.carrierMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the setup wizard did not write a platform_admins row: %v.\n"+
			"    The bootstrap administrator would exist only as an organization membership, and "+
			"would have no platform-admin authority at all once it derives from the carrier "+
			"(issue #766).", err)
	}
}

// TestConfigureAdmin_TreatsAnExistingGrantAsSuccess. Running the wizard twice,
// or running it on a deployment whose migration 000051 backfill already caught
// this person, must not report a failure — the row exists, which is the only
// thing invariant A cares about, and re-granting would rewrite the provenance
// the carrier exists to keep.
func TestConfigureAdmin_TreatsAnExistingGrantAsSuccess(t *testing.T) {
	env := newBootstrapEnv(t)
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapUser(env)
	// ON CONFLICT DO NOTHING ... RETURNING yields no rows, which the repository
	// reports as ErrAlreadyPlatformAdmin.
	expectCarrierGrant(env, grantConflicts)
	env.oidcMock.ExpectExec("UPDATE system_settings SET").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if resp := getJSON(w); resp["platform_admin_carrier_incomplete"] != nil {
		t.Fatal("a grant that already exists was reported as an incomplete bootstrap")
	}
}

// TestConfigureAdmin_FailsSetupWhenTheCarrierGrantDoesNot. This inverted when
// the membership went away (migration 000054).
//
// While ConfigureAdmin also wrote an admin-bearing membership, a failed carrier
// write left a deployment that still had an administrator, so it was reported
// beside a 200 and the operator repaired it later. Now the carrier is the only
// thing this handler grants: a failed write leaves NO administrator and no API
// route able to create one, which is the lockout the rest of this release
// exists to prevent. Setup has not been marked complete at this point, so the
// operator can retry — a clean 200 is what would make it unrecoverable.
func TestConfigureAdmin_FailsSetupWhenTheCarrierGrantDoesNot(t *testing.T) {
	env := newBootstrapEnv(t)
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapUser(env)
	expectCarrierGrant(env, grantFails)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — the carrier is the only grant this wizard makes, so a failed "+
			"one leaves the deployment with no administrator at all: %s", w.Code, w.Body.String())
	}
	// The pending-admin email is NOT recorded: nothing was queued for it, so a
	// handler that carried on past the failure would take an unexpected-query
	// error and this test would fail on that too.
	if err := env.oidcMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations after a failed bootstrap: %v", err)
	}
}

// TestConfigureAdmin_FailsSetupWithAnUnwiredCarrier. A deployment whose router
// never passed the carrier cannot bootstrap invariant A at all, and must say so
// with a failure rather than a flagged success.
func TestConfigureAdmin_FailsSetupWithAnUnwiredCarrier(t *testing.T) {
	env := newTestEnv(t) // no WithPlatformAdminCarrier
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapUser(&bootstrapEnv{testEnv: env})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// errTestCarrierUnavailable stands in for the registry connection being down
// while the identity connection is up — the split-brain the carrier's
// cross-connection placement makes possible.
var errTestCarrierUnavailable = &carrierUnavailableError{}

type carrierUnavailableError struct{}

func (*carrierUnavailableError) Error() string { return "registry connection unavailable" }

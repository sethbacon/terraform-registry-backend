package setup

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #766, bootstrap half: the setup wizard must establish invariant A, and
// it must be able to do so with no pre-existing administrator to check.
//
// It could not. Until this change ConfigureAdmin wrote ONE thing — an
// organization_members row pointing at the `admin` role template — and nothing
// at all to platform_admins. That is invisible today, because effective
// platform-admin is `carrier OR the role-template scope union` and the union
// answers. It stops being invisible the moment authority derives from the
// carrier alone: a deployment installed after migration 000051 (whose backfill
// runs once, at migration time, over rows that do not yet exist) would have a
// bootstrap administrator with no carrier row, and nobody able to administer
// it.
//
// `grep -rn platform_admins internal/api/setup/` returned nothing before this
// change, which is the whole finding.

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
	env.h.WithPlatformAdminCarrier(
		repositories.NewPlatformAdminRepository(carrierDB), audit.NewOutbox(carrierDB))
	return &bootstrapEnv{testEnv: env, carrierMock: carrierMock}
}

// carrierGrantOutcome selects which of Grant's three endings to queue.
type carrierGrantOutcome int

const (
	grantLands carrierGrantOutcome = iota
	grantConflicts
	grantFails
)

// expectCarrierGrant queues the carrier grant as PlatformAdminRepository.Grant
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
		env.carrierMock.ExpectQuery("INSERT INTO platform_admins").
			WillReturnRows(sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"}).
				AddRow("user-1", "user-1", time.Now(), "bootstrap administrator configured by the setup wizard"))
		env.carrierMock.ExpectExec("INSERT INTO audit_outbox").
			WillReturnResult(sqlmock.NewResult(1, 1))
		env.carrierMock.ExpectCommit()
	case grantConflicts:
		env.carrierMock.ExpectQuery("INSERT INTO platform_admins").
			WillReturnRows(sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"}))
		env.carrierMock.ExpectRollback()
	case grantFails:
		env.carrierMock.ExpectQuery("INSERT INTO platform_admins").
			WillReturnError(errTestCarrierUnavailable)
		env.carrierMock.ExpectRollback()
	}
}

// expectBootstrapMembership queues everything ConfigureAdmin does before it
// reaches the carrier.
func expectBootstrapMembership(env *bootstrapEnv) {
	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))
	env.userMock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(1, 1))
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").WillReturnResult(sqlmock.NewResult(1, 1))
}

// TestConfigureAdmin_RecordsTheBootstrapAdminInTheCarrier is the assertion the
// missing grep would have made: the wizard writes to platform_admins.
func TestConfigureAdmin_RecordsTheBootstrapAdminInTheCarrier(t *testing.T) {
	env := newBootstrapEnv(t)
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapMembership(env)
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

	expectBootstrapMembership(env)
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

// TestConfigureAdmin_ReportsAFailedCarrierGrantWithoutFailingSetup. The
// membership already makes this person an administrator today, so failing the
// wizard would leave a half-configured deployment whose only recovery is the
// SQL the management API exists to replace. It must be VISIBLE, though — a
// clean 200 over a missing carrier row is the silent half-bootstrap.
func TestConfigureAdmin_ReportsAFailedCarrierGrantWithoutFailingSetup(t *testing.T) {
	env := newBootstrapEnv(t)
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapMembership(env)
	expectCarrierGrant(env, grantFails)
	env.oidcMock.ExpectExec("UPDATE system_settings SET").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the membership grant succeeded, so setup must not fail: %s",
			w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["platform_admin_carrier_incomplete"] != true {
		t.Fatalf("platform_admin_carrier_incomplete = %v, want true — a failed carrier grant must "+
			"be visible to the operator who has to repair it", resp["platform_admin_carrier_incomplete"])
	}
}

// TestConfigureAdmin_ReportsAnUnwiredCarrier. A deployment whose router never
// passed the carrier bootstraps only half of invariant A, and must say so
// rather than report a clean success.
func TestConfigureAdmin_ReportsAnUnwiredCarrier(t *testing.T) {
	env := newTestEnv(t) // no WithPlatformAdminCarrier
	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	expectBootstrapMembership(&bootstrapEnv{testEnv: env})
	env.oidcMock.ExpectExec("UPDATE system_settings SET").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", jsonBody(map[string]string{"email": "admin@example.com"})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if resp := getJSON(w); resp["platform_admin_carrier_incomplete"] != true {
		t.Fatalf("platform_admin_carrier_incomplete = %v, want true", resp["platform_admin_carrier_incomplete"])
	}
}

// errTestCarrierUnavailable stands in for the registry connection being down
// while the identity connection is up — the split-brain the carrier's
// cross-connection placement makes possible.
var errTestCarrierUnavailable = &carrierUnavailableError{}

type carrierUnavailableError struct{}

func (*carrierUnavailableError) Error() string { return "registry connection unavailable" }

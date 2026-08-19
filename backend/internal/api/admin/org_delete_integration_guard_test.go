package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// GUARD org-owns-integrations (issue #899).
//
// Migration 000056 dropped scm_providers.organization_id and
// mirror_configurations.organization_id, both ON DELETE CASCADE, because no
// foreign key can span the identity topologies (issue #883). Those two were the
// sole mechanism holding their invariant, so after the drop
// DELETE /organizations/:id left behind:
//
//   - an SCM provider holding client_secret_encrypted and webhook_secret, which
//     the UNAUTHENTICATED webhook endpoint keeps honouring with no organization
//     check at all; and
//   - a mirror configuration that keeps syncing on schedule, stamping every
//     provider it creates with the dead organization id, invisible to every
//     non-platform administrator because tenantscope.Permits denies a foreign
//     organization.
//
// The handler now REFUSES rather than sweeping. These tests pin both refusals,
// both of their fail-closed error paths, and — the half that a guard test
// usually forgets — that a clean organization still deletes.
//
// The two connections are separate sqlmocks ON PURPOSE, matching production:
// organizations are read on the identity connection, scm_providers and
// mirror_configurations on the registry's own. A single mock would hide a
// wiring mistake that only appears once identity moves.

const guardOrgUUID = "9f8e7d6c-5b4a-4321-8fed-cba987654321"

func guardOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow(guardOrgUUID, "acme", "Acme", nil, nil, time.Now(), time.Now())
}

// newOrgRouterWithIntegrationGuards builds the delete route with the two
// registry-connection repositories wired, and returns the identity mock and the
// registry mock in that order.
func newOrgRouterWithIntegrationGuards(t *testing.T) (sqlmock.Sqlmock, sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()

	identityDB, identityMock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock (identity): %v", err)
	}
	t.Cleanup(func() { identityDB.Close() })

	registryDB, registryMock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock (registry): %v", err)
	}
	t.Cleanup(func() { registryDB.Close() })

	registrySqlx := sqlx.NewDb(registryDB, "sqlmock")

	h := NewOrganizationHandlers(&config.Config{}, identityDB,
		repositories.NewNamespaceClaimRepository(identityDB), nil).
		WithOrgIntegrationGuards(
			repositories.NewSCMRepository(registrySqlx),
			repositories.NewMirrorRepository(registrySqlx),
		)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("scopes", []string{string(auth.ScopeAdmin)}) })
	r.DELETE("/organizations/:id", h.DeleteOrganizationHandler())
	return identityMock, registryMock, r
}

// expectPassesExistingGuards queues the two refusals that already existed, both
// answering "nothing here", so the request reaches the new ones.
func expectPassesExistingGuards(identityMock sqlmock.Sqlmock) {
	identityMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(guardOrgRow())
	identityMock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	identityMock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
}

func deleteGuardOrg(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/"+guardOrgUUID, nil))
	return w
}

// An organization that still owns an SCM provider must not be deletable.
//
// No DELETE FROM organizations is queued on the identity mock, so if the guard
// stopped refusing, the handler would reach a statement sqlmock has no
// expectation for and answer 500 — this asserting 409 is itself the proof that
// the row survived.
func TestDeleteOrganization_BlockedBySCMProviders(t *testing.T) {
	identityMock, registryMock, r := newOrgRouterWithIntegrationGuards(t)
	expectPassesExistingGuards(identityMock)
	registryMock.ExpectQuery("SELECT COUNT.*FROM scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := deleteGuardOrg(r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SCM providers") {
		t.Errorf("body does not name the blocking resource: %s", w.Body.String())
	}
	if err := identityMock.ExpectationsWereMet(); err != nil {
		t.Errorf("identity expectations not met: %v", err)
	}
	if err := registryMock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry expectations not met: %v", err)
	}
}

// Same for a mirror configuration, reached only once the SCM count is clean —
// which also pins the order, so a deployment whose only asset is a mirror gets
// the message about mirrors.
func TestDeleteOrganization_BlockedByMirrorConfigurations(t *testing.T) {
	identityMock, registryMock, r := newOrgRouterWithIntegrationGuards(t)
	expectPassesExistingGuards(identityMock)
	registryMock.ExpectQuery("SELECT COUNT.*FROM scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	registryMock.ExpectQuery("SELECT COUNT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	w := deleteGuardOrg(r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mirror configurations") {
		t.Errorf("body does not name the blocking resource: %s", w.Body.String())
	}
	if err := registryMock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry expectations not met: %v", err)
	}
}

// A count that cannot be taken must not be read as "nothing there". This is the
// direction that matters: the registry connection is a different database from
// the identity one in the topology this whole issue comes from, so it can be
// down while organizations reads fine.
func TestDeleteOrganization_SCMProviderCountDBError(t *testing.T) {
	identityMock, registryMock, r := newOrgRouterWithIntegrationGuards(t)
	expectPassesExistingGuards(identityMock)
	registryMock.ExpectQuery("SELECT COUNT.*FROM scm_providers").
		WillReturnError(errDB)

	w := deleteGuardOrg(r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
	// Pinned to the guard's own message: a 500 from any earlier step would
	// satisfy the status code alone and let this pass for the wrong reason.
	if !strings.Contains(w.Body.String(), "Failed to check organization SCM providers") {
		t.Errorf("500 did not come from the SCM guard: %s", w.Body.String())
	}
}

func TestDeleteOrganization_MirrorCountDBError(t *testing.T) {
	identityMock, registryMock, r := newOrgRouterWithIntegrationGuards(t)
	expectPassesExistingGuards(identityMock)
	registryMock.ExpectQuery("SELECT COUNT.*FROM scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	registryMock.ExpectQuery("SELECT COUNT.*FROM mirror_configurations").
		WillReturnError(errDB)

	w := deleteGuardOrg(r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Failed to check organization mirror configurations") {
		t.Errorf("500 did not come from the mirror guard: %s", w.Body.String())
	}
}

// The other half of a refusal: an organization owning neither still deletes.
// Without this, "always 409" would pass every test above.
func TestDeleteOrganization_SucceedsWithNoIntegrations(t *testing.T) {
	identityMock, registryMock, r := newOrgRouterWithIntegrationGuards(t)
	expectPassesExistingGuards(identityMock)
	registryMock.ExpectQuery("SELECT COUNT.*FROM scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	registryMock.ExpectQuery("SELECT COUNT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	identityMock.ExpectExec("DELETE FROM organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := deleteGuardOrg(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := identityMock.ExpectationsWereMet(); err != nil {
		t.Errorf("identity expectations not met (the delete never ran): %v", err)
	}
	if err := registryMock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry expectations not met (a count was skipped): %v", err)
	}
}

// An organization id the repositories cannot key on fails closed. Counting zero
// of everything for an unparsable id is exactly the silent pass this guard
// exists to prevent.
func TestDeleteOrganization_IntegrationGuardNonUUIDOrgID(t *testing.T) {
	identityMock, _, r := newOrgRouterWithIntegrationGuards(t)
	identityMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows(orgCols).
			AddRow("org-1", "acme", "Acme", nil, nil, time.Now(), time.Now()))
	identityMock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	identityMock.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Failed to check organization integrations") {
		t.Errorf("500 did not come from the guard's id parse: %s", w.Body.String())
	}
}

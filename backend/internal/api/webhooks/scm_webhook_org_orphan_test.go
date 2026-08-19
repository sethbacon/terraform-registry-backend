package webhooks

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/sethbacon/terraform-suite-identity/identity/pgxparam"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// GUARD webhook-provider-org-exists (issue #899).
//
// This is the serious half of the issue. /webhooks/scm/:link/:secret is the
// only UNAUTHENTICATED route in the service that acts on a stored credential:
// it loads the SCM provider by id from the payload URL and verifies the
// delivery against provider.WebhookSecret, on the row's own authority.
//
// scm_providers.organization_id was ON DELETE CASCADE until migration 000056
// (issue #883), so the row could not outlive its organization and the question
// never had to be asked. It can now — in every topology — and a repository
// still pointing at the registry would otherwise keep triggering module
// publishes into a tenant that no longer exists, indefinitely, using a
// client secret and a webhook secret nobody can see in the UI any more.
//
// DeleteOrganizationHandler refuses to create such a row (GUARD
// org-owns-integrations), but these are the orphans that already exist, and the
// ones no registry handler is involved in at all: organizations may live in a
// separate database with a lifecycle this service never observes.

func newWebhookSQLMock() (*sql.DB, sqlmock.Sqlmock, error) {
	return sqlmock.New(sqlmock.ValueConverterOption(pgxparam.Converter{}))
}

var orphanOrgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}

// orphanProviderRow is sampleProviderRow with a caller-chosen organization_id,
// which is the column under test here.
func orphanProviderRow(t *testing.T, id, orgID uuid.UUID, providerType string) *sqlmock.Rows {
	t.Helper()
	baseURL := "https://bitbucket.example.com"
	encryptedSecret, err := testTokenCipher(t).Seal("test-client-secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sqlmock.NewRows(scmProviderCols).AddRow(
		id, orgID, providerType, "Test Provider",
		&baseURL, nil, "client-id",
		encryptedSecret, "",
		true, time.Now(), time.Now(),
	)
}

// newWebhookRouterWithOrgLookup wires the real identity-connection repository
// through WithOrganizationExistence, so the production closure is what these
// tests drive rather than a stand-in. Returns the registry mock and the
// identity mock in that order.
func newWebhookRouterWithOrgLookup(t *testing.T) (sqlmock.Sqlmock, sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()

	registryDB, registryMock, err := newWebhookSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { registryDB.Close() })

	identityDB, identityMock, err := newWebhookSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { identityDB.Close() })

	h := NewSCMWebhookHandler(
		repositories.NewSCMRepository(sqlx.NewDb(registryDB, "sqlmock")),
		nil, // publisher: every test here stops before publishing
		testTokenCipher(t),
	).WithOrganizationExistence(repositories.NewOrganizationRepository(identityDB))

	r := gin.New()
	r.POST("/webhooks/scm/:module_source_repo_id/:secret", h.HandleWebhook)
	return registryMock, identityMock, r
}

func expectLinkAndProvider(registryMock sqlmock.Sqlmock, t *testing.T, providerID, orgID uuid.UUID) {
	t.Helper()
	registryMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE id").
		WillReturnRows(sampleModuleSourceRepoRowWithURL(providerID,
			"https://registry.example.com/webhooks/scm/"+webhookTestUUID+"/secret123"))
	registryMock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(orphanProviderRow(t, providerID, orgID, "bitbucket_dc"))
}

func postWebhook(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))
	return w
}

// An SCM provider whose organization is gone is answered exactly as a provider
// that does not exist — the same 404, so an anonymous caller learns nothing new
// — and the handler stops before the client secret is ever decrypted.
func TestWebhook_RefusesProviderWhoseOrganizationIsGone(t *testing.T) {
	registryMock, identityMock, r := newWebhookRouterWithOrgLookup(t)
	providerID, orgID := uuid.New(), uuid.New()
	expectLinkAndProvider(registryMock, t, providerID, orgID)
	identityMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID.String()).
		WillReturnRows(sqlmock.NewRows(orphanOrgCols)) // no such organization

	w := postWebhook(r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (orphaned provider must not be honoured): body=%s",
			w.Code, w.Body.String())
	}
	if err := identityMock.ExpectationsWereMet(); err != nil {
		t.Errorf("the organization was never looked up: %v", err)
	}
	if err := registryMock.ExpectationsWereMet(); err != nil {
		t.Errorf("registry expectations not met: %v", err)
	}
}

// A lookup that fails is NOT read as "probably still there". On this route that
// would mean honouring a credential on the strength of a database error, with
// no principal anywhere in the request.
func TestWebhook_OrganizationLookupErrorFailsClosed(t *testing.T) {
	registryMock, identityMock, r := newWebhookRouterWithOrgLookup(t)
	providerID, orgID := uuid.New(), uuid.New()
	expectLinkAndProvider(registryMock, t, providerID, orgID)
	identityMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(webhookErrDB)

	w := postWebhook(r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail closed): body=%s", w.Code, w.Body.String())
	}
}

// The other half: a live organization must still be served. bitbucket_dc builds
// a connector without OAuth credentials, and the fixture's webhook_secret is
// empty, so a request with no signature reaches 401 — which is proof the guard
// let it through rather than proof of anything about signatures.
func TestWebhook_ProceedsWhenOrganizationLives(t *testing.T) {
	registryMock, identityMock, r := newWebhookRouterWithOrgLookup(t)
	providerID, orgID := uuid.New(), uuid.New()
	expectLinkAndProvider(registryMock, t, providerID, orgID)
	identityMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows(orphanOrgCols).
			AddRow(orgID.String(), "acme", "Acme", nil, nil, time.Now(), time.Now()))

	w := postWebhook(r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (guard must not block a live organization): body=%s",
			w.Code, w.Body.String())
	}
}

// A provider with no organization at all is the single-tenant deployment: the
// column is nullable and scans to uuid.Nil, it is owned by nobody, and there is
// nothing to outlive. No identity query is queued, so a check made here would
// fail the request instead of passing it.
func TestWebhook_SingleTenantProviderSkipsOrganizationCheck(t *testing.T) {
	registryMock, identityMock, r := newWebhookRouterWithOrgLookup(t)
	providerID := uuid.New()
	expectLinkAndProvider(registryMock, t, providerID, uuid.Nil)

	w := postWebhook(r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (unowned provider must not be blocked): body=%s",
			w.Code, w.Body.String())
	}
	if err := identityMock.ExpectationsWereMet(); err != nil {
		t.Errorf("identity expectations not met: %v", err)
	}
}

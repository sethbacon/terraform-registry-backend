package admin

import (
	"bytes"
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
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

// scmProvCols matches the SCMProvider struct db tags for SELECT * FROM scm_providers
var scmProvCols = []string{
	"id", "organization_id", "provider_type", "name",
	"base_url", "tenant_id", "client_id",
	"client_secret_encrypted", "webhook_secret",
	"is_active", "created_at", "updated_at",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleSCMProviderRow() *sqlmock.Rows {
	return sqlmock.NewRows(scmProvCols).AddRow(
		knownUUID, "00000000-0000-0000-0000-000000000000", "github", "test-github",
		nil, nil, "client-id",
		"encrypted-secret", "webhook-secret",
		true, time.Now(), time.Now(),
	)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func testTokenCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	tc, err := crypto.NewTokenCipher(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

func newSCMProviderRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	orgRepo := repositories.NewOrganizationRepository(db)
	cipher := testTokenCipher(t)
	h := NewSCMProviderHandlers(&config.Config{}, scmRepo, orgRepo, cipher)

	r := gin.New()
	// These routes sit behind AuthMiddleware + RequireScope in production, so an
	// unauthenticated principal can never reach the handler. Default the test
	// router to a platform admin: it keeps each existing test exercising the
	// behaviour it was written for, while tenant scoping for non-admins is
	// covered separately (issue #719).
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", "test-admin")
	})
	r.POST("/scm-providers", h.CreateProvider)
	r.GET("/scm-providers", h.ListProviders)
	r.GET("/scm-providers/:id", h.GetProvider)
	r.PUT("/scm-providers/:id", h.UpdateProvider)
	r.DELETE("/scm-providers/:id", h.DeleteProvider)
	return mock, r
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

func TestSCMCreate_MissingBody(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{}))) // missing required fields

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_InvalidProviderType(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "invalid-type",
			"name":          "test",
			"client_id":     "cid",
			"client_secret": "csec",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_MissingClientID(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test",
			// no client_id
			"client_secret": "csec",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_MissingClientSecret(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test",
			"client_id":     "cid",
			// no client_secret
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_Success(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	expectOrganizationByID(mock, knownUUID)
	// GetProviderByOrgAndName — no existing provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "client-id",
			"client_secret": "client-secret",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	expectOrganizationByID(mock, knownUUID)
	// GetProviderByOrgAndName — DB error
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "client-id",
			"client_secret": "client-secret",
		})), knownUUID))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSCMCreate_DuplicateConflict(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	expectOrganizationByID(mock, knownUUID)
	// GetProviderByOrgAndName — returns existing provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sampleSCMProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "client-id",
			"client_secret": "client-secret",
		})), knownUUID))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_InvalidJSON(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		bytes.NewBufferString("{invalid json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_PATBased_MissingBaseURL(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "test-bdc",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_PATBased_EmptyBaseURL(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "test-bdc",
			"base_url":      "",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_PATBased_Success(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	expectOrganizationByID(mock, knownUUID)
	// GetProviderByOrgAndName — no existing provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "test-bdc",
			"base_url":      "https://bitbucket.example.com",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SSRF: private / cloud-metadata base_url rejected at save
// ---------------------------------------------------------------------------

func TestSCMCreate_RejectsCloudMetadataBaseURL(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "test-bdc",
			"base_url":      "http://169.254.169.254/",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_RejectsPrivateBaseURL_OAuthMode(t *testing.T) {
	// base_url is validated regardless of auth mode (e.g. a GitHub Enterprise
	// Server instance configured with the default oauth_user auth mode).
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-ghe",
			"client_id":     "cid",
			"client_secret": "csec",
			"base_url":      "http://10.1.2.3/",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMUpdate_RejectsPrivateBaseURL(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"base_url": "http://127.0.0.1:8080/"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_AllowlistedBaseURLSucceeds(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	orgRepo := repositories.NewOrganizationRepository(db)
	cipher := testTokenCipher(t)
	h := NewSCMProviderHandlers(&config.Config{}, scmRepo, orgRepo, cipher).
		WithEgressGuard(httpsafe.MustGuard("10.5.0.0/16"))

	r := gin.New()
	// Platform administrator: these routes sit behind AuthMiddleware +
	// RequireScope in production, and since #719 the create axis resolves a
	// tenant scope before choosing a target organization (GUARD
	// scm-create-target-org). A platform admin's scope spans every
	// organization, so these tests name the target through the organization
	// picker's X-Organization-Id header (#1011) and prime the existence check
	// the handler makes on an admin's choice.
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", "test-admin")
	})
	r.POST("/scm-providers", h.CreateProvider)

	expectOrganizationByID(mock, knownUUID)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "internal-bdc",
			"base_url":      "https://10.5.1.1/",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// A platform admin's scope spans every organization, so a create that names
// none is refused as ambiguous — the default-organization fallback that used
// to answer this request is gone (#1011). No statement is issued.
func TestSCMCreate_AdminMustNameOrganization(t *testing.T) {
	mock, r := newSCMProviderRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "X-Organization-Id") {
		t.Errorf("the refusal must tell the caller how to name the organization: body=%s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no statement may be issued for a refused create: %v", err)
	}
}

func TestSCMCreate_OrganizationLookupDBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})), knownUUID))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// A platform admin naming an organization that does not exist gets the
// non-member's 403, so the response cannot be used to probe organization ids.
func TestSCMCreate_AdminUnknownOrganizationRefused(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	expectOrganizationByIDMissing(mock, knownUUID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})), knownUUID))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestSCMCreate_WithExplicitOrgID(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	// Explicit organization_id: a platform admin's choice is verified to exist.
	expectOrganizationByID(mock, knownUUID)
	// GetProviderByOrgAndName — no existing provider
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type":   "github",
			"name":            "test-github",
			"client_id":       "cid",
			"client_secret":   "csec",
			"organization_id": knownUUID,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListProviders
// ---------------------------------------------------------------------------

func TestSCMList_All(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers ORDER BY").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestSCMList_InvalidOrgID(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers?organization_id=not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSCMList_FilterByOrg(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers?organization_id="+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestSCMList_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

func TestSCMGet_InvalidID(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSCMGet_NotFound(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestSCMGet_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSCMGet_Success(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

func TestSCMUpdate_InvalidID(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/not-a-uuid",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSCMUpdate_NotFound(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "new-name"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestSCMUpdate_Success(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	mock.ExpectExec("UPDATE scm_providers SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	// Update name only - no ClientSecret means tokenCipher.Seal not called
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated-github"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMUpdate_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	mock.ExpectExec("UPDATE scm_providers SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated-github"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSCMUpdate_InvalidBody(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		bytes.NewBufferString("{invalid json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMUpdate_GetProviderDBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "new-name"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMUpdate_WithClientSecret(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	mock.ExpectExec("UPDATE scm_providers SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	// Updating client_secret exercises the tokenCipher.Seal path during update
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{"client_secret": "new-secret"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMUpdate_AllFields(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRow())
	mock.ExpectExec("UPDATE scm_providers SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/scm-providers/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":           "updated-github",
			"base_url":       "https://github.example.com",
			"tenant_id":      "tenant-123",
			"client_id":      "new-client-id",
			"client_secret":  "new-client-secret",
			"webhook_secret": "new-webhook-secret",
			"is_active":      false,
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

func TestSCMDelete_InvalidID(t *testing.T) {
	_, r := newSCMProviderRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scm-providers/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSCMDelete_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectExec("DELETE FROM scm_providers WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scm-providers/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSCMDelete_Success(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectExec("DELETE FROM scm_providers WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scm-providers/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
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
	// GetDefaultOrganization lookup (required — CreateProvider returns 400 if org not found)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow(knownUUID, "default", "Default", nil, nil, time.Now(), time.Now()))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "client-id",
			"client_secret": "client-secret",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_DBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	// GetDefaultOrganization lookup
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow(knownUUID, "default", "Default", nil, nil, time.Now(), time.Now()))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "client-id",
			"client_secret": "client-secret",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
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
	// Default org lookup
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow(knownUUID, "default", "Default", nil, nil, time.Now(), time.Now()))
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "bitbucket_dc",
			"name":          "test-bdc",
			"base_url":      "https://bitbucket.example.com",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_NoDefaultOrg(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	// Default org lookup returns no rows
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_DefaultOrgDBError(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_DefaultOrgInvalidUUID(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	// Default org returns a row with an unparseable UUID
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow("not-a-uuid", "default", "Default", nil, nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "test-github",
			"client_id":     "cid",
			"client_secret": "csec",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestSCMCreate_WithExplicitOrgID(t *testing.T) {
	mock, r := newSCMProviderRouter(t)
	// Explicit org ID skips default org lookup — only INSERT expected
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

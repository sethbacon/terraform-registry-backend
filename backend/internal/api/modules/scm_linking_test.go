package modules

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

var errSCMLinkDB = errors.New("db error")

const scmLinkModuleUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const scmLinkProviderUUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

// Column definitions for SELECT * queries via sqlx.GetContext
var scmProviderColsLink = []string{
	"id", "organization_id", "provider_type", "name",
	"base_url", "tenant_id", "client_id",
	"client_secret_encrypted", "webhook_secret",
	"is_active", "created_at", "updated_at",
}

var moduleSourceRepoColsLink = []string{
	"id", "module_id", "scm_provider_id",
	"repository_owner", "repository_name", "repository_url",
	"default_branch", "module_path", "tag_pattern",
	"auto_publish", "webhook_id", "webhook_url",
	"webhook_enabled", "last_sync_at", "last_sync_commit",
	"created_at", "updated_at",
}

func sampleSCMProviderRowLink() *sqlmock.Rows {
	return sqlmock.NewRows(scmProviderColsLink).AddRow(
		scmLinkProviderUUID, uuid.Nil.String(), "github", "github-provider",
		nil, nil, "client-id",
		"encrypted-secret", "webhook-secret",
		true, time.Now(), time.Now(),
	)
}

func sampleModuleSourceRepoRowLink() *sqlmock.Rows {
	return sqlmock.NewRows(moduleSourceRepoColsLink).AddRow(
		uuid.New(), scmLinkModuleUUID, scmLinkProviderUUID,
		"owner", "repo", nil,
		"main", "", "v*",
		false, nil, nil,
		false, nil, nil,
		time.Now(), time.Now(),
	)
}

// moduleSCMCols matches the 11 columns selected by GetModuleByID.
var moduleSCMCols = []string{
	"id", "organization_id", "namespace", "name", "system",
	"description", "source", "created_by", "created_at", "updated_at", "created_by_name",
}

func sampleModuleForSCMRow(id string) *sqlmock.Rows {
	return sqlmock.NewRows(moduleSCMCols).AddRow(
		id, uuid.Nil.String(), "hashicorp", "vpc", "aws",
		nil, nil, nil, time.Now(), time.Now(), nil,
	)
}

func linkBody(fields map[string]interface{}) *bytes.Buffer {
	b, _ := json.Marshal(fields)
	return bytes.NewBuffer(b)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newSCMLinkingRouter(t *testing.T) (sqlmock.Sqlmock, sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()

	// SCM repo uses sqlx
	scmDB, scmMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (scm): %v", err)
	}
	t.Cleanup(func() { scmDB.Close() })

	// Module repo uses *sql.DB
	modDB, modMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (mod): %v", err)
	}
	t.Cleanup(func() { modDB.Close() })

	scmRepo := repositories.NewSCMRepository(sqlx.NewDb(scmDB, "sqlmock"))
	moduleRepo := repositories.NewModuleRepository(modDB)
	tokenCipher := &crypto.TokenCipher{}
	scmPublisher := &services.SCMPublisher{}
	h := NewSCMLinkingHandler(scmRepo, moduleRepo, tokenCipher, "https://registry.example.com", scmPublisher)

	r := gin.New()
	r.POST("/modules/:id/scm", h.LinkModuleToSCM)
	r.PUT("/modules/:id/scm", h.UpdateSCMLink)
	r.DELETE("/modules/:id/scm", h.UnlinkModuleFromSCM)
	r.GET("/modules/:id/scm", h.GetModuleSCMInfo)
	r.POST("/modules/:id/scm/sync", h.TriggerManualSync)
	r.GET("/modules/:id/scm/events", h.GetWebhookEvents)

	return scmMock, modMock, r
}

// ---------------------------------------------------------------------------
// LinkModuleToSCM
// ---------------------------------------------------------------------------

func TestLinkModule_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/not-a-uuid/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestLinkModule_MissingBody(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{}))) // missing required fields

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestLinkModule_InvalidProviderID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      "not-a-uuid",
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestLinkModule_ProviderNotFound(t *testing.T) {
	scmMock, modMock, r := newSCMLinkingRouter(t)
	// Handler checks module exists first
	modMock.ExpectQuery("SELECT.*FROM modules m.*WHERE m.id").
		WillReturnRows(sampleModuleForSCMRow(scmLinkModuleUUID))
	// Then checks provider
	scmMock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProviderColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestLinkModule_AlreadyLinked(t *testing.T) {
	scmMock, modMock, r := newSCMLinkingRouter(t)
	// Handler checks module exists first
	modMock.ExpectQuery("SELECT.*FROM modules m.*WHERE m.id").
		WillReturnRows(sampleModuleForSCMRow(scmLinkModuleUUID))
	// GetProvider found
	scmMock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleSCMProviderRowLink())
	// GetModuleSourceRepo already exists
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowLink())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UnlinkModuleFromSCM
// ---------------------------------------------------------------------------

func TestUnlinkModule_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/not-a-uuid/scm", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUnlinkModule_NotFound(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/"+scmLinkModuleUUID+"/scm", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetModuleSCMInfo
// ---------------------------------------------------------------------------

func TestGetSCMInfo_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/not-a-uuid/scm", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestGetSCMInfo_NotFound(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/"+scmLinkModuleUUID+"/scm", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TriggerManualSync
// ---------------------------------------------------------------------------

func TestTriggerSync_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/not-a-uuid/scm/sync", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTriggerSync_NotLinked(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/modules/"+scmLinkModuleUUID+"/scm/sync", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetWebhookEvents
// ---------------------------------------------------------------------------

func TestGetWebhookEvents_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/not-a-uuid/scm/events", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// webhookEventCols matches scm.SCMWebhookEvent db tags
var webhookEventCols = []string{
	"id", "module_scm_repo_id", "event_id", "event_type",
	"ref", "commit_sha", "tag_name", "payload", "headers",
	"signature", "signature_valid", "processed",
	"processing_started_at", "processed_at", "result_version_id",
	"error", "created_at",
}

// ---------------------------------------------------------------------------
// UpdateSCMLink
// ---------------------------------------------------------------------------

func TestUpdateSCMLink_InvalidModuleID(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/not-a-uuid/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateSCMLink_MissingBody(t *testing.T) {
	_, _, r := newSCMLinkingRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{}))) // missing required fields

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateSCMLink_LinkNotFound(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	// GetModuleSourceRepo returns no rows
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateSCMLink_GetLinkDBError(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnError(errSCMLinkDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "owner",
			"repository_name":  "repo",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateSCMLink_UpdateDBError(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowLink())
	scmMock.ExpectExec("UPDATE module_scm_repos").
		WillReturnError(errSCMLinkDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "new-owner",
			"repository_name":  "new-repo",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateSCMLink_Success(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowLink())
	scmMock.ExpectExec("UPDATE module_scm_repos").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/modules/"+scmLinkModuleUUID+"/scm",
		linkBody(map[string]interface{}{
			"provider_id":      scmLinkProviderUUID,
			"repository_owner": "new-owner",
			"repository_name":  "new-repo",
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetWebhookEvents (additional paths beyond InvalidModuleID)
// ---------------------------------------------------------------------------

func TestGetWebhookEvents_GetLinkDBError(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnError(errSCMLinkDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/"+scmLinkModuleUUID+"/scm/events", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestGetWebhookEvents_LinkNotFound(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoColsLink))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/"+scmLinkModuleUUID+"/scm/events", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestGetWebhookEvents_ListEventsDBError(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowLink())
	scmMock.ExpectQuery("SELECT.*FROM scm_webhook_events WHERE module_scm_repo_id").
		WillReturnError(errSCMLinkDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/"+scmLinkModuleUUID+"/scm/events", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestGetWebhookEvents_Success(t *testing.T) {
	scmMock, _, r := newSCMLinkingRouter(t)
	scmMock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowLink())
	scmMock.ExpectQuery("SELECT.*FROM scm_webhook_events WHERE module_scm_repo_id").
		WillReturnRows(sqlmock.NewRows(webhookEventCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/modules/"+scmLinkModuleUUID+"/scm/events", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// generateWebhookSecret (unexported helper)
// ---------------------------------------------------------------------------

func TestGenerateWebhookSecret_IsNonEmpty(t *testing.T) {
	s := generateWebhookSecret()
	if s == "" {
		t.Error("expected non-empty secret")
	}
}

func TestGenerateWebhookSecret_IsUnique(t *testing.T) {
	s1 := generateWebhookSecret()
	s2 := generateWebhookSecret()
	if s1 == s2 {
		t.Error("expected unique secrets, got identical values")
	}
}

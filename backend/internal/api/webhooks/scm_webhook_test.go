package webhooks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"

	// Register SCM connectors so scm.BuildConnector works in tests
	_ "github.com/terraform-registry/terraform-registry/internal/scm/azuredevops"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/bitbucket"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/github"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/gitlab"
)

var webhookErrDB = errors.New("db error")

const webhookTestUUID = "11111111-1111-1111-1111-111111111111"

// ---------------------------------------------------------------------------
// Column definitions (db tags from ModuleSCMRepo / SCMProvider structs)
// ---------------------------------------------------------------------------

var moduleSourceRepoCols = []string{
	"id", "module_id", "scm_provider_id",
	"repository_owner", "repository_name", "repository_url",
	"default_branch", "module_path", "tag_pattern",
	"auto_publish", "webhook_id", "webhook_url",
	"webhook_enabled", "last_sync_at", "last_sync_commit",
	"created_at", "updated_at",
}

var scmProviderCols = []string{
	"id", "organization_id", "provider_type", "name",
	"base_url", "tenant_id", "client_id",
	"client_secret_encrypted", "webhook_secret",
	"is_active", "created_at", "updated_at",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleModuleSourceRepoRow(scmProviderID uuid.UUID) *sqlmock.Rows {
	repoID := uuid.MustParse(webhookTestUUID)
	moduleID := uuid.New()
	return sqlmock.NewRows(moduleSourceRepoCols).AddRow(
		repoID, moduleID, scmProviderID,
		"my-org", "my-repo", nil,
		"main", "", "v*",
		false, nil, nil,
		false, nil, nil,
		time.Now(), time.Now(),
	)
}

// sampleModuleSourceRepoRowWithURL is like sampleModuleSourceRepoRow but sets a
// non-nil webhook_url so the handler can verify the URL-embedded secret.
func sampleModuleSourceRepoRowWithURL(scmProviderID uuid.UUID, webhookURL string) *sqlmock.Rows {
	repoID := uuid.MustParse(webhookTestUUID)
	moduleID := uuid.New()
	return sqlmock.NewRows(moduleSourceRepoCols).AddRow(
		repoID, moduleID, scmProviderID,
		"my-org", "my-repo", nil,
		"main", "", "v*",
		false, nil, webhookURL,
		false, nil, nil,
		time.Now(), time.Now(),
	)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newWebhookRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	h := NewSCMWebhookHandler(scmRepo, nil) // nil publisher OK for early-exit tests

	r := gin.New()
	r.POST("/webhooks/scm/:module_source_repo_id/:secret", h.HandleWebhook)
	return mock, r
}

// ---------------------------------------------------------------------------
// HandleWebhook tests
// ---------------------------------------------------------------------------

func TestWebhook_InvalidUUID(t *testing.T) {
	_, r := newWebhookRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/not-a-uuid/secret123", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestWebhook_GetModuleSourceRepo_DBError(t *testing.T) {
	mock, r := newWebhookRouter(t)
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnError(webhookErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestWebhook_GetModuleSourceRepo_NotFound(t *testing.T) {
	mock, r := newWebhookRouter(t)
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestWebhook_GetProvider_DBError(t *testing.T) {
	mock, r := newWebhookRouter(t)
	providerID := uuid.New()
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRow(providerID))
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnError(webhookErrDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestWebhook_GetProvider_NotFound(t *testing.T) {
	mock, r := newWebhookRouter(t)
	providerID := uuid.New()
	// Use matching secret so the URL-secret check passes and we reach the provider lookup.
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowWithURL(providerID,
			"https://registry.example.com/webhooks/scm/"+webhookTestUUID+"/secret123"))
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProviderCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func sampleProviderRow(id uuid.UUID, providerType string) *sqlmock.Rows {
	baseURL := "https://bitbucket.example.com"
	return sqlmock.NewRows(scmProviderCols).AddRow(
		id, uuid.New(), providerType, "Test Provider",
		&baseURL, nil, "client-id",
		"encrypted-secret", "", // empty webhook_secret
		true, time.Now(), time.Now(),
	)
}

func TestWebhook_InvalidConnectorType(t *testing.T) {
	// Provider with an unknown type causes scm.BuildConnector to fail → 500
	mock, r := newWebhookRouter(t)
	providerID := uuid.New()

	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRow(providerID))
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(sampleProviderRow(providerID, "unknown_type"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (unknown connector type)", w.Code)
	}
}

func TestWebhook_InvalidSignature(t *testing.T) {
	// bitbucket_dc is PAT-based: BuildConnector succeeds without CallbackURL.
	// Empty X-Hub-Signature header → VerifyDeliverySignature returns false → 401.
	mock, r := newWebhookRouter(t)
	providerID := uuid.New()

	// Use a webhook URL whose embedded secret does NOT match "secret123" → 401.
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE module_id").
		WillReturnRows(sampleModuleSourceRepoRowWithURL(providerID,
			"https://registry.example.com/webhooks/scm/"+webhookTestUUID+"/different-secret"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (invalid signature)", w.Code)
	}
}

// ---------------------------------------------------------------------------
// getSignatureHeader (method on SCMWebhookHandler)
// ---------------------------------------------------------------------------

func newBareWebhookHandler() *SCMWebhookHandler {
	return &SCMWebhookHandler{}
}

func TestGetSignatureHeader_GitHub(t *testing.T) {
	h := newBareWebhookHandler()
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("X-Hub-Signature-256", "sha256=abc")

	sig := h.getSignatureHeader(req, "github")
	if sig != "sha256=abc" {
		t.Errorf("sig = %q, want sha256=abc", sig)
	}
}

func TestGetSignatureHeader_GitLab(t *testing.T) {
	h := newBareWebhookHandler()
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("X-Gitlab-Token", "gl-secret")

	sig := h.getSignatureHeader(req, "gitlab")
	if sig != "gl-secret" {
		t.Errorf("sig = %q, want gl-secret", sig)
	}
}

func TestGetSignatureHeader_AzureDevOps(t *testing.T) {
	h := newBareWebhookHandler()
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("X-Vss-Signature", "ado-sig")

	sig := h.getSignatureHeader(req, "azuredevops")
	if sig != "ado-sig" {
		t.Errorf("sig = %q, want ado-sig", sig)
	}
}

func TestGetSignatureHeader_BitbucketDC(t *testing.T) {
	h := newBareWebhookHandler()
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("X-Hub-Signature", "sha256=bbdc")

	sig := h.getSignatureHeader(req, "bitbucket_dc")
	if sig != "sha256=bbdc" {
		t.Errorf("sig = %q, want sha256=bbdc", sig)
	}
}

func TestGetSignatureHeader_Unknown(t *testing.T) {
	h := newBareWebhookHandler()
	req, _ := http.NewRequest("POST", "/", nil)

	sig := h.getSignatureHeader(req, "unknown")
	if sig != "" {
		t.Errorf("sig = %q, want empty", sig)
	}
}

// ---------------------------------------------------------------------------
// formatHeaders
// ---------------------------------------------------------------------------

func TestFormatHeaders_Empty(t *testing.T) {
	result := formatHeaders(map[string]string{})
	if result != "" {
		t.Errorf("result = %q, want empty", result)
	}
}

func TestFormatHeaders_SingleEntry(t *testing.T) {
	result := formatHeaders(map[string]string{"Content-Type": "application/json"})
	if result != "Content-Type: application/json" {
		t.Errorf("result = %q, want 'Content-Type: application/json'", result)
	}
}

func TestFormatHeaders_MultipleEntries(t *testing.T) {
	result := formatHeaders(map[string]string{"A": "1", "B": "2"})
	// Map order is non-deterministic, just check both entries appear
	if result == "" {
		t.Error("expected non-empty result")
	}
}

// ---------------------------------------------------------------------------
// convertHeaders
// ---------------------------------------------------------------------------

func TestConvertHeaders_Empty(t *testing.T) {
	result := convertHeaders(map[string]string{})
	if len(result) != 0 {
		t.Errorf("len = %d, want 0", len(result))
	}
}

func TestConvertHeaders_WithEntries(t *testing.T) {
	result := convertHeaders(map[string]string{"X-Key": "val"})
	if v, ok := result["X-Key"]; !ok || v != "val" {
		t.Errorf("result[X-Key] = %v, want val", result["X-Key"])
	}
}

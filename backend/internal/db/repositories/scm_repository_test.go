package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSCMRepo(t *testing.T) (*SCMRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSCMRepository(sqlx.NewDb(db, "sqlmock")), mock
}

// Minimal column sets matching struct db tags
var scmProviderCols = []string{
	"id", "organization_id", "provider_type", "name",
	"client_id", "client_secret_encrypted", "webhook_secret",
	"is_active", "created_at", "updated_at",
}

var scmTokenCols = []string{
	"id", "user_id", "scm_provider_id",
	"access_token_encrypted", "token_type",
	"created_at", "updated_at",
}

var scmModuleRepoCols = []string{
	"id", "module_id", "scm_provider_id",
	"repository_owner", "repository_name",
	"default_branch", "module_path", "tag_pattern",
	"auto_publish", "webhook_enabled",
	"created_at", "updated_at",
}

var scmAlertCols = []string{
	"id", "module_version_id", "tag_name",
	"original_commit_sha", "detected_commit_sha",
	"detected_at", "alert_sent", "resolved",
}

func sampleSCMProviderRow() *sqlmock.Rows {
	id := uuid.New()
	orgID := uuid.New()
	return sqlmock.NewRows(scmProviderCols).
		AddRow(id, orgID, "github", "My GitHub",
			"client-123", "encrypted-secret", "webhook-secret",
			true, time.Now(), time.Now())
}

func sampleSCMTokenRow() *sqlmock.Rows {
	return sqlmock.NewRows(scmTokenCols).
		AddRow(uuid.New(), uuid.New(), uuid.New(),
			"encrypted-access-token", "Bearer",
			time.Now(), time.Now())
}

func sampleSCMModuleRepoRow() *sqlmock.Rows {
	return sqlmock.NewRows(scmModuleRepoCols).
		AddRow(uuid.New(), uuid.New(), uuid.New(),
			"hashicorp", "terraform-aws",
			"main", ".", "v*",
			true, false,
			time.Now(), time.Now())
}

func sampleSCMAlertRow() *sqlmock.Rows {
	return sqlmock.NewRows(scmAlertCols).
		AddRow(uuid.New(), uuid.New(), "v1.0.0",
			"abc123", "def456",
			time.Now(), false, false)
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

func TestSCMCreateProvider_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	provider := &scm.SCMProviderRecord{
		ID:                    uuid.New(),
		OrganizationID:        uuid.New(),
		ProviderType:          scm.ProviderGitHub,
		Name:                  "My GitHub",
		ClientID:              "client-123",
		ClientSecretEncrypted: "encrypted",
		WebhookSecret:         "secret",
		IsActive:              true,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
	if err := repo.CreateProvider(context.Background(), provider); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCMCreateProvider_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_providers").
		WillReturnError(errDB)

	provider := &scm.SCMProviderRecord{ID: uuid.New()}
	if err := repo.CreateProvider(context.Background(), provider); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

func TestSCMGetProvider_Found(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(sampleSCMProviderRow())

	p, err := repo.GetProvider(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestSCMGetProvider_NotFound(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnRows(sqlmock.NewRows(scmProviderCols))

	p, err := repo.GetProvider(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil, got %v", p)
	}
}

func TestSCMGetProvider_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetProvider(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListProviders
// ---------------------------------------------------------------------------

func TestSCMListProviders_All(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers").
		WillReturnRows(sampleSCMProviderRow())

	providers, err := repo.ListProviders(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 1 {
		t.Errorf("len = %d, want 1", len(providers))
	}
}

func TestSCMListProviders_ForOrg(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProviderCols))

	providers, err := repo.ListProviders(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("len = %d, want 0", len(providers))
	}
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

func TestSCMUpdateProvider_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("UPDATE scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	provider := &scm.SCMProviderRecord{
		ID:       uuid.New(),
		Name:     "Updated",
		ClientID: "new-client",
		IsActive: true,
	}
	if err := repo.UpdateProvider(context.Background(), provider); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

func TestSCMDeleteProvider_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("DELETE FROM scm_providers").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteProvider(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SaveUserToken
// ---------------------------------------------------------------------------

func TestSCMSaveUserToken_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_oauth_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	token := &scm.SCMUserTokenRecord{
		ID:                   uuid.New(),
		UserID:               uuid.New(),
		SCMProviderID:        uuid.New(),
		AccessTokenEncrypted: "encrypted",
		TokenType:            "Bearer",
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := repo.SaveUserToken(context.Background(), token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCMSaveUserToken_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_oauth_tokens").
		WillReturnError(errDB)

	token := &scm.SCMUserTokenRecord{ID: uuid.New()}
	if err := repo.SaveUserToken(context.Background(), token); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetUserToken
// ---------------------------------------------------------------------------

func TestSCMGetUserToken_Found(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens.*WHERE user_id").
		WillReturnRows(sampleSCMTokenRow())

	token, err := repo.GetUserToken(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == nil {
		t.Fatal("expected token, got nil")
	}
}

func TestSCMGetUserToken_NotFound(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens.*WHERE user_id").
		WillReturnRows(sqlmock.NewRows(scmTokenCols))

	token, err := repo.GetUserToken(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != nil {
		t.Errorf("expected nil, got %v", token)
	}
}

// ---------------------------------------------------------------------------
// DeleteUserToken
// ---------------------------------------------------------------------------

func TestSCMDeleteUserToken_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("DELETE FROM scm_oauth_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteUserToken(context.Background(), uuid.New(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateModuleSourceRepo
// ---------------------------------------------------------------------------

func TestSCMCreateModuleSourceRepo_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO module_scm_repos").
		WillReturnResult(sqlmock.NewResult(1, 1))

	link := &scm.ModuleSourceRepoRecord{
		ID:              uuid.New(),
		ModuleID:        uuid.New(),
		SCMProviderID:   uuid.New(),
		RepositoryOwner: "hashicorp",
		RepositoryName:  "terraform-aws",
		DefaultBranch:   "main",
		ModulePath:      ".",
		TagPattern:      "v*",
		AutoPublish:     true,
		WebhookEnabled:  false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := repo.CreateModuleSourceRepo(context.Background(), link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetModuleSourceRepo
// ---------------------------------------------------------------------------

func TestSCMGetModuleSourceRepo_Found(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_scm_repos.*WHERE module_id").
		WillReturnRows(sampleSCMModuleRepoRow())

	link, err := repo.GetModuleSourceRepo(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link == nil {
		t.Fatal("expected link, got nil")
	}
}

func TestSCMGetModuleSourceRepo_NotFound(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM module_scm_repos.*WHERE module_id").
		WillReturnRows(sqlmock.NewRows(scmModuleRepoCols))

	link, err := repo.GetModuleSourceRepo(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link != nil {
		t.Errorf("expected nil, got %v", link)
	}
}

// ---------------------------------------------------------------------------
// UpdateModuleSourceRepo
// ---------------------------------------------------------------------------

func TestSCMUpdateModuleSourceRepo_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("UPDATE module_scm_repos").
		WillReturnResult(sqlmock.NewResult(1, 1))

	link := &scm.ModuleSourceRepoRecord{
		ID:              uuid.New(),
		RepositoryOwner: "updated",
		RepositoryName:  "repo",
		DefaultBranch:   "main",
		ModulePath:      ".",
		TagPattern:      "v*",
	}
	if err := repo.UpdateModuleSourceRepo(context.Background(), link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteModuleSourceRepo
// ---------------------------------------------------------------------------

func TestSCMDeleteModuleSourceRepo_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("DELETE FROM module_scm_repos").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteModuleSourceRepo(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateWebhookLog
// ---------------------------------------------------------------------------

func TestSCMCreateWebhookLog_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_webhook_events").
		WillReturnResult(sqlmock.NewResult(1, 1))

	log := &scm.SCMWebhookLogRecord{
		ID:              uuid.New(),
		ModuleSCMRepoID: uuid.New(),
		EventType:       scm.WebhookEventPush,
		Payload:         map[string]interface{}{"action": "push"},
		Headers:         map[string]interface{}{"X-GitHub-Event": "push"},
		Processed:       false,
		CreatedAt:       time.Now(),
	}
	if err := repo.CreateWebhookLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCMCreateWebhookLog_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO scm_webhook_events").
		WillReturnError(errDB)

	log := &scm.SCMWebhookLogRecord{
		ID:      uuid.New(),
		Payload: map[string]interface{}{},
		Headers: map[string]interface{}{},
	}
	if err := repo.CreateWebhookLog(context.Background(), log); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetWebhookLog (only error/not-found since Payload scanning is complex)
// ---------------------------------------------------------------------------

func TestSCMGetWebhookLog_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_webhook_events.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetWebhookLog(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSCMGetWebhookLog_NotFound(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_webhook_events.*WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	log, err := repo.GetWebhookLog(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log != nil {
		t.Errorf("expected nil, got %v", log)
	}
}

// ---------------------------------------------------------------------------
// ListWebhookLogs
// ---------------------------------------------------------------------------

func TestSCMListWebhookLogs_Error(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_webhook_events.*WHERE module_scm_repo_id").
		WillReturnError(errDB)

	_, err := repo.ListWebhookLogs(context.Background(), uuid.New(), 10)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSCMListWebhookLogs_Empty(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM scm_webhook_events.*WHERE module_scm_repo_id").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	logs, err := repo.ListWebhookLogs(context.Background(), uuid.New(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("len = %d, want 0", len(logs))
	}
}

// ---------------------------------------------------------------------------
// UpdateWebhookLogState
// ---------------------------------------------------------------------------

func TestSCMUpdateWebhookLogState_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("UPDATE scm_webhook_events").
		WillReturnResult(sqlmock.NewResult(1, 1))

	errMsg := "some error"
	if err := repo.UpdateWebhookLogState(context.Background(), uuid.New(), "failed", &errMsg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CreateImmutabilityAlert
// ---------------------------------------------------------------------------

func TestSCMCreateImmutabilityAlert_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("INSERT INTO version_immutability_violations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	alert := &scm.TagImmutabilityAlertRecord{
		ID:                uuid.New(),
		ModuleVersionID:   uuid.New(),
		TagName:           "v1.0.0",
		OriginalCommitSHA: "abc123",
		DetectedCommitSHA: "def456",
		DetectedAt:        time.Now(),
		AlertSent:         false,
		Resolved:          false,
	}
	if err := repo.CreateImmutabilityAlert(context.Background(), alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListUnacknowledgedAlerts
// ---------------------------------------------------------------------------

func TestSCMListUnacknowledgedAlerts_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM version_immutability_violations.*WHERE resolved").
		WillReturnRows(sampleSCMAlertRow())

	alerts, err := repo.ListUnacknowledgedAlerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("len = %d, want 1", len(alerts))
	}
}

func TestSCMListUnacknowledgedAlerts_Empty(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectQuery("SELECT.*FROM version_immutability_violations.*WHERE resolved").
		WillReturnRows(sqlmock.NewRows(scmAlertCols))

	alerts, err := repo.ListUnacknowledgedAlerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("len = %d, want 0", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// AcknowledgeAlert
// ---------------------------------------------------------------------------

func TestSCMAcknowledgeAlert_Success(t *testing.T) {
	repo, mock := newSCMRepo(t)
	mock.ExpectExec("UPDATE version_immutability_violations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.AcknowledgeAlert(context.Background(), uuid.New(), uuid.New(), "resolved"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

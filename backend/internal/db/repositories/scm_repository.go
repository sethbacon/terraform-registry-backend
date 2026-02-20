// scm_repository.go implements SCMRepository, providing database queries for SCM provider
// configuration storage and OAuth token persistence.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// SCMRepository handles database operations for SCM integration
type SCMRepository struct {
	db *sqlx.DB
}

// NewSCMRepository creates a new SCM repository
func NewSCMRepository(db *sqlx.DB) *SCMRepository {
	return &SCMRepository{db: db}
}

// SCM Provider Management

// CreateProvider creates a new SCM provider configuration
func (r *SCMRepository) CreateProvider(ctx context.Context, provider *scm.SCMProviderRecord) error {
	query := `
		INSERT INTO scm_providers (
			id, organization_id, provider_type, name, base_url, tenant_id,
			client_id, client_secret_encrypted, webhook_secret,
			is_active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`

	_, err := r.db.ExecContext(ctx, query,
		provider.ID, provider.OrganizationID, provider.ProviderType, provider.Name,
		provider.BaseURL, provider.TenantID, provider.ClientID, provider.ClientSecretEncrypted,
		provider.WebhookSecret, provider.IsActive, provider.CreatedAt, provider.UpdatedAt,
	)
	return err
}

// GetProvider retrieves an SCM provider by ID
func (r *SCMRepository) GetProvider(ctx context.Context, id uuid.UUID) (*scm.SCMProviderRecord, error) {
	var provider scm.SCMProviderRecord
	query := `SELECT * FROM scm_providers WHERE id = $1`
	err := r.db.GetContext(ctx, &provider, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &provider, err
}

// ListProviders lists all SCM providers for an organization
// If orgID is uuid.Nil, it returns all providers across all organizations
func (r *SCMRepository) ListProviders(ctx context.Context, orgID uuid.UUID) ([]*scm.SCMProviderRecord, error) {
	var providers []*scm.SCMProviderRecord
	var query string
	var err error

	if orgID == uuid.Nil {
		query = `SELECT * FROM scm_providers ORDER BY created_at DESC`
		err = r.db.SelectContext(ctx, &providers, query)
	} else {
		query = `SELECT * FROM scm_providers WHERE organization_id = $1 ORDER BY created_at DESC`
		err = r.db.SelectContext(ctx, &providers, query, orgID)
	}

	return providers, err
}

// UpdateProvider updates an SCM provider configuration
func (r *SCMRepository) UpdateProvider(ctx context.Context, provider *scm.SCMProviderRecord) error {
	query := `
		UPDATE scm_providers SET
			name = $2, base_url = $3, tenant_id = $4, client_id = $5,
			client_secret_encrypted = $6, webhook_secret = $7,
			is_active = $8, updated_at = $9
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		provider.ID, provider.Name, provider.BaseURL, provider.TenantID, provider.ClientID,
		provider.ClientSecretEncrypted, provider.WebhookSecret,
		provider.IsActive, time.Now(),
	)
	return err
}

// DeleteProvider deletes an SCM provider
func (r *SCMRepository) DeleteProvider(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM scm_providers WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// User Token Management

// SaveUserToken saves or updates a user's OAuth token
func (r *SCMRepository) SaveUserToken(ctx context.Context, token *scm.SCMUserTokenRecord) error {
	query := `
		INSERT INTO scm_oauth_tokens (
			id, user_id, scm_provider_id, access_token_encrypted, refresh_token_encrypted,
			token_type, expires_at, scopes, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		) ON CONFLICT (user_id, scm_provider_id) DO UPDATE SET
			access_token_encrypted = $4, refresh_token_encrypted = $5, token_type = $6,
			expires_at = $7, scopes = $8, updated_at = $10`

	_, err := r.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.SCMProviderID, token.AccessTokenEncrypted,
		token.RefreshTokenEncrypted, token.TokenType, token.ExpiresAt,
		token.Scopes, token.CreatedAt, token.UpdatedAt,
	)
	return err
}

// GetUserToken retrieves a user's OAuth token for a provider
func (r *SCMRepository) GetUserToken(ctx context.Context, userID, providerID uuid.UUID) (*scm.SCMUserTokenRecord, error) {
	var token scm.SCMUserTokenRecord
	query := `SELECT * FROM scm_oauth_tokens WHERE user_id = $1 AND scm_provider_id = $2`
	err := r.db.GetContext(ctx, &token, query, userID, providerID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &token, err
}

// DeleteUserToken deletes a user's OAuth token
func (r *SCMRepository) DeleteUserToken(ctx context.Context, userID, providerID uuid.UUID) error {
	query := `DELETE FROM scm_oauth_tokens WHERE user_id = $1 AND scm_provider_id = $2`
	_, err := r.db.ExecContext(ctx, query, userID, providerID)
	return err
}

// Module Source Repository Linking

// CreateModuleSourceRepo creates a link between a module and a repository
func (r *SCMRepository) CreateModuleSourceRepo(ctx context.Context, link *scm.ModuleSourceRepoRecord) error {
	query := `
		INSERT INTO module_scm_repos (
			id, module_id, scm_provider_id, repository_owner, repository_name, repository_url,
			default_branch, module_path, tag_pattern, auto_publish,
			webhook_id, webhook_url, webhook_enabled,
			last_sync_at, last_sync_commit, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err := r.db.ExecContext(ctx, query,
		link.ID, link.ModuleID, link.SCMProviderID, link.RepositoryOwner, link.RepositoryName,
		link.RepositoryURL, link.DefaultBranch, link.ModulePath, link.TagPattern,
		link.AutoPublish, link.WebhookID, link.WebhookURL,
		link.WebhookEnabled, link.LastSyncAt, link.LastSyncCommit,
		link.CreatedAt, link.UpdatedAt,
	)
	return err
}

// GetModuleSourceRepo retrieves the source repository link for a module
func (r *SCMRepository) GetModuleSourceRepo(ctx context.Context, moduleID uuid.UUID) (*scm.ModuleSourceRepoRecord, error) {
	var link scm.ModuleSourceRepoRecord
	query := `SELECT * FROM module_scm_repos WHERE module_id = $1`
	err := r.db.GetContext(ctx, &link, query, moduleID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &link, err
}

// UpdateModuleSourceRepo updates a module source repository link
func (r *SCMRepository) UpdateModuleSourceRepo(ctx context.Context, link *scm.ModuleSourceRepoRecord) error {
	query := `
		UPDATE module_scm_repos SET
			repository_owner = $2, repository_name = $3, repository_url = $4,
			default_branch = $5, module_path = $6, tag_pattern = $7,
			auto_publish = $8, webhook_id = $9, webhook_url = $10,
			webhook_enabled = $11, last_sync_at = $12, last_sync_commit = $13,
			updated_at = $14
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		link.ID, link.RepositoryOwner, link.RepositoryName, link.RepositoryURL,
		link.DefaultBranch, link.ModulePath, link.TagPattern,
		link.AutoPublish, link.WebhookID, link.WebhookURL,
		link.WebhookEnabled, link.LastSyncAt, link.LastSyncCommit, time.Now(),
	)
	return err
}

// DeleteModuleSourceRepo deletes a module source repository link
func (r *SCMRepository) DeleteModuleSourceRepo(ctx context.Context, moduleID uuid.UUID) error {
	query := `DELETE FROM module_scm_repos WHERE module_id = $1`
	_, err := r.db.ExecContext(ctx, query, moduleID)
	return err
}

// Webhook Event Logging

// CreateWebhookLog creates a webhook event log entry
func (r *SCMRepository) CreateWebhookLog(ctx context.Context, log *scm.SCMWebhookLogRecord) error {
	payloadJSON, err := json.Marshal(log.Payload)
	if err != nil {
		return err
	}

	headersJSON, err := json.Marshal(log.Headers)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO scm_webhook_events (
			id, module_scm_repo_id, event_id, event_type, ref, commit_sha,
			tag_name, payload, headers, signature, signature_valid,
			processed, processing_started_at, processed_at,
			result_version_id, error, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err = r.db.ExecContext(ctx, query,
		log.ID, log.ModuleSCMRepoID, log.EventID, log.EventType, log.Ref,
		log.CommitSHA, log.TagName, payloadJSON, headersJSON, log.Signature,
		log.SignatureValid, false, log.ProcessingStartedAt,
		log.ProcessedAt, log.ResultVersionID, log.Error, log.CreatedAt,
	)
	return err
}

// GetWebhookLog retrieves a webhook log entry
func (r *SCMRepository) GetWebhookLog(ctx context.Context, id uuid.UUID) (*scm.SCMWebhookLogRecord, error) {
	var log scm.SCMWebhookLogRecord
	query := `SELECT * FROM scm_webhook_events WHERE id = $1`
	err := r.db.GetContext(ctx, &log, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &log, err
}

// ListWebhookLogs lists webhook logs for a module source repository
func (r *SCMRepository) ListWebhookLogs(ctx context.Context, repoID uuid.UUID, limit int) ([]*scm.SCMWebhookLogRecord, error) {
	var logs []*scm.SCMWebhookLogRecord
	query := `SELECT * FROM scm_webhook_events WHERE module_scm_repo_id = $1 ORDER BY created_at DESC LIMIT $2`
	err := r.db.SelectContext(ctx, &logs, query, repoID, limit)
	return logs, err
}

// UpdateWebhookLogState updates the processing state of a webhook log
func (r *SCMRepository) UpdateWebhookLogState(ctx context.Context, id uuid.UUID, state string, errorMsg *string, versionID *uuid.UUID) error {
	now := time.Now()
	query := `
		UPDATE scm_webhook_events SET
			processed = true, processed_at = $3,
			error = $4, result_version_id = $5
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query, id, state, now, errorMsg, versionID)
	return err
}

// Tag Immutability Alerts

// CreateImmutabilityAlert creates a tag immutability violation alert
func (r *SCMRepository) CreateImmutabilityAlert(ctx context.Context, alert *scm.TagImmutabilityAlertRecord) error {
	query := `
		INSERT INTO version_immutability_violations (
			id, module_version_id, tag_name, original_commit_sha, detected_commit_sha,
			detected_at, alert_sent, alert_sent_at,
			resolved, resolved_at, resolved_by, notes
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`

	_, err := r.db.ExecContext(ctx, query,
		alert.ID, alert.ModuleVersionID, alert.TagName, alert.OriginalCommitSHA,
		alert.DetectedCommitSHA, alert.DetectedAt, alert.AlertSent,
		alert.AlertSentAt, alert.Resolved, alert.ResolvedAt,
		alert.ResolvedBy, alert.Notes,
	)
	return err
}

// ListUnacknowledgedAlerts lists all unacknowledged immutability alerts
func (r *SCMRepository) ListUnacknowledgedAlerts(ctx context.Context) ([]*scm.TagImmutabilityAlertRecord, error) {
	var alerts []*scm.TagImmutabilityAlertRecord
	query := `SELECT * FROM version_immutability_violations WHERE resolved = false ORDER BY detected_at DESC`
	err := r.db.SelectContext(ctx, &alerts, query)
	return alerts, err
}

// AcknowledgeAlert marks an immutability alert as acknowledged
func (r *SCMRepository) AcknowledgeAlert(ctx context.Context, id, userID uuid.UUID, note string) error {
	now := time.Now()
	query := `
		UPDATE version_immutability_violations SET
			resolved = true, resolved_at = $2, resolved_by = $3, notes = $4
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query, id, now, userID, note)
	return err
}

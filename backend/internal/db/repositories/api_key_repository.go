// api_key_repository.go implements APIKeyRepository, providing database queries for API key
// lookup by prefix, creation, expiry management, and last-used timestamp updates.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// APIKeyRepository handles API key database operations
type APIKeyRepository struct {
	db *sql.DB
}

// NewAPIKeyRepository creates a new APIKeyRepository
func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// CreateAPIKey creates a new API key
func (r *APIKeyRepository) CreateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	apiKey.ID = uuid.New().String()
	apiKey.CreatedAt = time.Now()

	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO api_keys (id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = r.db.ExecContext(ctx, query,
		apiKey.ID,
		apiKey.UserID,
		apiKey.OrganizationID,
		apiKey.Name,
		apiKey.Description,
		apiKey.KeyHash,
		apiKey.KeyPrefix,
		scopesJSON,
		apiKey.ExpiresAt,
		apiKey.LastUsedAt,
		apiKey.CreatedAt,
	)

	return err
}

// GetAPIKeyByHash retrieves an API key by its hash (for authentication)
func (r *APIKeyRepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at
		FROM api_keys
		WHERE key_hash = $1
	`

	apiKey := &models.APIKey{}
	var scopesJSON []byte

	err := r.db.QueryRowContext(ctx, query, keyHash).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.OrganizationID,
		&apiKey.Name,
		&apiKey.Description,
		&apiKey.KeyHash,
		&apiKey.KeyPrefix,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsedAt,
		&apiKey.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	// Unmarshal scopes from JSONB
	err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

// GetAPIKeyByID retrieves an API key by ID
func (r *APIKeyRepository) GetAPIKeyByID(ctx context.Context, keyID string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at
		FROM api_keys
		WHERE id = $1
	`

	apiKey := &models.APIKey{}
	var scopesJSON []byte

	err := r.db.QueryRowContext(ctx, query, keyID).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.OrganizationID,
		&apiKey.Name,
		&apiKey.Description,
		&apiKey.KeyHash,
		&apiKey.KeyPrefix,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsedAt,
		&apiKey.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	// Unmarshal scopes from JSONB
	err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

// ListAPIKeysByUser retrieves all API keys for a user
func (r *APIKeyRepository) ListAPIKeysByUser(ctx context.Context, userID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey := &models.APIKey{}
		var scopesJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.OrganizationID,
			&apiKey.Name,
			&apiKey.Description,
			&apiKey.KeyHash,
			&apiKey.KeyPrefix,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsedAt,
			&apiKey.CreatedAt,
			&apiKey.UserName,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal scopes from JSONB
		err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// ListAPIKeysByOrganization retrieves all API keys for an organization
func (r *APIKeyRepository) ListAPIKeysByOrganization(ctx context.Context, orgID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.organization_id = $1
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey := &models.APIKey{}
		var scopesJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.OrganizationID,
			&apiKey.Name,
			&apiKey.Description,
			&apiKey.KeyHash,
			&apiKey.KeyPrefix,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsedAt,
			&apiKey.CreatedAt,
			&apiKey.UserName,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal scopes from JSONB
		err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// UpdateLastUsed updates the last_used_at timestamp for an API key
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, keyID string) error {
	query := `
		UPDATE api_keys
		SET last_used_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, keyID, time.Now())
	return err
}

// RevokeAPIKey deletes/revokes an API key
func (r *APIKeyRepository) RevokeAPIKey(ctx context.Context, keyID string) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, keyID)
	return err
}

// DeleteExpiredKeys deletes all expired API keys (for cleanup/cron job)
func (r *APIKeyRepository) DeleteExpiredKeys(ctx context.Context) error {
	query := `
		DELETE FROM api_keys
		WHERE expires_at IS NOT NULL AND expires_at < $1
	`

	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}

// GetAPIKeysByPrefix retrieves API keys matching a prefix (for authentication)
func (r *APIKeyRepository) GetAPIKeysByPrefix(ctx context.Context, keyPrefix string) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at
		FROM api_keys
		WHERE key_prefix = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, keyPrefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey := &models.APIKey{}
		var scopesJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.OrganizationID,
			&apiKey.Name,
			&apiKey.Description,
			&apiKey.KeyHash,
			&apiKey.KeyPrefix,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsedAt,
			&apiKey.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal scopes from JSONB
		err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// FindExpiringKeys returns API keys that will expire within warningDays days
// and have not yet had a notification email sent (expiry_notification_sent_at IS NULL).
// Only keys associated with a user (user_id IS NOT NULL) are returned so the caller
// can look up an email address.
func (r *APIKeyRepository) FindExpiringKeys(ctx context.Context, warningDays int) ([]*models.APIKey, error) {
	cutoff := time.Now().Add(time.Duration(warningDays) * 24 * time.Hour)
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
		       expires_at, last_used_at, created_at
		FROM api_keys
		WHERE expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= $1
		  AND expiry_notification_sent_at IS NULL
		  AND user_id IS NOT NULL
		ORDER BY expires_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*models.APIKey, 0)
	for rows.Next() {
		k := &models.APIKey{}
		var scopesJSON []byte
		err := rows.Scan(
			&k.ID, &k.UserID, &k.OrganizationID, &k.Name, &k.Description,
			&k.KeyHash, &k.KeyPrefix, &scopesJSON, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopesJSON, &k.Scopes); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// MarkExpiryNotificationSent records that the expiry warning email was sent for a key,
// preventing duplicate emails on subsequent job runs.
func (r *APIKeyRepository) MarkExpiryNotificationSent(ctx context.Context, keyID string) error {
	query := `UPDATE api_keys SET expiry_notification_sent_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), keyID)
	return err
}

// Create is an alias for CreateAPIKey to match admin handlers
func (r *APIKeyRepository) Create(ctx context.Context, apiKey *models.APIKey) error {
	return r.CreateAPIKey(ctx, apiKey)
}

// GetByID is an alias for GetAPIKeyByID to match admin handlers
func (r *APIKeyRepository) GetByID(ctx context.Context, keyID string) (*models.APIKey, error) {
	return r.GetAPIKeyByID(ctx, keyID)
}

// Update updates an API key's information
func (r *APIKeyRepository) Update(ctx context.Context, apiKey *models.APIKey) error {
	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return err
	}

	query := `
		UPDATE api_keys
		SET name = $2, description = $3, scopes = $4, expires_at = $5
		WHERE id = $1
	`

	_, err = r.db.ExecContext(ctx, query,
		apiKey.ID,
		apiKey.Name,
		apiKey.Description,
		scopesJSON,
		apiKey.ExpiresAt,
	)

	return err
}

// Delete is an alias for RevokeAPIKey to match admin handlers
func (r *APIKeyRepository) Delete(ctx context.Context, keyID string) error {
	return r.RevokeAPIKey(ctx, keyID)
}

// ListByUser is an alias for ListAPIKeysByUser to match admin handlers
func (r *APIKeyRepository) ListByUser(ctx context.Context, userID string) ([]*models.APIKey, error) {
	return r.ListAPIKeysByUser(ctx, userID)
}

// ListByOrganization is an alias for ListAPIKeysByOrganization to match admin handlers
func (r *APIKeyRepository) ListByOrganization(ctx context.Context, orgID string) ([]*models.APIKey, error) {
	return r.ListAPIKeysByOrganization(ctx, orgID)
}

// ListByUserAndOrganization retrieves API keys for a specific user within a specific organization
func (r *APIKeyRepository) ListByUserAndOrganization(ctx context.Context, userID, orgID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1 AND ak.organization_id = $2
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey := &models.APIKey{}
		var scopesJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.OrganizationID,
			&apiKey.Name,
			&apiKey.Description,
			&apiKey.KeyHash,
			&apiKey.KeyPrefix,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsedAt,
			&apiKey.CreatedAt,
			&apiKey.UserName,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal scopes from JSONB
		err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
		if err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// ListAll retrieves all API keys across all organizations (for admin use)
func (r *APIKeyRepository) ListAll(ctx context.Context) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey := &models.APIKey{}
		var scopesJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.OrganizationID,
			&apiKey.Name,
			&apiKey.Description,
			&apiKey.KeyHash,
			&apiKey.KeyPrefix,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsedAt,
			&apiKey.CreatedAt,
			&apiKey.UserName,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal scopes from JSONB
		err = json.Unmarshal(scopesJSON, &apiKey.Scopes)
		if err != nil {
			return nil, err
		}

		allKeys = append(allKeys, apiKey)
	}

	return allKeys, rows.Err()
}

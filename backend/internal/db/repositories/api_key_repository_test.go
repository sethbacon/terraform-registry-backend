// api_key_repository_test.go adds a contract test for GetAPIKeysByPrefix, the
// real API-key authentication lookup (candidates are then bcrypt-compared by
// auth.ValidateAPIKey). APIKeyRepository is a pure alias to the shared
// identity store (api_key_repository.go), so this path is otherwise invisible
// to this repo's test suite and coverage gate (issue #669).
package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

var apiKeyRepoCols = []string{
	"id", "user_id", "organization_id", "name", "description", "key_hash", "key_prefix",
	"scopes", "expires_at", "last_used_at", "expiry_notification_sent_at", "created_at",
}

func newAPIKeyRepo(t *testing.T) (*APIKeyRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAPIKeyRepository(db), mock
}

func sampleAPIKeyRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyRepoCols).
		AddRow("key-1", "user-1", "org-1", "ci key", nil, "$2a$hash", "abcd1234",
			[]byte(`["modules:read"]`), nil, nil, nil, time.Now())
}

func TestAPIKeyRepository_GetAPIKeysByPrefix_Found(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	// Two arguments since identity v0.25.0: the lookup is bounded (LIMIT $2) so
	// one non-discriminating prefix cannot fan a single unauthenticated request
	// across every live key as bcrypt candidates.
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_prefix").
		WithArgs("abcd1234", sqlmock.AnyArg()).
		WillReturnRows(sampleAPIKeyRow())

	keys, err := repo.GetAPIKeysByPrefix(context.Background(), "abcd1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
	}
}

func TestAPIKeyRepository_GetAPIKeysByPrefix_Empty(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_prefix").
		WillReturnRows(sqlmock.NewRows(apiKeyRepoCols))

	keys, err := repo.GetAPIKeysByPrefix(context.Background(), "zzzz0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("len = %d, want 0", len(keys))
	}
}

func TestAPIKeyRepository_GetAPIKeysByPrefix_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_prefix").
		WillReturnError(errDB)

	_, err := repo.GetAPIKeysByPrefix(context.Background(), "abcd1234")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

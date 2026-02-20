package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var apiKeyCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "created_at",
}

var apiKeyListCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "created_at", "user_name",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

var sampleScopes = []byte(`["modules:read","modules:write"]`)

func sampleAPIKeyRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			sampleScopes, nil, nil, time.Now())
}

func emptyAPIKeyRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyCols)
}

func sampleAPIKeyListRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyListCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			sampleScopes, nil, nil, time.Now(), nil)
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

// ---------------------------------------------------------------------------
// CreateAPIKey
// ---------------------------------------------------------------------------

func TestCreateAPIKey_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{
		ID:             "key-new",
		OrganizationID: "org-1",
		Name:           "Test Key",
		KeyHash:        "hash",
		KeyPrefix:      "tfr_test",
		Scopes:         []string{"modules:read"},
	}
	if err := repo.CreateAPIKey(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAPIKey_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-new", Scopes: []string{"modules:read"}}
	if err := repo.CreateAPIKey(context.Background(), key); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeyByHash
// ---------------------------------------------------------------------------

func TestGetAPIKeyByHash_Found(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_hash").
		WithArgs("hashedkey").
		WillReturnRows(sampleAPIKeyRow())

	key, err := repo.GetAPIKeyByHash(context.Background(), "hashedkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
	if key.ID != "key-1" {
		t.Errorf("ID = %s, want key-1", key.ID)
	}
	if len(key.Scopes) != 2 {
		t.Errorf("len(Scopes) = %d, want 2", len(key.Scopes))
	}
}

func TestGetAPIKeyByHash_NotFound(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_hash").
		WillReturnRows(emptyAPIKeyRow())

	key, err := repo.GetAPIKeyByHash(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeyByID
// ---------------------------------------------------------------------------

func TestGetAPIKeyByID_Found(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").
		WithArgs("key-1").
		WillReturnRows(sampleAPIKeyRow())

	key, err := repo.GetAPIKeyByID(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
}

func TestGetAPIKeyByID_NotFound(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").
		WillReturnRows(emptyAPIKeyRow())

	key, err := repo.GetAPIKeyByID(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// ListAPIKeysByUser
// ---------------------------------------------------------------------------

func TestListAPIKeysByUser_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

func TestListAPIKeysByUser_Empty(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sqlmock.NewRows(apiKeyListCols))

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("len(keys) = %d, want 0", len(keys))
	}
}

// ---------------------------------------------------------------------------
// ListAPIKeysByOrganization
// ---------------------------------------------------------------------------

func TestListAPIKeysByOrganization_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAPIKeysByOrganization(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// UpdateLastUsed
// ---------------------------------------------------------------------------

func TestUpdateLastUsed_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys.*SET last_used_at").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateLastUsed(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RevokeAPIKey
// ---------------------------------------------------------------------------

func TestRevokeAPIKey_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RevokeAPIKey(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteExpiredKeys
// ---------------------------------------------------------------------------

func TestDeleteExpiredKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys.*WHERE.*expires_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteExpiredKeys(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeysByPrefix
// ---------------------------------------------------------------------------

func TestGetAPIKeysByPrefix_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix").
		WillReturnRows(sampleAPIKeyRow())

	keys, err := repo.GetAPIKeysByPrefix(context.Background(), "tfr_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// ListAll
// ---------------------------------------------------------------------------

func TestListAllAPIKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// ListByUserAndOrganization
// ---------------------------------------------------------------------------

func TestListByUserAndOrganization_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByUserAndOrganization(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// Delegate aliases (Create / GetByID / Update / Delete / ListByUser / ListByOrganization)
// ---------------------------------------------------------------------------

func TestAPIKey_Create_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{ID: "k1", OrganizationID: "org-1", Name: "k", KeyHash: "h", KeyPrefix: "p", Scopes: []string{"read"}}
	if err := repo.Create(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_GetByID_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*id").
		WillReturnRows(sampleAPIKeyRow())

	k, err := repo.GetByID(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k == nil {
		t.Fatal("expected key, got nil")
	}
}

func TestAPIKey_Update_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_Update_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key); err == nil {
		t.Error("expected error")
	}
}

func TestAPIKey_Delete_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_ListByUser_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
	}
}

func TestAPIKey_ListByOrganization_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByOrganization(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
	}
}

// user_repository_test.go adds contract tests for the security-relevant paths
// of UserRepository, which is a pure alias to the shared identity store
// (user_repository.go) and therefore otherwise invisible to this repo's test
// suite and coverage gate (issue #669). Search is the SCIM-exposed lookup;
// GetUserByID backs the auth middleware's per-request user resolution.
package repositories

import (
	"context"
	"errors"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

var userRepoCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func newUserRepo(t *testing.T) (*UserRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewUserRepository(db), mock
}

func sampleUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userRepoCols).
		AddRow("user-1", "alice@example.com", "Alice", nil, time.Now(), time.Now())
}

func TestUserRepository_Search_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email ILIKE").
		WillReturnRows(sampleUserRow())

	users, err := repo.Search(context.Background(), "alice", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("len = %d, want 1", len(users))
	}
}

func TestUserRepository_Search_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email ILIKE").
		WillReturnRows(sqlmock.NewRows(userRepoCols))

	users, err := repo.Search(context.Background(), "nobody", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("len = %d, want 0", len(users))
	}
}

func TestUserRepository_Search_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email ILIKE").
		WillReturnError(errDB)

	_, err := repo.Search(context.Background(), "alice", 20, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUserRepository_GetUserByID_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestUserRepository_GetUserByID_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WillReturnRows(sqlmock.NewRows(userRepoCols))

	user, err := repo.GetUserByID(context.Background(), "missing")
	// identity v0.24.0 reports a miss with the store.ErrNotFound sentinel
	// instead of (nil, nil). Assert the SENTINEL, not merely a non-nil error:
	// a bare `err != nil` check would also pass for a real database failure,
	// which callers must not map to 404.
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if user != nil {
		t.Errorf("expected nil, got %v", user)
	}
}

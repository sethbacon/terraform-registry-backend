package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

var errDB = errors.New("db error")

var userCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func sampleUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userCols).
		AddRow("user-1", "alice@example.com", "Alice", nil, time.Now(), time.Now())
}

func emptyUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userCols)
}

func newUserRepo(t *testing.T) (*UserRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewUserRepository(db), mock
}

// ---------------------------------------------------------------------------
// GetUserByID
// ---------------------------------------------------------------------------

func TestGetUserByID_Found(t *testing.T) {
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
	if user.ID != "user-1" {
		t.Errorf("ID = %s, want user-1", user.ID)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("missing").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByID(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user for not found, got %v", user)
	}
}

func TestGetUserByID_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnError(errDB)

	_, err := repo.GetUserByID(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetUserByEmail
// ---------------------------------------------------------------------------

func TestGetUserByEmail_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("nobody@example.com").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByEmail(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user, got %v", user)
	}
}

// ---------------------------------------------------------------------------
// GetUserByOIDCSub
// ---------------------------------------------------------------------------

func TestGetUserByOIDCSub_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByOIDCSub(context.Background(), "sub-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetUserByOIDCSub_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-missing").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByOIDCSub(context.Background(), "sub-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// CreateUser
// ---------------------------------------------------------------------------

func TestCreateUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user := &models.User{Email: "bob@example.com", Name: "Bob"}
	if err := repo.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID == "" {
		t.Error("expected ID to be set")
	}
}

func TestCreateUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("INSERT INTO users").
		WillReturnError(errDB)

	user := &models.User{Email: "bob@example.com", Name: "Bob"}
	if err := repo.CreateUser(context.Background(), user); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateUser
// ---------------------------------------------------------------------------

func TestUpdateUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user := &models.User{ID: "user-1", Email: "alice@example.com", Name: "Alice Updated"}
	if err := repo.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("UPDATE users").
		WillReturnError(errDB)

	user := &models.User{ID: "user-1", Email: "alice@example.com", Name: "Alice"}
	if err := repo.UpdateUser(context.Background(), user); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteUser
// ---------------------------------------------------------------------------

func TestDeleteUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteUser(context.Background(), "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users").
		WillReturnError(errDB)

	if err := repo.DeleteUser(context.Background(), "user-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListUsers
// ---------------------------------------------------------------------------

func TestListUsers_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())

	users, total, err := repo.ListUsers(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

func TestListUsers_CountError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnError(errDB)

	_, _, err := repo.ListUsers(context.Background(), 20, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListUsers_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(emptyUserRow())

	users, total, err := repo.ListUsers(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(users) != 0 {
		t.Errorf("len(users) = %d, want 0", len(users))
	}
}

// ---------------------------------------------------------------------------
// List (simple paginated list)
// ---------------------------------------------------------------------------

func TestList_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())

	users, err := repo.List(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------

func TestCount_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	count, err := repo.Count(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 42 {
		t.Errorf("count = %d, want 42", count)
	}
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func TestSearch_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE.*ILIKE").
		WillReturnRows(sampleUserRow())

	users, err := repo.Search(context.Background(), "alice", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

func TestSearch_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE.*ILIKE").
		WillReturnRows(emptyUserRow())

	users, err := repo.Search(context.Background(), "nobody", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("len(users) = %d, want 0", len(users))
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateUserFromOIDC
// ---------------------------------------------------------------------------

func TestGetOrCreateUserFromOIDC_ExistingUser_NoChange(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds user with matching email/name
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow()) // email=alice@example.com, name=Alice

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-123", "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserFromOIDC_ExistingUser_UpdateNeeded(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds user with different email
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow()) // email=alice@example.com
	// UpdateUser called because email changed
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-123", "alice_new@example.com", "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserFromOIDC_NewUser(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds no user
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	// CreateUser
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "new@example.com", "New User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetUserWithOrgRoles
// ---------------------------------------------------------------------------

func TestGetUserWithOrgRoles_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("missing").
		WillReturnRows(emptyUserRow())

	result, err := repo.GetUserWithOrgRoles(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for not found user")
	}
}

func TestGetUserWithOrgRoles_Success_NoMemberships(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	// Memberships query returns empty
	membCols := []string{
		"organization_id", "organization_name", "role_template_id", "created_at",
		"role_template_name", "role_template_display_name", "role_template_scopes",
	}
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(membCols))

	result, err := repo.GetUserWithOrgRoles(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if len(result.Memberships) != 0 {
		t.Errorf("len(memberships) = %d, want 0", len(result.Memberships))
	}
}

// ---------------------------------------------------------------------------
// Create / Update / Delete delegate aliases
// ---------------------------------------------------------------------------

func TestCreate_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	user := &models.User{ID: "user-1", Email: "a@b.com", Name: "Alice"}
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdate_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	user := &models.User{ID: "user-1", Email: "a@b.com", Name: "Alice"}
	mock.ExpectExec("UPDATE users SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Update(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateUserByOIDC (alias for GetOrCreateUserFromOIDC)
// ---------------------------------------------------------------------------

func TestGetOrCreateUserByOIDC_ExistingUser(t *testing.T) {
	repo, mock := newUserRepo(t)
	// GetUserByOIDCSub returns existing user
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow())

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_ExistingUserUpdateNeeded(t *testing.T) {
	repo, mock := newUserRepo(t)
	// Return user with different name
	oidcSub := "sub-123"
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("user-1", "old@example.com", "OldName", &oidcSub, time.Now(), time.Now()))
	// UpdateUser called because email/name differ
	mock.ExpectExec("UPDATE users SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "new@example.com", "NewName")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_NewUser(t *testing.T) {
	repo, mock := newUserRepo(t)
	// GetUserByOIDCSub returns no rows
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WillReturnRows(sqlmock.NewRows(userCols))
	// CreateUser
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-new", "new@example.com", "New User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_OIDCLookupError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WillReturnError(errDB)

	_, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "a@b.com", "Alice")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// ListUsersWithRoles (deprecated alias for ListUsers)
// ---------------------------------------------------------------------------

func TestListUsersWithRoles_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users").
		WillReturnRows(sampleUserRow())

	users, total, err := repo.ListUsersWithRoles(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 {
		t.Errorf("len = %d, want 1", len(users))
	}
}

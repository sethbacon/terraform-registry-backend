// token_repository_test.go adds contract tests for JWT revocation checks
// (IsTokenRevoked/RevokeToken). TokenRepository is a pure alias to the shared
// identity store (token_repository.go), so this token-validation path is
// otherwise invisible to this repo's test suite and coverage gate (issue #669).
package repositories

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func newTokenRepo(t *testing.T) (*TokenRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewTokenRepository(db), mock
}

func TestTokenRepository_IsTokenRevoked_True(t *testing.T) {
	repo, mock := newTokenRepo(t)
	mock.ExpectQuery("SELECT EXISTS.*FROM revoked_tokens WHERE jti").
		WithArgs("jti-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	revoked, err := repo.IsTokenRevoked(context.Background(), "jti-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Error("expected revoked = true")
	}
}

func TestTokenRepository_IsTokenRevoked_False(t *testing.T) {
	repo, mock := newTokenRepo(t)
	mock.ExpectQuery("SELECT EXISTS.*FROM revoked_tokens WHERE jti").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	revoked, err := repo.IsTokenRevoked(context.Background(), "jti-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Error("expected revoked = false")
	}
}

func TestTokenRepository_IsTokenRevoked_DBError(t *testing.T) {
	repo, mock := newTokenRepo(t)
	mock.ExpectQuery("SELECT EXISTS.*FROM revoked_tokens WHERE jti").
		WillReturnError(errDB)

	_, err := repo.IsTokenRevoked(context.Background(), "jti-3")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestTokenRepository_RevokeToken_Success(t *testing.T) {
	repo, mock := newTokenRepo(t)
	mock.ExpectExec("INSERT INTO revoked_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RevokeToken(context.Background(), "jti-4", "user-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenRepository_RevokeToken_DBError(t *testing.T) {
	repo, mock := newTokenRepo(t)
	mock.ExpectExec("INSERT INTO revoked_tokens").
		WillReturnError(errDB)

	if err := repo.RevokeToken(context.Background(), "jti-5", "user-1", time.Now().Add(time.Hour)); err == nil {
		t.Error("expected error, got nil")
	}
}

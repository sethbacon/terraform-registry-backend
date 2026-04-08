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

func TestNewTokenRepository(t *testing.T) {
	repo, _ := newTokenRepo(t)
	if repo == nil {
		t.Fatal("NewTokenRepository returned nil")
	}
}

func TestRevokeToken_Success(t *testing.T) {
	repo, mock := newTokenRepo(t)
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").
		WithArgs("jti-123", "user-456", exp).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RevokeToken(context.Background(), "jti-123", "user-456", exp); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRevokeToken_DBError(t *testing.T) {
	repo, mock := newTokenRepo(t)
	exp := time.Now().Add(time.Hour)

	mock.ExpectExec("INSERT INTO revoked_tokens").
		WillReturnError(errDB)

	if err := repo.RevokeToken(context.Background(), "jti-123", "user-456", exp); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestIsTokenRevoked_True(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("jti-abc").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	revoked, err := repo.IsTokenRevoked(context.Background(), "jti-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Error("expected revoked=true")
	}
}

func TestIsTokenRevoked_False(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("jti-xyz").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	revoked, err := repo.IsTokenRevoked(context.Background(), "jti-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false")
	}
}

func TestIsTokenRevoked_DBError(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectQuery("SELECT EXISTS").
		WillReturnError(errDB)

	_, err := repo.IsTokenRevoked(context.Background(), "jti-bad")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestCleanupExpiredRevocations_Success(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectExec("DELETE FROM revoked_tokens").
		WillReturnResult(sqlmock.NewResult(0, 3))

	if err := repo.CleanupExpiredRevocations(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCleanupExpiredRevocations_DBError(t *testing.T) {
	repo, mock := newTokenRepo(t)

	mock.ExpectExec("DELETE FROM revoked_tokens").
		WillReturnError(errDB)

	if err := repo.CleanupExpiredRevocations(context.Background()); err == nil {
		t.Error("expected error, got nil")
	}
}

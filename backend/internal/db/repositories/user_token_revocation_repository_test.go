package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func newTestUserTokenRevocationRepo(t *testing.T) (*UserTokenRevocationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewUserTokenRevocationRepository(db), mock
}

func TestUserTokenRevocationRepository_RevokeAllUserTokens(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RevokeAllUserTokens(context.Background(), "user-1"); err != nil {
		t.Fatalf("RevokeAllUserTokens: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUserTokenRevocationRepository_RevokeAllUserTokens_DBError(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	mock.ExpectExec("INSERT INTO user_token_revocations").
		WillReturnError(errors.New("db error"))

	if err := repo.RevokeAllUserTokens(context.Background(), "user-1"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUserTokenRevocationRepository_TokensRevokedSince_Revoked(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	issuedAt := time.Now().Add(-time.Hour)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("user-1", issuedAt).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	revoked, err := repo.TokensRevokedSince(context.Background(), "user-1", issuedAt)
	if err != nil {
		t.Fatalf("TokensRevokedSince: %v", err)
	}
	if !revoked {
		t.Error("expected revoked = true")
	}
}

func TestUserTokenRevocationRepository_TokensRevokedSince_NotRevoked(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	issuedAt := time.Now()
	mock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	revoked, err := repo.TokensRevokedSince(context.Background(), "user-1", issuedAt)
	if err != nil {
		t.Fatalf("TokensRevokedSince: %v", err)
	}
	if revoked {
		t.Error("expected revoked = false")
	}
}

func TestUserTokenRevocationRepository_TokensRevokedSince_DBError(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	mock.ExpectQuery("SELECT EXISTS").
		WillReturnError(errors.New("db error"))

	if _, err := repo.TokensRevokedSince(context.Background(), "user-1", time.Now()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUserTokenRevocationRepository_CleanupExpiredWatermarks(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	mock.ExpectExec("DELETE FROM user_token_revocations").
		WillReturnResult(sqlmock.NewResult(0, 3))

	if err := repo.CleanupExpiredWatermarks(context.Background(), 25*time.Hour); err != nil {
		t.Fatalf("CleanupExpiredWatermarks: %v", err)
	}
}

func TestUserTokenRevocationRepository_CleanupExpiredWatermarks_DBError(t *testing.T) {
	repo, mock := newTestUserTokenRevocationRepo(t)

	mock.ExpectExec("DELETE FROM user_token_revocations").
		WillReturnError(errors.New("db error"))

	if err := repo.CleanupExpiredWatermarks(context.Background(), 25*time.Hour); err == nil {
		t.Fatal("expected error, got nil")
	}
}

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func newReleasesGPGRepo(t *testing.T) (*ReleasesGPGKeyRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewReleasesGPGKeyRepository(sqlx.NewDb(db, "postgres")), mock
}

var releasesGPGCols = []string{
	"tool", "armored_key", "primary_fpr", "key_expires_at", "source_url", "fetched_at",
}

func TestReleasesGPGRepo_Get_NoRow(t *testing.T) {
	repo, mock := newReleasesGPGRepo(t)
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("terraform").
		WillReturnRows(sqlmock.NewRows(releasesGPGCols))

	got, err := repo.Get(context.Background(), "terraform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil row, got %+v", got)
	}
}

func TestReleasesGPGRepo_Get_Found(t *testing.T) {
	repo, mock := newReleasesGPGRepo(t)
	expiry := time.Now().Add(365 * 24 * time.Hour)
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("terraform").
		WillReturnRows(sqlmock.NewRows(releasesGPGCols).
			AddRow("terraform", "ARMORED", "C874011F0AB405110D02105534365D9472D7468F", expiry, "https://example.com/key.txt", time.Now()))

	got, err := repo.Get(context.Background(), "terraform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Tool != "terraform" || got.PrimaryFingerprint != "C874011F0AB405110D02105534365D9472D7468F" {
		t.Fatalf("unexpected row: %+v", got)
	}
	if got.KeyExpiresAt == nil {
		t.Fatal("expected KeyExpiresAt to be populated")
	}
}

func TestReleasesGPGRepo_Get_DBError(t *testing.T) {
	repo, mock := newReleasesGPGRepo(t)
	mock.ExpectQuery(`SELECT.*FROM releases_gpg_keys WHERE tool`).
		WithArgs("terraform").
		WillReturnError(fmt.Errorf("db error"))

	if _, err := repo.Get(context.Background(), "terraform"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestReleasesGPGRepo_Upsert_Success(t *testing.T) {
	repo, mock := newReleasesGPGRepo(t)
	expiry := time.Now().Add(365 * 24 * time.Hour)
	mock.ExpectExec(`INSERT INTO releases_gpg_keys`).
		WithArgs("terraform", "ARMORED", "C874011F0AB405110D02105534365D9472D7468F", expiry, "https://example.com/key.txt").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.Upsert(context.Background(), &models.ReleasesGPGKey{
		Tool:               "terraform",
		ArmoredKey:         "ARMORED",
		PrimaryFingerprint: "C874011F0AB405110D02105534365D9472D7468F",
		KeyExpiresAt:       &expiry,
		SourceURL:          "https://example.com/key.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestReleasesGPGRepo_Upsert_DBError(t *testing.T) {
	repo, mock := newReleasesGPGRepo(t)
	mock.ExpectExec(`INSERT INTO releases_gpg_keys`).
		WillReturnError(fmt.Errorf("db error"))

	err := repo.Upsert(context.Background(), &models.ReleasesGPGKey{
		Tool:               "terraform",
		ArmoredKey:         "ARMORED",
		PrimaryFingerprint: "FPR",
		SourceURL:          "https://example.com/key.txt",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

package repositories

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// The two counts DeleteOrganizationHandler refuses on (issue #899).
//
// Both replace an ON DELETE CASCADE that migration 000056 dropped, so the
// predicate is the whole contract: it must key on organization_id and nothing
// else, and it must not fold a NULL owner into somebody's total.

var errCountDB = errors.New("db error")

func newCountRepos(t *testing.T) (*SCMRepository, *MirrorRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("newSQLMock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	return NewSCMRepository(sqlxDB), NewMirrorRepository(sqlxDB), mock
}

func TestCountProvidersByOrganization(t *testing.T) {
	scmRepo, _, mock := newCountRepos(t)
	orgID := uuid.New()
	mock.ExpectQuery("SELECT COUNT.*FROM scm_providers WHERE organization_id").
		WithArgs(orgID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	n, err := scmRepo.CountProvidersByOrganization(context.Background(), orgID)
	if err != nil {
		t.Fatalf("CountProvidersByOrganization: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations not met: %v", err)
	}
}

func TestCountProvidersByOrganization_DBError(t *testing.T) {
	scmRepo, _, mock := newCountRepos(t)
	mock.ExpectQuery("SELECT COUNT.*FROM scm_providers").WillReturnError(errCountDB)

	if _, err := scmRepo.CountProvidersByOrganization(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error, got nil: a failed count must not read as zero")
	}
}

func TestMirrorCountByOrganization(t *testing.T) {
	_, mirrorRepo, mock := newCountRepos(t)
	orgID := uuid.New()
	mock.ExpectQuery("SELECT COUNT.*FROM mirror_configurations WHERE organization_id").
		WithArgs(orgID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	n, err := mirrorRepo.CountByOrganization(context.Background(), orgID)
	if err != nil {
		t.Fatalf("CountByOrganization: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations not met: %v", err)
	}
}

func TestMirrorCountByOrganization_DBError(t *testing.T) {
	_, mirrorRepo, mock := newCountRepos(t)
	mock.ExpectQuery("SELECT COUNT.*FROM mirror_configurations").WillReturnError(errCountDB)

	if _, err := mirrorRepo.CountByOrganization(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error, got nil: a failed count must not read as zero")
	}
}

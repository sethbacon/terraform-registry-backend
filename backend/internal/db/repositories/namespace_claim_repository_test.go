package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

var namespaceClaimCols = []string{"namespace", "organization_id", "claimed_by", "created_at"}
var artifactOrgIDCols = []string{"organization_id"}

var errClaimDB = errors.New("db error")

func newNamespaceClaimRepo(t *testing.T) (*NamespaceClaimRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewNamespaceClaimRepository(db), mock
}

func TestGetClaim_Found(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(namespaceClaimCols).AddRow("acme", "org-1", nil, time.Now()))

	claim, err := repo.GetClaim(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetClaim: %v", err)
	}
	if claim == nil || claim.OrganizationID != "org-1" {
		t.Fatalf("GetClaim = %+v, want organization_id org-1", claim)
	}
}

func TestGetClaim_NotFound(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(namespaceClaimCols))

	claim, err := repo.GetClaim(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("GetClaim: %v", err)
	}
	if claim != nil {
		t.Errorf("GetClaim = %+v, want nil for unclaimed namespace", claim)
	}
}

func TestGetClaim_DBError(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnError(errClaimDB)

	if _, err := repo.GetClaim(context.Background(), "acme"); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestClaimNamespace_FirstClaimWins(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectExec("INSERT INTO namespace_claims").
		WithArgs("acme", "org-1", nil).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(namespaceClaimCols).AddRow("acme", "org-1", nil, time.Now()))

	claim, err := repo.ClaimNamespace(context.Background(), "acme", "org-1", nil)
	if err != nil {
		t.Fatalf("ClaimNamespace: %v", err)
	}
	if claim.OrganizationID != "org-1" {
		t.Errorf("claim.OrganizationID = %q, want org-1", claim.OrganizationID)
	}
}

func TestClaimNamespace_LoserSeesWinningOrg(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	// org-2 races for "acme" but org-1 already holds it (ON CONFLICT DO NOTHING).
	mock.ExpectExec("INSERT INTO namespace_claims").
		WithArgs("acme", "org-2", nil).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(namespaceClaimCols).AddRow("acme", "org-1", nil, time.Now()))

	claim, err := repo.ClaimNamespace(context.Background(), "acme", "org-2", nil)
	if err != nil {
		t.Fatalf("ClaimNamespace: %v", err)
	}
	if claim.OrganizationID != "org-1" {
		t.Errorf("claim.OrganizationID = %q, want org-1 (the winner of the race)", claim.OrganizationID)
	}
}

func TestClaimNamespace_InsertError(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectExec("INSERT INTO namespace_claims").
		WillReturnError(errClaimDB)

	if _, err := repo.ClaimNamespace(context.Background(), "acme", "org-1", nil); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestArtifactOrganizations_Multiple(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(artifactOrgIDCols).AddRow("org-1").AddRow("org-2"))

	orgIDs, err := repo.ArtifactOrganizations(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ArtifactOrganizations: %v", err)
	}
	if len(orgIDs) != 2 {
		t.Fatalf("ArtifactOrganizations = %v, want 2 entries", orgIDs)
	}
}

func TestArtifactOrganizations_None(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnRows(sqlmock.NewRows(artifactOrgIDCols))

	orgIDs, err := repo.ArtifactOrganizations(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("ArtifactOrganizations: %v", err)
	}
	if len(orgIDs) != 0 {
		t.Errorf("ArtifactOrganizations = %v, want empty", orgIDs)
	}
}

func TestArtifactOrganizations_QueryError(t *testing.T) {
	repo, mock := newNamespaceClaimRepo(t)

	mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
		WillReturnError(errClaimDB)

	if _, err := repo.ArtifactOrganizations(context.Background(), "acme"); err == nil {
		t.Error("expected error, got nil")
	}
}

package jobs

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func sampleOrphanOrgRow() *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(orphanOrgCols).
		AddRow(uuid.New().String(), "default", "Default", "local", "local", now, now)
}

func emptyOrphanOrgRows() *sqlmock.Rows { return sqlmock.NewRows(orphanOrgCols) }

// GUARD provider-owner-org-is-decided-not-defaulted (issue #932).
//
// An empty organization becomes SQL NULL in CreateProvider, and this repository
// reads a NULL owner as "visible to EVERY organization" -- the opposite of what
// the sibling state-manager means by the same NULL. So the mirror job's choice
// of owner is a tenancy decision, and the one thing it must never do is reach
// the widest possible answer by accident.
//
// It used to. The fallback was `if err == nil && defaultOrg != nil`, so a
// failed lookup fell through with the organization still empty: the same mirror
// produced an organization-owned provider or a globally visible one depending
// on whether an unrelated query happened to succeed.

func TestProviderOwnerOrganization_ConfiguredOrganizationWins(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	orgID := uuid.New()
	got, err := job.providerOwnerOrganization(context.Background(), orgBoundMirror(&orgID))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != orgID.String() {
		t.Fatalf("owner = %q, want the mirror's own organization %q", got, orgID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a mirror that names its organization must not query for a default: %v", err)
	}
}

func TestProviderOwnerOrganization_GlobalMirrorTakesTheDefaultOrganization(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrphanOrgRow())

	got, err := job.providerOwnerOrganization(context.Background(), orgBoundMirror(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Fatal("a resolved default organization must own the provider, not NULL")
	}
}

func TestProviderOwnerOrganization_LookupFailureRefusesRatherThanWidening(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnError(errMirrorOrphanDB)

	got, err := job.providerOwnerOrganization(context.Background(), orgBoundMirror(nil))
	if err == nil {
		t.Fatalf("a failed default-organization lookup returned owner %q and no error; "+
			"an empty owner is written as NULL and read as visible to every organization", got)
	}
	if got != "" {
		t.Fatalf("owner = %q on the error path, want empty", got)
	}
}

func TestProviderOwnerOrganization_NoDefaultOrganizationIsADeliberateNull(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	// Single-tenant: there is no default organization to own the row, so NULL
	// is the intended answer rather than an accident.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(emptyOrphanOrgRows())

	got, err := job.providerOwnerOrganization(context.Background(), orgBoundMirror(nil))
	if err != nil {
		t.Fatalf("a deployment with no default organization is not an error: %v", err)
	}
	if got != "" {
		t.Fatalf("owner = %q, want empty so the provider is written NULL", got)
	}
}

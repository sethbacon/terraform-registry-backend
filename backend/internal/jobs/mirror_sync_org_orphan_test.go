package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// GUARD mirror-owner-org-exists (issue #899).
//
// GetMirrorsNeedingSync applies no tenancy filter and no organization-existence
// filter — verified against the query itself, which selects on enabled, the
// sync interval and last_sync_status only. Until migration 000056 it did not
// need one: mirror_configurations.organization_id was ON DELETE CASCADE, so an
// orphaned mirror could not exist. Issue #883 dropped that constraint, and an
// orphan now keeps running on schedule forever, stamping every provider it
// creates with the dead organization id — while tenantscope.Permits denies a
// foreign organization, so no non-platform administrator can even see the row
// to stop it.

func newOrphanOrgRepo(t *testing.T) (*repositories.OrganizationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOrganizationRepository(db), mock
}

var errMirrorOrphanDB = errors.New("identity db error")

var orphanOrgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}

func orgBoundMirror(orgID *uuid.UUID) models.MirrorConfiguration {
	return models.MirrorConfiguration{
		ID:                  uuid.New(),
		Name:                "upstream",
		UpstreamRegistryURL: "https://registry.example.invalid",
		OrganizationID:      orgID,
		Enabled:             true,
		SyncIntervalHours:   24,
	}
}

// ---------------------------------------------------------------------------
// ownerOrganizationLives — the guard's decision, in isolation
// ---------------------------------------------------------------------------

func TestOwnerOrganizationLives_DeletedOrganizationStopsTheMirror(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	orgID := uuid.New()
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID.String()).
		WillReturnRows(sqlmock.NewRows(orphanOrgCols))

	if job.ownerOrganizationLives(context.Background(), orgBoundMirror(&orgID)) {
		t.Fatal("a mirror whose organization no longer exists must not sync")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the organization was never looked up: %v", err)
	}
}

func TestOwnerOrganizationLives_LiveOrganizationStillSyncs(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	orgID := uuid.New()
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows(orphanOrgCols).
			AddRow(orgID.String(), "acme", "Acme", nil, nil, time.Now(), time.Now()))

	if !job.ownerOrganizationLives(context.Background(), orgBoundMirror(&orgID)) {
		t.Fatal("a mirror whose organization exists must still sync")
	}
}

// A global mirror (NULL organization_id) is owned by nobody and has nothing to
// outlive. No query is queued, so a lookup made here would fail the assertion
// below rather than silently pass.
func TestOwnerOrganizationLives_GlobalMirrorIsNotChecked(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	if !job.ownerOrganizationLives(context.Background(), orgBoundMirror(nil)) {
		t.Fatal("a global mirror must sync")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations not met: %v", err)
	}
}

// Fail OPEN, deliberately and only here: a transient identity-database fault
// would otherwise stop every organization-bound mirror in the deployment at
// once, which is a far larger outage than one extra sync of a mirror that is
// probably fine. The fail-CLOSED decision is on the webhook path, where a
// credential is being honoured.
func TestOwnerOrganizationLives_LookupFailureFailsOpen(t *testing.T) {
	orgRepo, mock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(nil, nil, nil, orgRepo, nil, "")

	orgID := uuid.New()
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnError(errMirrorOrphanDB)

	if !job.ownerOrganizationLives(context.Background(), orgBoundMirror(&orgID)) {
		t.Fatal("a failed lookup must not stop the mirror")
	}
}

// ---------------------------------------------------------------------------
// runScheduledSyncs — the decision actually wired into the loop
// ---------------------------------------------------------------------------

// The sync-history INSERT is queued as a NEGATIVE expectation: syncMirror
// writes it first thing, so it is the earliest observable proof that a sync
// started. With the guard in place it must never be reached, which is why this
// test asserts that the expectation went UNFULFILLED.
func TestRunScheduledSyncs_SkipsMirrorWhoseOrganizationIsGone(t *testing.T) {
	mirrorDB, mirrorMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { mirrorDB.Close() })
	mirrorRepo := repositories.NewMirrorRepository(sqlx.NewDb(mirrorDB, "sqlmock"))

	orgRepo, orgMock := newOrphanOrgRepo(t)
	job := NewMirrorSyncJob(mirrorRepo, nil, nil, orgRepo, nil, "")

	orgID := uuid.New()
	mirrorMock.ExpectQuery("SELECT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols).AddRow(
			uuid.New(), "orphaned", nil, "https://registry.example.invalid", orgID,
			nil, nil, nil, nil,
			true, 24, nil, nil,
			nil, time.Now(), time.Now(), nil,
		))
	orgMock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows(orphanOrgCols)) // gone
	mirrorMock.ExpectExec("INSERT INTO mirror_sync_history").
		WillReturnResult(sqlmock.NewResult(1, 1))

	job.runScheduledSyncs(context.Background())

	job.activeSyncsMutex.Lock()
	active := len(job.activeSyncs)
	job.activeSyncsMutex.Unlock()
	if active != 0 {
		t.Errorf("a sync was started for a mirror whose organization is gone (%d active)", active)
	}

	// Give a mutated build time to reach the insert before the assertion.
	time.Sleep(200 * time.Millisecond)
	if err := mirrorMock.ExpectationsWereMet(); err == nil {
		t.Error("the sync-history insert ran: the orphaned mirror synced anyway")
	}
	if err := orgMock.ExpectationsWereMet(); err != nil {
		t.Errorf("the organization was never looked up: %v", err)
	}
}

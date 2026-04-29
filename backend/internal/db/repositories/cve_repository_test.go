package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

var cveCols = []string{
	"id", "source", "source_id", "severity", "summary", "details",
	"references", "published_at", "modified_at", "fetched_at",
	"withdrawn_at", "created_at", "updated_at",
}

var cveTargetCols = []string{
	"id", "advisory_id", "target_kind", "fingerprint", "target_ref",
	"terraform_version_id", "provider_version_id", "created_at",
}

func newCVERepo(t *testing.T) (*CVERepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewCVERepository(db), mock
}

// ---------------------------------------------------------------------------
// NewCVERepository
// ---------------------------------------------------------------------------

func TestNewCVERepository_NotNil(t *testing.T) {
	repo, _ := newCVERepo(t)
	if repo == nil {
		t.Fatal("expected non-nil CVERepository")
	}
}

// ---------------------------------------------------------------------------
// ExistsAdvisory
// ---------------------------------------------------------------------------

func TestExistsAdvisory_True(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WithArgs("osv", "CVE-2024-0001").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	exists, err := repo.ExistsAdvisory(context.Background(), "osv", "CVE-2024-0001")
	if err != nil {
		t.Fatalf("ExistsAdvisory error: %v", err)
	}
	if !exists {
		t.Error("expected exists=true")
	}
}

func TestExistsAdvisory_False(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WithArgs("osv", "CVE-9999-0001").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	exists, err := repo.ExistsAdvisory(context.Background(), "osv", "CVE-9999-0001")
	if err != nil {
		t.Fatalf("ExistsAdvisory error: %v", err)
	}
	if exists {
		t.Error("expected exists=false")
	}
}

func TestExistsAdvisory_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WithArgs("osv", "CVE-2024-0001").
		WillReturnError(errors.New("db error"))

	_, err := repo.ExistsAdvisory(context.Background(), "osv", "CVE-2024-0001")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// MarkWithdrawn
// ---------------------------------------------------------------------------

func TestMarkWithdrawn_Success(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectExec("UPDATE cve_advisories").
		WithArgs(sqlmock.AnyArg(), "osv", "CVE-2024-0002").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.MarkWithdrawn(context.Background(), "osv", "CVE-2024-0002")
	if err != nil {
		t.Fatalf("MarkWithdrawn error: %v", err)
	}
}

func TestMarkWithdrawn_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectExec("UPDATE cve_advisories").
		WithArgs(sqlmock.AnyArg(), "osv", "CVE-2024-0002").
		WillReturnError(errors.New("db error"))

	err := repo.MarkWithdrawn(context.Background(), "osv", "CVE-2024-0002")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListAll
// ---------------------------------------------------------------------------

func TestListAll_Empty(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols))

	result, err := repo.ListAll(context.Background(), "")
	if err != nil {
		t.Fatalf("ListAll error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 results, got %d", len(result))
	}
}

func TestListAll_WithRow(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols).AddRow(
			id, "osv", "CVE-2024-1111", "critical", "Summary", "Details",
			[]byte(`["https://ref.example.com"]`), &now, &now, now, nil, now, now,
		))

	result, err := repo.ListAll(context.Background(), "")
	if err != nil {
		t.Fatalf("ListAll error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].SourceID != "CVE-2024-1111" {
		t.Errorf("SourceID = %q, want CVE-2024-1111", result[0].SourceID)
	}
	if len(result[0].References) != 1 || result[0].References[0] != "https://ref.example.com" {
		t.Errorf("References = %v", result[0].References)
	}
}

func TestListAll_WithKindFilter(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WithArgs("binary").
		WillReturnRows(sqlmock.NewRows(cveCols))

	_, err := repo.ListAll(context.Background(), "binary")
	if err != nil {
		t.Fatalf("ListAll with kind filter error: %v", err)
	}
}

func TestListAll_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnError(errors.New("db error"))

	_, err := repo.ListAll(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpsertAdvisory
// ---------------------------------------------------------------------------

func TestUpsertAdvisory_New(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("INSERT INTO cve_advisories").
		WillReturnRows(sqlmock.NewRows([]string{"id", "is_new"}).AddRow(id, true))

	advisory := &models.CVEAdvisory{
		Source:      "osv",
		SourceID:    "CVE-2024-9999",
		Severity:    models.CVESeverityHigh,
		Summary:     "Test advisory",
		References:  []string{"https://example.com"},
		PublishedAt: &now,
	}

	retID, isNew, err := repo.UpsertAdvisory(context.Background(), advisory)
	if err != nil {
		t.Fatalf("UpsertAdvisory error: %v", err)
	}
	if retID != id {
		t.Errorf("returned ID = %v, want %v", retID, id)
	}
	if !isNew {
		t.Error("expected isNew=true")
	}
}

func TestUpsertAdvisory_Existing(t *testing.T) {
	id := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("INSERT INTO cve_advisories").
		WillReturnRows(sqlmock.NewRows([]string{"id", "is_new"}).AddRow(id, false))

	advisory := &models.CVEAdvisory{
		Source:     "osv",
		SourceID:   "CVE-2024-9999",
		Severity:   models.CVESeverityLow,
		References: []string{},
	}

	_, isNew, err := repo.UpsertAdvisory(context.Background(), advisory)
	if err != nil {
		t.Fatalf("UpsertAdvisory error: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false for existing advisory")
	}
}

func TestUpsertAdvisory_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("INSERT INTO cve_advisories").
		WillReturnError(errors.New("constraint violation"))

	advisory := &models.CVEAdvisory{
		Source:     "osv",
		SourceID:   "CVE-2024-0000",
		References: []string{},
	}

	_, _, err := repo.UpsertAdvisory(context.Background(), advisory)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ReplaceAffectedTargets
// ---------------------------------------------------------------------------

func TestReplaceAffectedTargets_EmptyTargets(t *testing.T) {
	repo, mock := newCVERepo(t)
	advisoryID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM cve_affected_targets").
		WithArgs(advisoryID, "binary").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	err := repo.ReplaceAffectedTargets(context.Background(), advisoryID, models.CVETargetKindBinary, nil)
	if err != nil {
		t.Fatalf("ReplaceAffectedTargets error: %v", err)
	}
}

func TestReplaceAffectedTargets_WithTarget(t *testing.T) {
	repo, mock := newCVERepo(t)
	advisoryID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM cve_affected_targets").
		WithArgs(advisoryID, "binary").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO cve_affected_targets").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	targets := []models.CVEAffectedTarget{
		{
			AdvisoryID:  advisoryID,
			TargetKind:  models.CVETargetKindBinary,
			Fingerprint: "cfg:ver",
			TargetRef:   models.CVETargetRef{Tool: "terraform", Version: "1.5.0"},
		},
	}

	err := repo.ReplaceAffectedTargets(context.Background(), advisoryID, models.CVETargetKindBinary, targets)
	if err != nil {
		t.Fatalf("ReplaceAffectedTargets error: %v", err)
	}
}

func TestReplaceAffectedTargets_BeginTxError(t *testing.T) {
	repo, mock := newCVERepo(t)
	advisoryID := uuid.New()

	mock.ExpectBegin().WillReturnError(errors.New("db error"))

	err := repo.ReplaceAffectedTargets(context.Background(), advisoryID, models.CVETargetKindBinary, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListAllBinaryCandidates
// ---------------------------------------------------------------------------

func TestListAllBinaryCandidates_Empty(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("terraform_versions").
		WillReturnRows(sqlmock.NewRows([]string{"config_id", "tool", "version_id", "version"}))

	result, err := repo.ListAllBinaryCandidates(context.Background())
	if err != nil {
		t.Fatalf("ListAllBinaryCandidates error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates, got %d", len(result))
	}
}

func TestListAllBinaryCandidates_WithRow(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("terraform_versions").
		WillReturnRows(sqlmock.NewRows([]string{"config_id", "tool", "version_id", "version"}).
			AddRow("cfg-1", "terraform", "ver-1", "1.5.0"))

	result, err := repo.ListAllBinaryCandidates(context.Background())
	if err != nil {
		t.Fatalf("ListAllBinaryCandidates error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(result))
	}
	if result[0].Tool != "terraform" || result[0].Version != "1.5.0" {
		t.Errorf("unexpected candidate: %+v", result[0])
	}
}

// ---------------------------------------------------------------------------
// ListAllProviderCandidates
// ---------------------------------------------------------------------------

func TestListAllProviderCandidates_Empty(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"p_id", "pv_id", "namespace", "type", "version", "source"}))

	result, err := repo.ListAllProviderCandidates(context.Background())
	if err != nil {
		t.Fatalf("ListAllProviderCandidates error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates, got %d", len(result))
	}
}

func TestListAllProviderCandidates_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("provider_versions").
		WillReturnError(errors.New("db error"))

	_, err := repo.ListAllProviderCandidates(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListAllBinaryCandidates_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("terraform_versions").
		WillReturnError(errors.New("db error"))

	_, err := repo.ListAllBinaryCandidates(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestReplaceAffectedTargets_DeleteError(t *testing.T) {
	repo, mock := newCVERepo(t)
	advisoryID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM cve_affected_targets").
		WithArgs(advisoryID, "scanner").
		WillReturnError(errors.New("delete failed"))
	mock.ExpectRollback()

	err := repo.ReplaceAffectedTargets(context.Background(), advisoryID, models.CVETargetKindScanner, nil)
	if err == nil {
		t.Fatal("expected error from delete failure, got nil")
	}
}

func TestListAllProviderCandidates_WithRow(t *testing.T) {
	repo, mock := newCVERepo(t)

	var source *string
	mock.ExpectQuery("provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"p_id", "pv_id", "namespace", "type", "version", "source"}).
			AddRow("prov-1", "pv-1", "hashicorp", "aws", "5.0.0", source))

	result, err := repo.ListAllProviderCandidates(context.Background())
	if err != nil {
		t.Fatalf("ListAllProviderCandidates error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(result))
	}
	if result[0].Namespace != "hashicorp" || result[0].ProviderType != "aws" {
		t.Errorf("unexpected candidate: %+v", result[0])
	}
}

// ---------------------------------------------------------------------------
// ListActive + listTargetsForAdvisory
// ---------------------------------------------------------------------------

func TestListActive_Empty(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols))

	result, err := repo.ListActive(context.Background())
	if err != nil {
		t.Fatalf("ListActive error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 results, got %d", len(result))
	}
}

func TestListActive_DBError(t *testing.T) {
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnError(errors.New("db error"))

	_, err := repo.ListActive(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListActive_WithAdvisoryNoTargets(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols).AddRow(
			id, "osv", "CVE-2024-5555", "high", "Advisory summary", "Details",
			[]byte(`["https://example.com"]`), &now, nil, now, nil, now, now,
		))
	// listTargetsForAdvisory call for this advisory
	mock.ExpectQuery("cve_affected_targets").
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows(cveTargetCols))

	result, err := repo.ListActive(context.Background())
	if err != nil {
		t.Fatalf("ListActive error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(result))
	}
	if result[0].SourceID != "CVE-2024-5555" {
		t.Errorf("SourceID = %q", result[0].SourceID)
	}
	if len(result[0].Targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(result[0].Targets))
	}
}

func TestListActive_WithAdvisoryWithTargets(t *testing.T) {
	now := time.Now()
	advisoryID := uuid.New()
	targetID := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols).AddRow(
			advisoryID, "osv", "GHSA-0099", "critical", "Scanner vuln", "",
			[]byte(`[]`), nil, nil, now, nil, now, now,
		))
	mock.ExpectQuery("cve_affected_targets").
		WithArgs(advisoryID).
		WillReturnRows(sqlmock.NewRows(cveTargetCols).AddRow(
			targetID, advisoryID, "scanner", "trivy:0.50.0",
			[]byte(`{"tool":"trivy","version":"0.50.0"}`),
			nil, nil, now,
		))

	result, err := repo.ListActive(context.Background())
	if err != nil {
		t.Fatalf("ListActive error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(result))
	}
	if len(result[0].Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(result[0].Targets))
	}
	if result[0].Targets[0].TargetKind != "scanner" {
		t.Errorf("TargetKind = %q, want scanner", result[0].Targets[0].TargetKind)
	}
	if result[0].Targets[0].TargetRef.Tool != "trivy" {
		t.Errorf("TargetRef.Tool = %q, want trivy", result[0].Targets[0].TargetRef.Tool)
	}
}

func TestListActive_TargetQueryError(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	repo, mock := newCVERepo(t)

	mock.ExpectQuery("cve_advisories").
		WillReturnRows(sqlmock.NewRows(cveCols).AddRow(
			id, "osv", "CVE-2024-1", "low", "Summary", "",
			[]byte(`[]`), nil, nil, now, nil, now, now,
		))
	mock.ExpectQuery("cve_affected_targets").
		WithArgs(id).
		WillReturnError(errors.New("targets db error"))

	_, err := repo.ListActive(context.Background())
	if err == nil {
		t.Fatal("expected error when target query fails, got nil")
	}
}

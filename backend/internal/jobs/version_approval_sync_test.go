package jobs

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

func strptr(s string) *string { return &s }

// resolveProviderApproval

func TestResolveProviderApproval_NotGated(t *testing.T) {
	job := NewMirrorSyncJob(nil, nil, nil, nil, nil, "")
	cfg := models.MirrorConfiguration{RequiresApproval: false}

	status, rule := job.resolveProviderApproval(context.Background(), cfg, uuid.New(), "1.0.0", true)
	if status != nil || rule != "" {
		t.Fatalf("ungated mirror must yield (nil,\"\"), got (%v,%q)", status, rule)
	}
}

func TestResolveProviderApproval_GatedNoRules(t *testing.T) {
	job := NewMirrorSyncJob(nil, nil, nil, nil, nil, "")
	cfg := models.MirrorConfiguration{RequiresApproval: true}

	status, rule := job.resolveProviderApproval(context.Background(), cfg, uuid.New(), "1.0.0", true)
	if status == nil || *status != models.VersionApprovalStatusPending || rule != "" {
		t.Fatalf("gated mirror without rules must be pending, got (%v,%q)", status, rule)
	}
}

func TestResolveProviderApproval_AutoApproved(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := repositories.NewMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	job := NewMirrorSyncJob(repo, nil, nil, nil, nil, "")

	// Existing-versions lookup (no rows needed; gpg_verified rule ignores them).
	mock.ExpectQuery(`SELECT.*FROM mirrored_provider_versions`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	cfg := models.MirrorConfiguration{
		RequiresApproval: true,
		AutoApproveRules: strptr(`{"mode":"any","rules":[{"type":"gpg_verified"}]}`),
	}

	status, rule := job.resolveProviderApproval(context.Background(), cfg, uuid.New(), "1.0.0", true)
	if status == nil || *status != models.VersionApprovalStatusApproved || rule != "gpg_verified" {
		t.Fatalf("gpg-verified version should auto-approve, got (%v,%q)", status, rule)
	}
}

// resolveTerraformApproval

func TestResolveTerraformApproval_NotGated(t *testing.T) {
	job := NewTerraformMirrorSyncJob(nil, nil, "local")
	cfg := &models.TerraformMirrorConfig{RequiresApproval: false}

	if status := job.resolveTerraformApproval(context.Background(), cfg, "1.9.0"); status != nil {
		t.Fatalf("ungated terraform mirror must yield nil, got %v", status)
	}
}

func TestResolveTerraformApproval_GatedNoRules(t *testing.T) {
	job := NewTerraformMirrorSyncJob(nil, nil, "local")
	cfg := &models.TerraformMirrorConfig{RequiresApproval: true}

	status := job.resolveTerraformApproval(context.Background(), cfg, "1.9.0")
	if status == nil || *status != models.VersionApprovalStatusPending {
		t.Fatalf("gated terraform mirror without rules must be pending, got %v", status)
	}
}

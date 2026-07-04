// scanner_binary_version_repository.go provides database operations for module
// security-scanner (trivy/terrascan/checkov) binary versions discovered by the
// scheduled update-check job. Rows plug into the generic version-approval
// workflow (see version_approval_repository.go) as type="scanner".
package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ScannerBinaryVersionRepository handles database operations for scanner binary versions.
type ScannerBinaryVersionRepository struct {
	db *sqlx.DB
}

// NewScannerBinaryVersionRepository creates a new ScannerBinaryVersionRepository.
func NewScannerBinaryVersionRepository(db *sqlx.DB) *ScannerBinaryVersionRepository {
	return &ScannerBinaryVersionRepository{db: db}
}

// Upsert inserts a discovered version row, or does nothing if (tool, version)
// already exists. Returns the resulting row (including generated fields).
// approval_status is intentionally NOT touched on conflict: a re-discovery
// must never reset an already-decided version back to pending.
func (r *ScannerBinaryVersionRepository) Upsert(ctx context.Context, v *models.ScannerBinaryVersion) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}

	query := `
		INSERT INTO scanner_binary_versions (
			id, tool, version, source_url, sha256, signature_verified, signature_type,
			sync_status, approval_status, is_active, binary_path
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (tool, version) DO NOTHING
		RETURNING id, tool, version, source_url, sha256, signature_verified, signature_type,
		          sync_status, approval_status, is_active, binary_path, discovered_at, created_at
	`

	err := r.db.QueryRowContext(ctx, query,
		v.ID,
		v.Tool,
		v.Version,
		v.SourceURL,
		v.Sha256,
		v.SignatureVerified,
		v.SignatureType,
		v.SyncStatus,
		v.ApprovalStatus,
		v.IsActive,
		v.BinaryPath,
	).Scan(
		&v.ID,
		&v.Tool,
		&v.Version,
		&v.SourceURL,
		&v.Sha256,
		&v.SignatureVerified,
		&v.SignatureType,
		&v.SyncStatus,
		&v.ApprovalStatus,
		&v.IsActive,
		&v.BinaryPath,
		&v.DiscoveredAt,
		&v.CreatedAt,
	)
	if err == sql.ErrNoRows {
		// Conflict hit DO NOTHING: row already existed, nothing was returned.
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to upsert scanner binary version: %w", err)
	}
	return nil
}

// GetByToolVersion looks up a version row by tool+version, or nil if not found.
func (r *ScannerBinaryVersionRepository) GetByToolVersion(ctx context.Context, tool, version string) (*models.ScannerBinaryVersion, error) {
	query := `
		SELECT id, tool, version, source_url, sha256, signature_verified, signature_type,
		       sync_status, approval_status, is_active, binary_path, discovered_at, created_at
		FROM scanner_binary_versions
		WHERE tool = $1 AND version = $2
	`

	var v models.ScannerBinaryVersion
	err := r.db.GetContext(ctx, &v, query, tool, version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scanner binary version: %w", err)
	}

	return &v, nil
}

// ListForTool returns all version rows for a tool, newest discovered first.
func (r *ScannerBinaryVersionRepository) ListForTool(ctx context.Context, tool string) ([]models.ScannerBinaryVersion, error) {
	query := `
		SELECT id, tool, version, source_url, sha256, signature_verified, signature_type,
		       sync_status, approval_status, is_active, binary_path, discovered_at, created_at
		FROM scanner_binary_versions
		WHERE tool = $1
		ORDER BY discovered_at DESC
	`

	var versions []models.ScannerBinaryVersion
	if err := r.db.SelectContext(ctx, &versions, query, tool); err != nil {
		return nil, fmt.Errorf("failed to list scanner binary versions: %w", err)
	}

	return versions, nil
}

// ListApprovedInactive returns approved-but-not-yet-active versions across all
// tools, for the activation reconciler to pick up.
func (r *ScannerBinaryVersionRepository) ListApprovedInactive(ctx context.Context) ([]models.ScannerBinaryVersion, error) {
	query := `
		SELECT id, tool, version, source_url, sha256, signature_verified, signature_type,
		       sync_status, approval_status, is_active, binary_path, discovered_at, created_at
		FROM scanner_binary_versions
		WHERE approval_status = 'approved' AND NOT is_active
	`

	var versions []models.ScannerBinaryVersion
	if err := r.db.SelectContext(ctx, &versions, query); err != nil {
		return nil, fmt.Errorf("failed to list approved inactive scanner binary versions: %w", err)
	}

	return versions, nil
}

// MarkActive marks the given version as the active binary for its tool,
// demoting any previously active version of the same tool. Only one row per
// tool can be active at a time.
func (r *ScannerBinaryVersionRepository) MarkActive(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE scanner_binary_versions SET is_active = false
		 WHERE tool = (SELECT tool FROM scanner_binary_versions WHERE id = $1)`,
		id); err != nil {
		return fmt.Errorf("failed to demote active scanner binary versions: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE scanner_binary_versions SET is_active = true WHERE id = $1`,
		id); err != nil {
		return fmt.Errorf("failed to mark scanner binary version active: %w", err)
	}

	return tx.Commit()
}

// GetActive returns the currently active binary version for a tool, or nil if none.
func (r *ScannerBinaryVersionRepository) GetActive(ctx context.Context, tool string) (*models.ScannerBinaryVersion, error) {
	query := `
		SELECT id, tool, version, source_url, sha256, signature_verified, signature_type,
		       sync_status, approval_status, is_active, binary_path, discovered_at, created_at
		FROM scanner_binary_versions
		WHERE tool = $1 AND is_active
	`

	var v models.ScannerBinaryVersion
	err := r.db.GetContext(ctx, &v, query, tool)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active scanner binary version: %w", err)
	}

	return &v, nil
}

// Delete removes a scanner binary version row.
func (r *ScannerBinaryVersionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM scanner_binary_versions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete scanner binary version: %w", err)
	}

	return nil
}

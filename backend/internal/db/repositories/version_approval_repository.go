// version_approval_repository.go provides database operations for the version
// approval gate. It presents provider-mirror versions (mirrored_provider_versions)
// and terraform-binary-mirror versions (terraform_versions) through one uniform
// VersionApproval shape, and records every approve/reject decision in
// version_approval_events.
//
// Only versions that are actually gated (approval_status IS NOT NULL) are
// surfaced here — versions belonging to mirrors without requires_approval keep
// a NULL status and never appear in the approvals queue.
package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// VersionApprovalRepository handles version approval queries and mutations.
type VersionApprovalRepository struct {
	db *sqlx.DB
}

// NewVersionApprovalRepository creates a new VersionApprovalRepository.
func NewVersionApprovalRepository(db *sqlx.DB) *VersionApprovalRepository {
	return &VersionApprovalRepository{db: db}
}

// VersionApprovalFilter narrows the list query. Empty fields mean "no filter".
type VersionApprovalFilter struct {
	Status   string // pending_approval | approved | rejected
	Type     string // provider | terraform
	ConfigID string // mirror config UUID
	Limit    int
	Offset   int
}

// semverOrder is the reusable "highest semver first" ordering applied to a
// version column; matches the expression used elsewhere in the mirror repos.
const semverOrder = `COALESCE(CAST(NULLIF(SPLIT_PART(REGEXP_REPLACE(REGEXP_REPLACE(version, '^v', ''), '[-+].*$', ''), '.', 1), '') AS INTEGER), 0) DESC,
	COALESCE(CAST(NULLIF(SPLIT_PART(REGEXP_REPLACE(REGEXP_REPLACE(version, '^v', ''), '[-+].*$', ''), '.', 2), '') AS INTEGER), 0) DESC,
	COALESCE(CAST(NULLIF(SPLIT_PART(REGEXP_REPLACE(REGEXP_REPLACE(version, '^v', ''), '[-+].*$', ''), '.', 3), '') AS INTEGER), 0) DESC`

// providerSelect is the provider-version branch of the unified query. Only
// gated versions are included.
const providerSelect = `
	SELECT mpv.id AS id, 'provider' AS type, mpv.upstream_version AS version,
	       mpv.approval_status AS approval_status,
	       mp.upstream_namespace AS provider_namespace,
	       mp.upstream_type AS provider_name,
	       mc.name AS mirror_config_name, mc.id AS mirror_config_id,
	       mpv.gpg_verified AS gpg_verified, mpv.shasum_verified AS shasum_verified,
	       mpv.synced_at AS synced_at
	FROM mirrored_provider_versions mpv
	JOIN mirrored_providers mp ON mp.id = mpv.mirrored_provider_id
	JOIN mirror_configurations mc ON mc.id = mp.mirror_config_id
	WHERE mpv.approval_status IS NOT NULL`

// terraformSelect is the terraform-version branch. gpg/shasum verification is
// per-platform, so it is aggregated to a single bool with EXISTS.
const terraformSelect = `
	SELECT tv.id AS id, 'terraform' AS type, tv.version AS version,
	       tv.approval_status AS approval_status,
	       NULL::text AS provider_namespace, NULL::text AS provider_name,
	       tmc.name AS mirror_config_name, tmc.id AS mirror_config_id,
	       EXISTS(SELECT 1 FROM terraform_version_platforms p WHERE p.version_id = tv.id AND p.gpg_verified) AS gpg_verified,
	       EXISTS(SELECT 1 FROM terraform_version_platforms p WHERE p.version_id = tv.id AND p.sha256_verified) AS shasum_verified,
	       COALESCE(tv.synced_at, tv.created_at) AS synced_at
	FROM terraform_versions tv
	JOIN terraform_mirror_configs tmc ON tmc.id = tv.config_id
	WHERE tv.approval_status IS NOT NULL`

// scannerSelect is the scanner-binary-version branch. There is no mirror config
// for a scanner tool, so mirror_config_name/id are fixed placeholder values.
const scannerSelect = `
	SELECT sbv.id AS id, 'scanner' AS type, sbv.version AS version,
	       sbv.approval_status AS approval_status,
	       NULL::text AS provider_namespace, NULL::text AS provider_name,
	       'Security Scanner' AS mirror_config_name,
	       '00000000-0000-0000-0000-000000000000'::uuid AS mirror_config_id,
	       sbv.signature_verified AS gpg_verified, sbv.signature_verified AS shasum_verified,
	       sbv.discovered_at AS synced_at
	FROM scanner_binary_versions sbv
	WHERE sbv.approval_status IS NOT NULL`

// innerQuery builds the UNION-ALL subquery honouring the type filter.
func innerQuery(typeFilter string) string {
	switch typeFilter {
	case models.VersionApprovalTypeProvider:
		return providerSelect
	case models.VersionApprovalTypeTerraform:
		return terraformSelect
	case models.VersionApprovalTypeScanner:
		return scannerSelect
	default:
		return providerSelect + "\nUNION ALL" + terraformSelect + "\nUNION ALL" + scannerSelect
	}
}

// List returns gated versions matching the filter, plus the total count
// (ignoring limit/offset). status and config_id are applied as $1/$2 which the
// inner branches expose through the va.* outer alias.
func (r *VersionApprovalRepository) List(ctx context.Context, f VersionApprovalFilter) ([]models.VersionApproval, int, error) {
	var statusArg, configArg interface{}
	if f.Status != "" {
		statusArg = f.Status
	}
	if f.ConfigID != "" {
		configArg = f.ConfigID
	}

	where := `WHERE ($1::text IS NULL OR va.approval_status = $1)
	            AND ($2::uuid IS NULL OR va.mirror_config_id = $2)`

	inner := innerQuery(f.Type)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM (%s) AS va %s", inner, where)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, statusArg, configArg).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count version approvals: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	listQuery := fmt.Sprintf(
		"SELECT * FROM (%s) AS va %s ORDER BY va.synced_at DESC LIMIT %d OFFSET %d",
		inner, where, limit, offset,
	)

	var items []models.VersionApproval
	if err := r.db.SelectContext(ctx, &items, listQuery, statusArg, configArg); err != nil {
		return nil, 0, fmt.Errorf("failed to list version approvals: %w", err)
	}
	if items == nil {
		items = []models.VersionApproval{}
	}
	return items, total, nil
}

// PendingCount returns the number of versions awaiting approval across both
// provider and terraform mirrors. Used for the dashboard badge.
func (r *VersionApprovalRepository) PendingCount(ctx context.Context) (int, error) {
	const q = `
		SELECT
		  (SELECT COUNT(*) FROM mirrored_provider_versions WHERE approval_status = $1) +
		  (SELECT COUNT(*) FROM terraform_versions WHERE approval_status = $1) +
		  (SELECT COUNT(*) FROM scanner_binary_versions WHERE approval_status = $1)`
	var count int
	if err := r.db.QueryRowContext(ctx, q, models.VersionApprovalStatusPending).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count pending approvals: %w", err)
	}
	return count, nil
}

// SetStatus transitions a single gated version to newStatus (approved|rejected),
// records an audit event, and recomputes is_latest for terraform mirrors. It
// returns sql.ErrNoRows if no gated version with that id exists.
func (r *VersionApprovalRepository) SetStatus(ctx context.Context, id uuid.UUID, newStatus string, performedBy *uuid.UUID, notes *string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	action := models.VersionApprovalActionApproved
	if newStatus == models.VersionApprovalStatusRejected {
		action = models.VersionApprovalActionRejected
	}

	// Try provider versions first.
	res, err := tx.ExecContext(ctx,
		`UPDATE mirrored_provider_versions SET approval_status = $2 WHERE id = $1 AND approval_status IS NOT NULL`,
		id, newStatus)
	if err != nil {
		return fmt.Errorf("failed to update provider version status: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if err := insertEvent(ctx, tx, &id, nil, nil, action, performedBy, notes, nil); err != nil {
			return err
		}
		return tx.Commit()
	}

	// Fall back to terraform versions.
	res, err = tx.ExecContext(ctx,
		`UPDATE terraform_versions SET approval_status = $2 WHERE id = $1 AND approval_status IS NOT NULL`,
		id, newStatus)
	if err != nil {
		return fmt.Errorf("failed to update terraform version status: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if err := insertEvent(ctx, tx, nil, &id, nil, action, performedBy, notes, nil); err != nil {
			return err
		}
		// A terraform approve/reject can change which version is "latest".
		var configID uuid.UUID
		if err := tx.GetContext(ctx, &configID, `SELECT config_id FROM terraform_versions WHERE id = $1`, id); err != nil {
			return fmt.Errorf("failed to load config for latest recalc: %w", err)
		}
		if err := recalcTerraformLatest(ctx, tx, configID); err != nil {
			return err
		}
		return tx.Commit()
	}

	// Fall back to scanner binary versions. No is_latest or activation side
	// effects here: activation is handled by the scanner update job's reconciler.
	res, err = tx.ExecContext(ctx,
		`UPDATE scanner_binary_versions SET approval_status = $2 WHERE id = $1 AND approval_status IS NOT NULL`,
		id, newStatus)
	if err != nil {
		return fmt.Errorf("failed to update scanner binary version status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	if err := insertEvent(ctx, tx, nil, nil, &id, action, performedBy, notes, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordEvent inserts a version approval event outside of a status transition —
// used by the sync job to log auto_approved decisions. Exactly one of the two
// version ids must be set.
func (r *VersionApprovalRepository) RecordEvent(ctx context.Context, ev *models.VersionApprovalEvent) error {
	if err := insertEventDB(ctx, r.db, ev); err != nil {
		return err
	}
	return nil
}

// Events returns the audit trail for a single version (provider or terraform),
// newest first, resolving the performer's display name.
func (r *VersionApprovalRepository) Events(ctx context.Context, versionID uuid.UUID) ([]models.VersionApprovalEvent, error) {
	const q = `
		SELECT e.id, e.mirrored_provider_version_id, e.terraform_version_id, e.scanner_binary_version_id,
		       e.action, e.performed_by, u.name AS performed_by_name,
		       e.notes, e.auto_approve_rule, e.created_at
		FROM version_approval_events e
		LEFT JOIN users u ON u.id = e.performed_by
		WHERE e.mirrored_provider_version_id = $1 OR e.terraform_version_id = $1 OR e.scanner_binary_version_id = $1
		ORDER BY e.created_at DESC`

	var events []models.VersionApprovalEvent
	if err := r.db.SelectContext(ctx, &events, q, versionID); err != nil {
		return nil, fmt.Errorf("failed to list approval events: %w", err)
	}
	if events == nil {
		events = []models.VersionApprovalEvent{}
	}
	return events, nil
}

// recalcTerraformLatest clears is_latest within a config and sets it on the
// highest synced, non-deprecated, visible (NULL or approved) version.
func recalcTerraformLatest(ctx context.Context, tx *sqlx.Tx, configID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE terraform_versions SET is_latest = false WHERE config_id = $1 AND is_latest = true`,
		configID); err != nil {
		return fmt.Errorf("failed to clear is_latest: %w", err)
	}
	q := fmt.Sprintf(`
		UPDATE terraform_versions SET is_latest = true
		WHERE id = (
		  SELECT id FROM terraform_versions
		  WHERE config_id = $1
		    AND sync_status = 'synced'
		    AND NOT is_deprecated
		    AND (approval_status IS NULL OR approval_status = 'approved')
		  ORDER BY %s
		  LIMIT 1
		)`, semverOrder)
	if _, err := tx.ExecContext(ctx, q, configID); err != nil {
		return fmt.Errorf("failed to set is_latest: %w", err)
	}
	return nil
}

// insertEvent inserts an approval event within a transaction.
func insertEvent(ctx context.Context, tx *sqlx.Tx, mpvID, tfvID, sbvID *uuid.UUID, action string, performedBy *uuid.UUID, notes *string, rule *string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO version_approval_events
		  (mirrored_provider_version_id, terraform_version_id, scanner_binary_version_id, action, performed_by, notes, auto_approve_rule)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		mpvID, tfvID, sbvID, action, performedBy, notes, rule)
	if err != nil {
		return fmt.Errorf("failed to insert approval event: %w", err)
	}
	return nil
}

// insertEventDB inserts an approval event using the pool (no transaction).
func insertEventDB(ctx context.Context, db *sqlx.DB, ev *models.VersionApprovalEvent) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO version_approval_events
		  (mirrored_provider_version_id, terraform_version_id, scanner_binary_version_id, action, performed_by, notes, auto_approve_rule)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ev.MirroredProviderVersionID, ev.TerraformVersionID, ev.ScannerBinaryVersionID, ev.Action, ev.PerformedBy, ev.Notes, ev.AutoApproveRule)
	if err != nil {
		return fmt.Errorf("failed to insert approval event: %w", err)
	}
	return nil
}

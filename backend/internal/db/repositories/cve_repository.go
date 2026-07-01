// cve_repository.go provides database operations for the CVE polling subsystem.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// CVERepository handles all database operations for cve_advisories and cve_affected_targets.
type CVERepository struct {
	db *sql.DB
}

// NewCVERepository creates a new CVERepository.
func NewCVERepository(db *sql.DB) *CVERepository {
	return &CVERepository{db: db}
}

// UpsertAdvisory inserts a new advisory or updates summary/severity/refs/modified_at/fetched_at
// if the (source, source_id) pair already exists. Returns the resolved UUID.
func (r *CVERepository) UpsertAdvisory(ctx context.Context, a *models.CVEAdvisory) (uuid.UUID, bool, error) {
	refsJSON, err := json.Marshal(a.References)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("marshal references: %w", err)
	}

	var id uuid.UUID
	var isNew bool

	row := r.db.QueryRowContext(ctx, `
		INSERT INTO cve_advisories
			(source, source_id, severity, summary, details, "references",
			 published_at, modified_at, fetched_at, withdrawn_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),$9)
		ON CONFLICT (source, source_id) DO UPDATE
			SET severity     = EXCLUDED.severity,
			    summary      = EXCLUDED.summary,
			    details      = EXCLUDED.details,
			    "references" = EXCLUDED."references",
			    modified_at  = EXCLUDED.modified_at,
			    fetched_at   = NOW(),
			    withdrawn_at = EXCLUDED.withdrawn_at,
			    updated_at   = NOW()
		RETURNING id, (xmax = 0)
	`,
		a.Source, a.SourceID, string(a.Severity), a.Summary, a.Details,
		refsJSON, a.PublishedAt, a.ModifiedAt, a.WithdrawnAt,
	)
	if err := row.Scan(&id, &isNew); err != nil {
		return uuid.Nil, false, fmt.Errorf("upsert advisory %s: %w", a.SourceID, err)
	}
	return id, isNew, nil
}

// MarkWithdrawn sets withdrawn_at to now for the advisory with the given source+sourceID.
func (r *CVERepository) MarkWithdrawn(ctx context.Context, source, sourceID string) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE cve_advisories SET withdrawn_at = $1, updated_at = NOW()
		WHERE source = $2 AND source_id = $3 AND withdrawn_at IS NULL
	`, now, source, sourceID)
	return err
}

// ReplaceAffectedTargets replaces all targets for an advisory+kind combination.
// It deletes existing rows for that (advisory_id, target_kind) and inserts the
// new set in a single transaction.
func (r *CVERepository) ReplaceAffectedTargets(ctx context.Context, advisoryID uuid.UUID, kind models.CVETargetKind, targets []models.CVEAffectedTarget) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM cve_affected_targets WHERE advisory_id = $1 AND target_kind = $2
	`, advisoryID, string(kind)); err != nil {
		return fmt.Errorf("delete existing targets: %w", err)
	}

	for _, t := range targets {
		refJSON, err := json.Marshal(t.TargetRef)
		if err != nil {
			return fmt.Errorf("marshal target_ref: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO cve_affected_targets
				(advisory_id, target_kind, fingerprint, target_ref,
				 terraform_version_id, provider_version_id)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (advisory_id, target_kind, fingerprint) DO NOTHING
		`,
			advisoryID, string(kind), t.Fingerprint, refJSON,
			t.TerraformVersionID, t.ProviderVersionID,
		); err != nil {
			return fmt.Errorf("insert target: %w", err)
		}
	}

	return tx.Commit()
}

// ListActive returns advisories that still have at least one "live" target:
//   - binary  targets where the terraform_version is not deprecated AND still present.
//   - provider targets where the provider_version is not deprecated AND still present.
//   - scanner targets are always included (no deprecation FK — caller sets withdrawn_at).
//
// Withdrawn advisories are excluded.
func (r *CVERepository) ListActive(ctx context.Context) ([]models.CVEAdvisory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT a.id, a.source, a.source_id, a.severity, a.summary, a.details,
		       a."references", a.published_at, a.modified_at, a.fetched_at,
		       a.withdrawn_at, a.created_at, a.updated_at
		FROM cve_advisories a
		WHERE a.withdrawn_at IS NULL
		  AND EXISTS (
		    SELECT 1 FROM cve_affected_targets t
		    WHERE t.advisory_id = a.id
		      AND (
		        -- binary: terraform_version still present and not deprecated
		        (t.target_kind = 'binary' AND t.terraform_version_id IS NOT NULL
		         AND EXISTS (
		           SELECT 1 FROM terraform_versions tv
		           WHERE tv.id = t.terraform_version_id AND tv.is_deprecated = false
		         ))
		        OR
		        -- provider: provider_version still present and not deprecated
		        (t.target_kind = 'provider' AND t.provider_version_id IS NOT NULL
		         AND EXISTS (
		           SELECT 1 FROM provider_versions pv
		           WHERE pv.id = t.provider_version_id AND pv.deprecated = false
		         ))
		        OR
		        -- scanner: always live (no deprecation FK)
		        t.target_kind = 'scanner'
		      )
		  )
		ORDER BY a.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list active advisories: %w", err)
	}
	defer rows.Close()

	var advisories []models.CVEAdvisory
	for rows.Next() {
		var a models.CVEAdvisory
		if err := rows.Scan(
			&a.ID, &a.Source, &a.SourceID, &a.Severity, &a.Summary, &a.Details,
			&a.RefsJSON, &a.PublishedAt, &a.ModifiedAt, &a.FetchedAt,
			&a.WithdrawnAt, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan advisory: %w", err)
		}
		a.DecodeRefs()
		advisories = append(advisories, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Populate targets for each advisory.
	for i := range advisories {
		targets, err := r.listTargetsForAdvisory(ctx, advisories[i].ID)
		if err != nil {
			return nil, err
		}
		advisories[i].Targets = targets
	}
	return advisories, nil
}

// ListAll returns all advisories (including withdrawn) for admin views.
// An optional kind filter restricts results to advisories of a specific target_kind.
func (r *CVERepository) ListAll(ctx context.Context, kindFilter string) ([]models.CVEAdvisory, error) {
	query := `
		SELECT a.id, a.source, a.source_id, a.severity, a.summary, a.details,
		       a."references", a.published_at, a.modified_at, a.fetched_at,
		       a.withdrawn_at, a.created_at, a.updated_at
		FROM cve_advisories a
	`
	args := []interface{}{}

	if kindFilter != "" {
		query += ` WHERE EXISTS (
			SELECT 1 FROM cve_affected_targets t
			WHERE t.advisory_id = a.id AND t.target_kind = $1
		)`
		args = append(args, kindFilter)
	}
	query += ` ORDER BY a.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list all advisories: %w", err)
	}
	defer rows.Close()

	var advisories []models.CVEAdvisory
	for rows.Next() {
		var a models.CVEAdvisory
		if err := rows.Scan(
			&a.ID, &a.Source, &a.SourceID, &a.Severity, &a.Summary, &a.Details,
			&a.RefsJSON, &a.PublishedAt, &a.ModifiedAt, &a.FetchedAt,
			&a.WithdrawnAt, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan advisory: %w", err)
		}
		a.DecodeRefs()
		advisories = append(advisories, a)
	}
	return advisories, rows.Err()
}

// listTargetsForAdvisory returns all CVEAffectedTarget rows for a single advisory.
func (r *CVERepository) listTargetsForAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]models.CVEAffectedTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, advisory_id, target_kind, fingerprint, target_ref,
		       terraform_version_id, provider_version_id, created_at
		FROM cve_affected_targets
		WHERE advisory_id = $1
		ORDER BY target_kind, created_at
	`, advisoryID)
	if err != nil {
		return nil, fmt.Errorf("list targets for advisory %s: %w", advisoryID, err)
	}
	defer rows.Close()

	var targets []models.CVEAffectedTarget
	for rows.Next() {
		var t models.CVEAffectedTarget
		if err := rows.Scan(
			&t.ID, &t.AdvisoryID, &t.TargetKind, &t.Fingerprint, &t.TargetRefJSON,
			&t.TerraformVersionID, &t.ProviderVersionID, &t.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		t.DecodeRef()
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// ExistsAdvisory returns true when (source, sourceID) is already in the database.
func (r *CVERepository) ExistsAdvisory(ctx context.Context, source, sourceID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM cve_advisories WHERE source=$1 AND source_id=$2)
	`, source, sourceID).Scan(&exists)
	return exists, err
}

// ---- CVE scan candidates ---------------------------------------------------

// BinaryCandidate is a Terraform/OpenTofu binary version eligible for CVE scanning.
type BinaryCandidate struct {
	MirrorConfigID string
	Tool           string // "terraform" | "opentofu"
	VersionID      string
	Version        string
}

// ProviderCandidate is a provider version eligible for CVE scanning.
type ProviderCandidate struct {
	ProviderID        string
	ProviderVersionID string
	Namespace         string
	ProviderType      string
	Version           string
	Source            *string // upstream source URL, may be nil
}

// ListAllBinaryCandidates returns all non-deprecated terraform/opentofu versions
// across all enabled mirror configs.
func (r *CVERepository) ListAllBinaryCandidates(ctx context.Context) ([]BinaryCandidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id::text, c.tool, tv.id::text, tv.version
		FROM terraform_versions tv
		JOIN terraform_mirror_configs c ON c.id = tv.config_id
		WHERE c.enabled = true
		  AND c.tool IN ('terraform', 'opentofu', 'packer', 'sentinel', 'opa', 'terraform-docs')
		  AND tv.is_deprecated = false
		  AND tv.sync_status = 'synced'
		ORDER BY c.tool, tv.version
	`)
	if err != nil {
		return nil, fmt.Errorf("list binary candidates: %w", err)
	}
	defer rows.Close()

	var out []BinaryCandidate
	for rows.Next() {
		var c BinaryCandidate
		if err := rows.Scan(&c.MirrorConfigID, &c.Tool, &c.VersionID, &c.Version); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllProviderCandidates returns all non-deprecated provider versions registered
// in the registry, with enough metadata to build an OSV query.
func (r *CVERepository) ListAllProviderCandidates(ctx context.Context) ([]ProviderCandidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id, pv.id, p.namespace, p.type, pv.version, p.source
		FROM provider_versions pv
		JOIN providers p ON p.id = pv.provider_id
		WHERE COALESCE(pv.deprecated, false) = false
		ORDER BY p.namespace, p.type, pv.version
	`)
	if err != nil {
		return nil, fmt.Errorf("list provider candidates: %w", err)
	}
	defer rows.Close()

	var out []ProviderCandidate
	for rows.Next() {
		var c ProviderCandidate
		if err := rows.Scan(&c.ProviderID, &c.ProviderVersionID, &c.Namespace, &c.ProviderType, &c.Version, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

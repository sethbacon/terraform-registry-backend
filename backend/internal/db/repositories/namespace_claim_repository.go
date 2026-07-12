// Package repositories - namespace_claim_repository.go persists the
// namespace-to-organization ownership bindings used for object-level
// authorization on module and provider mutations (issue #555, CWE-639).
package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// NamespaceClaimRepository handles namespace ownership database operations.
type NamespaceClaimRepository struct {
	db *sql.DB
}

// NewNamespaceClaimRepository creates a new namespace claim repository.
func NewNamespaceClaimRepository(db *sql.DB) *NamespaceClaimRepository {
	return &NamespaceClaimRepository{db: db}
}

// GetClaim returns the ownership claim for a namespace, or nil when the
// namespace is unclaimed.
func (r *NamespaceClaimRepository) GetClaim(ctx context.Context, namespace string) (*models.NamespaceClaim, error) {
	query := `
		SELECT namespace, organization_id, claimed_by, created_at
		FROM namespace_claims
		WHERE namespace = $1
	`

	claim := &models.NamespaceClaim{}
	err := r.db.QueryRowContext(ctx, query, namespace).Scan(
		&claim.Namespace,
		&claim.OrganizationID,
		&claim.ClaimedBy,
		&claim.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Unclaimed
		}
		return nil, fmt.Errorf("failed to get namespace claim: %w", err)
	}

	return claim, nil
}

// ClaimNamespace atomically claims a namespace for an organization and returns
// the winning claim. When two organizations race for the same namespace, the
// first insert wins (ON CONFLICT DO NOTHING) and the loser receives the
// winner's claim back — callers must compare the returned organization ID with
// the one they requested.
func (r *NamespaceClaimRepository) ClaimNamespace(ctx context.Context, namespace, organizationID string, claimedBy *string) (*models.NamespaceClaim, error) {
	insert := `
		INSERT INTO namespace_claims (namespace, organization_id, claimed_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (namespace) DO NOTHING
	`

	if _, err := r.db.ExecContext(ctx, insert, namespace, organizationID, claimedBy); err != nil {
		return nil, fmt.Errorf("failed to claim namespace: %w", err)
	}

	claim, err := r.GetClaim(ctx, namespace)
	if err != nil {
		return nil, err
	}
	if claim == nil {
		// The claim row vanished between insert and select (concurrent org
		// deletion cascading onto the claim). Treat as a failed claim rather
		// than inventing ownership.
		return nil, fmt.Errorf("failed to claim namespace: claim not found after insert")
	}

	return claim, nil
}

// ArtifactOrganizations returns the distinct organization IDs that own module
// or provider rows in a namespace. Used as the ownership fallback for
// namespaces that predate the claims table or were populated by system paths
// (mirror sync, pull-through cache) that do not create claims.
func (r *NamespaceClaimRepository) ArtifactOrganizations(ctx context.Context, namespace string) ([]string, error) {
	query := `
		SELECT DISTINCT organization_id FROM (
			SELECT organization_id FROM modules   WHERE namespace = $1 AND organization_id IS NOT NULL
			UNION
			SELECT organization_id FROM providers WHERE namespace = $1 AND organization_id IS NOT NULL
		) artifact_orgs
	`

	rows, err := r.db.QueryContext(ctx, query, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespace artifact organizations: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return nil, fmt.Errorf("failed to scan namespace artifact organization: %w", err)
		}
		orgIDs = append(orgIDs, orgID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate namespace artifact organizations: %w", err)
	}

	return orgIDs, nil
}

// CountByOrganization returns how many namespaces an organization currently
// owns a claim to. Used to block organization deletion while claims exist:
// the claims FK is ON DELETE RESTRICT, but that surfaces as an opaque 500 —
// this backs a clear, actionable 409 instead. Deleting an org out from under
// its claims would silently fall back namespace ownership to whichever
// (unrelated) organization the mistagged artifact rows point at, defeating
// the object-level authorization this table exists to enforce.
func (r *NamespaceClaimRepository) CountByOrganization(ctx context.Context, organizationID string) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM namespace_claims WHERE organization_id = $1`
	if err := r.db.QueryRowContext(ctx, query, organizationID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count namespace claims for organization: %w", err)
	}
	return count, nil
}

// OwnsArtifacts reports whether an organization owns any module or provider
// row directly (in any namespace), independent of namespace_claims. Used
// alongside CountByOrganization to block organization deletion: a namespace
// whose artifacts already span more than one organization is deliberately
// left UNCLAIMED (ambiguous ownership, restricted to admins at runtime —
// see resolveOwnerOrg), so CountByOrganization alone would return 0 for it
// even though this organization still owns rows there. modules/providers'
// organization_id FK is still ON DELETE CASCADE (unrelated to the
// namespace_claims RESTRICT added alongside this method): deleting this
// organization would silently remove its rows from that ambiguous namespace,
// collapsing it from admin-only "ambiguous" to unchecked sole ownership by
// whichever organization's rows survive — the same "artifact-row fallback
// re-attributes ownership after an org disappears" defect this table exists
// to close, reached via a shared/ambiguous namespace instead of via a claim.
func (r *NamespaceClaimRepository) OwnsArtifacts(ctx context.Context, organizationID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM modules   WHERE organization_id = $1
			UNION ALL
			SELECT 1 FROM providers WHERE organization_id = $1
		)
	`
	var owns bool
	if err := r.db.QueryRowContext(ctx, query, organizationID).Scan(&owns); err != nil {
		return false, fmt.Errorf("failed to check organization artifact ownership: %w", err)
	}
	return owns, nil
}

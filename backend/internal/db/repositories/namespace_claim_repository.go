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

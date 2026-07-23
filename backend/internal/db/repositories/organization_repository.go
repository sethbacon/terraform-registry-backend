// Package repositories - organization_repository.go aliases the
// OrganizationRepository from the shared identity store.
//
// The identity store renames the organization row only (OrganizationRepository
// .Rename). The registry's denormalized module/provider namespace columns are a
// domain concern and are cascaded separately by CascadeOrganizationRename, which
// runs on the registry's own (public-schema) connection.
package repositories

import (
	"context"
	"database/sql"
	"fmt"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"
)

// OrganizationRepository handles organization database operations.
type OrganizationRepository = identitystore.OrganizationRepository

// NewOrganizationRepository constructs an OrganizationRepository over the given connection.
var NewOrganizationRepository = identitystore.NewOrganizationRepository

// CascadeOrganizationRename propagates a renamed organization's new name to the
// registry's denormalized module and provider namespace columns and to the
// organization's namespace-ownership claims, in a single transaction on the
// registry's domain connection. The identity-side rename (organizations.name)
// is performed separately via OrganizationRepository.Rename.
func CascadeOrganizationRename(ctx context.Context, db *sql.DB, orgID, oldName, newName string) (retErr error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin namespace cascade: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()

	// Match module/provider rows by namespace alone, NOT by organization_id.
	// Artifact rows are stamped with the DEFAULT organization at publish time,
	// not the namespace's true owner (issue #555), so an `organization_id = orgID`
	// predicate matches nothing whenever a NON-default organization is renamed --
	// silently leaving that organization's artifacts pinned to the old namespace
	// while the organization row and its namespace_claims move to the new name,
	// orphaning them from the unauthenticated protocol read path (which resolves
	// modules/providers by namespace). A namespace is a globally-unique ownership
	// identity (namespace_claims.namespace is the PRIMARY KEY) and this cascade is
	// triggered precisely by renaming the organization that owns it, so matching
	// on the old namespace string alone is both correct and complete. The
	// namespace_claims row below is matched by organization_id because claims —
	// unlike artifact rows — do carry the true owning organization.
	if _, err = tx.ExecContext(ctx,
		`UPDATE modules SET namespace = $1, updated_at = NOW() WHERE namespace = $2`,
		newName, oldName,
	); err != nil {
		return fmt.Errorf("cascade rename to modules: %w", err)
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE providers SET namespace = $1, updated_at = NOW() WHERE namespace = $2`,
		newName, oldName,
	); err != nil {
		return fmt.Errorf("cascade rename to providers: %w", err)
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE namespace_claims SET namespace = $1 WHERE organization_id = $2 AND namespace = $3`,
		newName, orgID, oldName,
	); err != nil {
		return fmt.Errorf("cascade rename to namespace claims: %w", err)
	}

	return tx.Commit()
}

// Package repositories - organization_repository.go wraps the
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
//
// It EMBEDS the shared identity store's repository and overrides exactly the
// methods that create or change a member's role, so that each one also writes
// registry's own `organization_member_roles`
// (sethbacon/terraform-suite-identity#206, migration 000055).
//
// This was a type alias until the dual-write landed, and it is a wrapper now for
// one reason: the dual-write must not be something a call site can forget. Every
// membership role in this product is written through this type -- guaranteed by
// TestPlatformAdminGrantClass_NoRawSQLMembershipWrites, which refuses a
// hand-written INSERT/UPDATE against organization_members anywhere in the module
// -- so putting the mirror inside the method is what makes "every path that
// assigns a role also writes the new table" a property of the type rather than a
// list of call sites somebody keeps up to date.
//
// The remaining risk is the other direction: the STORE growing a new membership
// writer that this type does not override, which promotion would then serve
// un-mirrored and silently. member_role_mirror_class_test.go derives the store's
// membership-writing methods from the module source and fails when one of them
// has no override here.
type OrganizationRepository struct {
	*identitystore.OrganizationRepository

	// mirror writes registry's own authorization tables. It is built on the SAME
	// connection as the embedded repository, deliberately: the two writes are
	// then guaranteed to be talking about the same organization_members, and in
	// the two topologies where identity is the app's own schema or a shared
	// schema in the same database, `search_path` resolves the mirror tables
	// through the trailing `,public`. The topology where it does not -- identity
	// in a SEPARATE DATABASE -- is caught at boot by VerifyMemberRoleMirror
	// rather than discovered as missing rows later.
	mirror *MemberRoleMirror
}

// NewOrganizationRepository constructs an OrganizationRepository over the given connection.
func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{
		OrganizationRepository: identitystore.NewOrganizationRepository(db),
		mirror:                 NewMemberRoleMirror(db),
	}
}

// mirrorMemberFromSource re-reads the membership that was just written and
// mirrors what the source now says, rather than what the caller asked for.
//
// Read-back rather than reusing the caller's argument because two of the store's
// write methods take a role template NAME and resolve it internally, and because
// the store's writes are scoped -- a scoped statement that matched no row must
// mirror nothing. Reading the row back through the same scope collapses all of
// that into one answer that is true by observation. Role writes are rare
// administrative actions, so the extra SELECT costs nothing that matters.
func (r *OrganizationRepository) mirrorMemberFromSource(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) {
	member, err := r.OrganizationRepository.GetMember(ctx, orgID, userID, scope)
	if err != nil {
		mirrorFailed(ctx, "read back membership", err, "organization_id", orgID, "user_id", userID)
		return
	}
	if err := r.mirror.AssignRole(ctx, member.OrganizationID, member.UserID, member.RoleTemplateID); err != nil {
		mirrorFailed(ctx, "assign role", err, "organization_id", orgID, "user_id", userID)
	}
}

// AddMemberWithRoleTemplate adds a member and mirrors the resulting assignment.
func (r *OrganizationRepository) AddMemberWithRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.AddMemberWithRoleTemplate(ctx, orgID, userID, roleTemplateID, scope); err != nil {
		return err
	}
	r.mirrorMemberFromSource(ctx, orgID, userID, scope)
	return nil
}

// AddMemberWithParams adds a member by role-template name and mirrors the
// resulting assignment.
//
// Overridden separately even though the store implements it in terms of
// AddMemberWithRoleTemplate: Go has no virtual dispatch, so the store's call
// reaches the store's own method and never this type's. An override that
// "obviously" comes for free is the exact shape of a silent gap here.
func (r *OrganizationRepository) AddMemberWithParams(ctx context.Context, orgID, userID, roleTemplateName string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.AddMemberWithParams(ctx, orgID, userID, roleTemplateName, scope); err != nil {
		return err
	}
	r.mirrorMemberFromSource(ctx, orgID, userID, scope)
	return nil
}

// UpdateMemberRoleTemplate changes a member's role and mirrors the result.
func (r *OrganizationRepository) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.UpdateMemberRoleTemplate(ctx, orgID, userID, roleTemplateID, scope); err != nil {
		return err
	}
	r.mirrorMemberFromSource(ctx, orgID, userID, scope)
	return nil
}

// UpdateMemberRole changes a member's role by template name and mirrors the
// result. Overridden for the same no-virtual-dispatch reason as
// AddMemberWithParams.
func (r *OrganizationRepository) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.UpdateMemberRole(ctx, orgID, userID, roleTemplateName, scope); err != nil {
		return err
	}
	r.mirrorMemberFromSource(ctx, orgID, userID, scope)
	return nil
}

// RemoveMember removes a membership and drops its mirrored role assignment.
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.RemoveMember(ctx, orgID, userID, scope); err != nil {
		return err
	}
	if err := r.mirror.ClearMember(ctx, orgID, userID); err != nil {
		mirrorFailed(ctx, "clear member", err, "organization_id", orgID, "user_id", userID)
	}
	return nil
}

// RemoveAllMembershipsForUser deprovisions a user and drops the mirrored role
// assignment in each organization the sweep actually emptied.
//
// The store returns the scope of organizations it removed, so the mirror clears
// exactly those rather than every organization the user appears in -- a scoped
// SCIM deprovision must not clear assignments outside its tenant, which is the
// same property issue #160 established for the source statement.
func (r *OrganizationRepository) RemoveAllMembershipsForUser(ctx context.Context, userID string, scope identitystore.OrgScope) (identitystore.OrgScope, error) {
	removed, err := r.OrganizationRepository.RemoveAllMembershipsForUser(ctx, userID, scope)
	if err != nil {
		return removed, err
	}
	for _, orgID := range removed.OrganizationIDs() {
		if clearErr := r.mirror.ClearMember(ctx, orgID, userID); clearErr != nil {
			mirrorFailed(ctx, "clear member", clearErr, "organization_id", orgID, "user_id", userID)
		}
	}
	return removed, nil
}

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

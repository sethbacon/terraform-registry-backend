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
	"errors"
	"fmt"

	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
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

	// roles READS those tables. Since phase 3b it is where every role and every
	// scope set this type returns comes from; the embedded repository still
	// supplies the membership FACT and the user/organization columns, because
	// `organization_members` remains the record of who belongs where until
	// phase 4.
	roles *MemberRoleReader
}

// NewOrganizationRepository constructs an OrganizationRepository over the given connection.
func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{
		OrganizationRepository: identitystore.NewOrganizationRepository(db),
		mirror:                 NewMemberRoleMirror(db),
		roles:                  NewMemberRoleReader(db),
	}
}

// ===========================================================================
// Role READS -- registry's own tables (terraform-suite-identity#206, phase 3b)
// ===========================================================================
//
// Each override below has the same three steps, and the order is the argument
// for its correctness:
//
//  1. Ask the embedded store. That answers "is this principal a member", and
//     supplies the organization/user columns the display shapes carry. Those
//     facts are still identity's and are not moving in this phase.
//  2. Ask registry's own tables what role that membership holds HERE.
//  3. Report any disagreement (compareRole) and return REGISTRY's answer.
//
// Step 1 first is what makes a stray mirrored row inert: a row in
// `organization_member_roles` whose membership no longer exists is never
// reached, because nothing below asks about a principal the store did not
// already return. That is the one drift direction that GRANTS authority, and
// this ordering is why it cannot.
//
// A FAILED read of registry's tables is returned as an error, never absorbed
// into "no role". The distinction matters: an empty scope set denies and looks
// exactly like a successful lookup of an unprivileged member, so absorbing the
// error would turn a database fault into a silent, plausible-looking
// authorization answer. Both accessors that deliberately absorb ErrNotFound in
// the shared store (CheckMembership, GetUserScopesForOrg) keep absorbing only
// THAT sentinel, for the reasons their doc comments give.
//
// EVERY ROLE-BEARING READ ON THE STORE IS OVERRIDDEN, and that is enforced
// rather than intended: Go promotes any method this type does not re-declare,
// so a missed one would keep compiling and keep serving identity's answer
// while its siblings serve registry's -- two answers to one question, differing
// only on the rows that are wrong. member_role_read_class_test.go derives the
// store's role-bearing readers from the pinned module's source and fails when
// one has no override here.

// GetMember retrieves a membership, with the role registry's own tables hold.
func (r *OrganizationRepository) GetMember(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) (*models.OrganizationMember, error) {
	member, err := r.OrganizationRepository.GetMember(ctx, orgID, userID, scope)
	if err != nil {
		return nil, err
	}
	role, err := r.roles.RoleFor(ctx, member.OrganizationID, member.UserID)
	if err != nil {
		return nil, err
	}
	compareRole(ctx, "GetMember", member.OrganizationID, member.UserID, member.RoleTemplateID, role)
	member.RoleTemplateID = role.id()
	return member, nil
}

// ListMembers lists an organization's members with registry's own roles.
func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID string, scope identitystore.OrgScope) ([]*models.OrganizationMember, error) {
	members, err := r.OrganizationRepository.ListMembers(ctx, orgID, scope)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return members, nil
	}
	// One read for the organization rather than one per member: this is the
	// list shape, and an N+1 here is a round trip per row on a page that
	// renders every member.
	roles, err := r.roles.RolesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		role := roles[member.UserID]
		compareRole(ctx, "ListMembers", member.OrganizationID, member.UserID, member.RoleTemplateID, role)
		member.RoleTemplateID = role.id()
	}
	return members, nil
}

// CheckMembership answers "is this user a member, and with what role", the
// role coming from registry's own tables.
//
// Overridden even though the shared store implements it in terms of GetMember:
// Go has no virtual dispatch, so the store's call reaches the store's GetMember
// and never this type's. Exactly the same trap the write overrides document for
// AddMemberWithParams, and it is silent in the same way.
func (r *OrganizationRepository) CheckMembership(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) (bool, *string, error) {
	member, err := r.GetMember(ctx, orgID, userID, scope)
	if errors.Is(err, identitystore.ErrNotFound) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, member.RoleTemplateID, nil
}

// GetMemberWithRole retrieves a membership with the role template registry's
// own tables record for it -- id, name, display name, and the SCOPES.
//
// This is the accessor the per-resource route guards and the API-key auth path
// are built on, so it is the single most authorization-critical read in the
// product.
func (r *OrganizationRepository) GetMemberWithRole(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) (*models.OrganizationMemberWithUser, error) {
	member, err := r.OrganizationRepository.GetMemberWithRole(ctx, orgID, userID, scope)
	if err != nil {
		return nil, err
	}
	role, err := r.roles.RoleFor(ctx, member.OrganizationID, member.UserID)
	if err != nil {
		return nil, err
	}
	compareRole(ctx, "GetMemberWithRole", member.OrganizationID, member.UserID, member.RoleTemplateID, role)
	applyMirroredRole(role, &member.RoleTemplateID, &member.RoleTemplateName,
		&member.RoleTemplateDisplayName, &member.RoleTemplateScopes)
	return member, nil
}

// ListMembersWithUsers lists an organization's members and their users, with
// registry's own roles.
func (r *OrganizationRepository) ListMembersWithUsers(ctx context.Context, orgID string, scope identitystore.OrgScope) ([]*models.OrganizationMemberWithUser, error) {
	members, err := r.OrganizationRepository.ListMembersWithUsers(ctx, orgID, scope)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return members, nil
	}
	roles, err := r.roles.RolesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		role := roles[member.UserID]
		compareRole(ctx, "ListMembersWithUsers", member.OrganizationID, member.UserID, member.RoleTemplateID, role)
		applyMirroredRole(role, &member.RoleTemplateID, &member.RoleTemplateName,
			&member.RoleTemplateDisplayName, &member.RoleTemplateScopes)
	}
	return members, nil
}

// GetUserMemberships returns every organization the user belongs to, each
// carrying the role registry's own tables hold for it.
//
// This is the base of three derived accessors (GetUserCombinedScopes,
// OrgScopeForUser, and the shared UserRepository's GetUserWithOrgRoles), which
// is why it is keyed per organization: a user with the right role in one
// organization and none in another must not have the two merged here.
func (r *OrganizationRepository) GetUserMemberships(ctx context.Context, userID string) ([]*models.UserMembership, error) {
	memberships, err := r.OrganizationRepository.GetUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return memberships, nil
	}
	roles, err := r.roles.RolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, m := range memberships {
		role := roles[m.OrganizationID]
		compareRole(ctx, "GetUserMemberships", m.OrganizationID, userID, m.RoleTemplateID, role)
		applyMirroredRole(role, &m.RoleTemplateID, &m.RoleTemplateName,
			&m.RoleTemplateDisplayName, &m.RoleTemplateScopes)
	}
	return memberships, nil
}

// GetUserCombinedScopes returns the flat, cross-organization union of the
// scopes registry's own role templates confer on this user.
//
// Overridden, and the derivation re-stated rather than delegated, for the
// no-virtual-dispatch reason: the store's implementation calls the store's
// GetUserMemberships, so delegating would union IDENTITY's scopes into a token
// while every per-request check used registry's.
//
// Deprecated: this union carries no per-organization qualifier and must not
// stand in for a per-org authorization check; use GetUserScopesForOrg. The
// marker is preserved from the shared store's method so the existing
// //nolint:staticcheck dispositions at the deliberate call sites keep applying.
func (r *OrganizationRepository) GetUserCombinedScopes(ctx context.Context, userID string) (identityauth.GlobalScopes, error) {
	memberships, err := r.GetUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	scopes := make(identityauth.GlobalScopes, 0)
	for _, m := range memberships {
		for _, scope := range m.RoleTemplateScopes {
			if seen[scope] {
				continue
			}
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}

// GetUserScopesForOrg returns what registry's own role template confers on
// this user in ONE organization.
//
// Overridden for the no-virtual-dispatch reason; the store's version calls the
// store's GetMemberWithRole. It keeps absorbing ErrNotFound into the empty
// scope set, which denies, exactly as the shared store documents.
func (r *OrganizationRepository) GetUserScopesForOrg(ctx context.Context, userID, orgID string) (identityauth.OrgScopes, error) {
	// UNSCOPED BY DESIGN, as in the shared store: this derives what the
	// principal may do in orgID, so it cannot be gated on the authority it is
	// deriving.
	member, err := r.GetMemberWithRole(ctx, orgID, userID, identitystore.OrgScopeAllOrganizations())
	if errors.Is(err, identitystore.ErrNotFound) {
		return identityauth.OrgScopes{}, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	scopes := make(identityauth.OrgScopes, 0, len(member.RoleTemplateScopes))
	for _, scope := range member.RoleTemplateScopes {
		if seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// OrgScopeForUser returns the organizations in which registry's own role
// template grants the user the required scope.
//
// Overridden for the no-virtual-dispatch reason; the store's version calls the
// store's GetUserMemberships. This is the tenant predicate every list and
// per-resource route is narrowed by, so serving it from identity while the
// per-resource check served registry would let the two disagree about which
// organizations a caller may even see.
func (r *OrganizationRepository) OrgScopeForUser(ctx context.Context, userID, required string, rwPairs identityauth.ReadWritePairs) (identitystore.OrgScope, error) {
	if userID == "" {
		return identitystore.OrgScope{}, nil
	}
	memberships, err := r.GetUserMemberships(ctx, userID)
	if err != nil {
		return identitystore.OrgScope{}, err
	}
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		if identityauth.HasScope(m.RoleTemplateScopes, required, rwPairs) {
			orgIDs = append(orgIDs, m.OrganizationID)
		}
	}
	return identitystore.OrgScopeOrganizations(orgIDs...), nil
}

// applyMirroredRole overwrites a membership's four role fields with what
// registry's own tables hold.
//
// One helper for all three display shapes: the fields are the same four in
// every one of them, and a per-accessor copy is how one of them ends up
// updating the id but not the scopes -- which would leave a member rendered
// with the new role's name and the old role's authority.
func applyMirroredRole(role *MirroredRole, id, name, displayName **string, scopes *[]string) {
	*id = role.id()
	*name = role.namePtr()
	*displayName = role.displayNamePtr()
	*scopes = role.scopes()
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
//
// THE EMBEDDED SELECTOR IS LOAD-BEARING, and it became so in phase 3b. This
// method must read what the SOURCE now says; `r.GetMember` is this type's
// override, which reads the membership from the store and then REPLACES its role
// with whatever registry's tables already hold. Mirroring that would write the
// mirror's own current value back into itself -- a dual-write that is a no-op on
// every role CHANGE, silently, while every test that only checks "a mirror write
// happened" keeps passing. Since reads now come from those tables, the change
// would never take effect anywhere.
//
// Phase 3a removed this selector to satisfy staticcheck's QF1008, correctly at
// the time: GetMember was not then overridden. It is now.
// TestOrganizationRepository_MirrorsTheSourceNotTheMirror fails if it is dropped
// again.
func (r *OrganizationRepository) mirrorMemberFromSource(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) {
	member, err := r.OrganizationRepository.GetMember(ctx, orgID, userID, scope) //nolint:staticcheck // QF1008: the embedded selector is REQUIRED — see above; r.GetMember would mirror the mirror
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

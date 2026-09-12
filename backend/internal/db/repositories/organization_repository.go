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

// THE ORDERING RULE for the two legs of a role write (#1056).
//
// identity and registry may be different databases, so the two writes cannot
// share a transaction and there IS a window between them. The rule that decides
// which goes first is: ORDER THEM SO THAT A CRASH BETWEEN THEM LEAVES THE LESS
// PRIVILEGED STATE.
//
//   - A grant (add, or change of role) writes IDENTITY first. A crash leaves
//     registry without an assignment identity has: under-privileged, and the
//     next boot's reconcile confirms the membership with no role, which is the
//     same direction.
//   - A revocation writes the MIRROR first. A crash leaves registry without an
//     assignment identity still has: the same harmless direction.
//     Identity-first would have left a revoked role still deciding reads here.
//
// AND A FAILED MIRROR LEG FAILS THE REQUEST. Before #1056 it was logged and
// swallowed, which was right while nothing read these tables and wrong from the
// moment they became the authority: an administrator demoting a principal got
// 200 and an audit entry while `organization_member_roles` still said `admin`,
// and nothing surfaced it until a restart. Three things make returning the
// error safe:
//
//   - REVOCATIONS MIRROR FIRST, so a failure returns BEFORE identity is
//     touched: nothing changed anywhere, and the caller's retry is a retry of
//     an operation that did not happen.
//   - GRANTS WRITE IDENTITY FIRST, so a failure leaves identity ahead. The
//     caller sees an error, registry grants nothing new, and the reconcile
//     confirms the membership with no role.
//   - EVERY ONE OF THESE WRITES IS IDEMPOTENT -- AssignRole is an upsert, the
//     deletes remove nothing when the row is gone -- so the retry the error
//     invites cannot double-apply.
//
// The identity leg is NOT rolled back: it cannot be, across a connection
// boundary. The divergence is reported by `role-drift` and repaired by granting
// the role again.

// registryRoleTemplateID resolves a role template NAME against registry's own
// table, which is the only place a role means anything here.
//
// Called BEFORE the identity leg on every name-based write, so an unknown name
// fails with nothing written anywhere. The shared store resolves the same name
// against identity's `role_templates` for its own column; the two agree today
// because the templates are still derived, and may diverge freely once #1057
// lands -- which is why the id written HERE is resolved here.
func (r *OrganizationRepository) registryRoleTemplateID(ctx context.Context, name string) (*string, error) {
	id, err := r.roles.RoleTemplateIDByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// mirrorRequestedRole records the role THE CALLER ASKED FOR, once the identity
// leg has confirmed the membership exists and is in scope.
//
// # What it reads back, and what it no longer takes from the read-back
//
// The store's writes are SCOPED: a statement that matched no row must mirror
// nothing, and the caller's arguments cannot tell you whether it matched. So
// the membership is still read back through the same scope -- but only for that
// FACT. The role written is the caller's, resolved against registry's own
// templates, never the `role_template_id` the read-back carries. Taking it from
// the read-back is what let the sibling's opinion in on the write path, the same
// way the reconcile's copy did on the boot path.
//
// THE EMBEDDED SELECTOR IS LOAD-BEARING. `r.GetMember` is this type's override,
// which replaces the role with whatever registry already holds; reading through
// it would make a no-op of every change. It is used here for the membership fact
// alone, and the role it carries is discarded.
func (r *OrganizationRepository) mirrorRequestedRole(ctx context.Context, orgID, userID string, roleTemplateID *string, scope identitystore.OrgScope) error {
	member, err := r.OrganizationRepository.GetMember(ctx, orgID, userID, scope) //nolint:staticcheck // QF1008: the embedded selector is REQUIRED -- see above; r.GetMember would read the mirror back into itself
	if err != nil {
		if errors.Is(err, identitystore.ErrNotFound) {
			// The scoped write matched no row. Nothing happened at the source,
			// so nothing may happen here either.
			return nil
		}
		return fmt.Errorf("read back membership (%s, %s) to mirror its role: %w", orgID, userID, err)
	}
	if err := r.mirror.AssignRole(ctx, member.OrganizationID, member.UserID, roleTemplateID); err != nil {
		return fmt.Errorf("record the role in registry's own tables: %w", err)
	}
	return nil
}

// THE IDENTITY LEG CARRIES NO ROLE (sethbacon/terraform-suite-identity#206).
//
// All four writes below hand the shared store a nil role template and record the
// real one only in registry's own tables. Identity gets the membership FACT --
// "this user is a member of this organization" -- which is what #206 specifies
// that table to be:
//
//	identity.organization_members | membership FACT only: (organization_id,
//	                              | user_id) -- no role
//
// # Why this is a prerequisite and not a tidy-up
//
// The role-bearing spellings resolve the name in IDENTITY's own role-template
// table: the shared library's unexported lookupRoleTemplateID selects that
// table by name and returns `role template %q not found` when the name is
// absent (identity/store/organization_repository.go). The SQL is deliberately
// described rather than quoted here -- member_role_read_class_test.go text-
// matches hand-written reads of the shared table, and it is right to, so a
// pasted statement in a comment reads to it as one.
//
// So while any of them stands, `identity.role_templates` has to stay populated,
// and `SeedSharedIdentityRoleTemplates` cannot be retired -- an unseeded shared
// table would fail every grant at the identity leg. That seed is the last writer
// of a table neither application has read for authorization since #1057. This
// removes its final reader on registry's side.
//
// # Why nil rather than registry's own id
//
// `organization_members.role_template_id` carries a real FK to
// `identity.role_templates(id)` in the shared library's migration 000001.
// Registry's template ids are its own since #1057 and are not in that table, so
// writing one there is a constraint violation, not an option. nil is the
// spelling the library documents for this:
//
//	callers that intend no role should use AddMemberWithRoleTemplate(nil) /
//	UpdateMemberRoleTemplate(nil)
//
// # Why nothing observable changes
//
// Every read of a membership's role already goes through this type's overrides,
// which discard identity's column and substitute registry's own
// (`GetMember`: `member.RoleTemplateID = role.id()`). The column has not been an
// input to an authorization decision here since #1056 moved the assignments and
// #1057 moved the templates. What changes is that it stops being written, so it
// stops being a second, stale answer to a question registry already answers.
//
// The name-taking wrappers keep their signatures: the name is still resolved,
// against `registry_role_templates`, and an unknown name still fails before
// anything is written anywhere.
func (r *OrganizationRepository) AddMemberWithRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.AddMemberWithRoleTemplate(ctx, orgID, userID, nil, scope); err != nil {
		return err
	}
	return r.mirrorRequestedRole(ctx, orgID, userID, roleTemplateID, scope)
}

func (r *OrganizationRepository) AddMemberWithParams(ctx context.Context, orgID, userID, roleTemplateName string, scope identitystore.OrgScope) error {
	registryRole, err := r.registryRoleTemplateID(ctx, roleTemplateName)
	if err != nil {
		return err
	}
	// The id-taking twin, not AddMemberWithParams: the name-taking one is the
	// call that reads identity's `role_templates`.
	if err := r.OrganizationRepository.AddMemberWithRoleTemplate(ctx, orgID, userID, nil, scope); err != nil {
		return err
	}
	return r.mirrorRequestedRole(ctx, orgID, userID, registryRole, scope)
}

func (r *OrganizationRepository) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope identitystore.OrgScope) error {
	if err := r.OrganizationRepository.UpdateMemberRoleTemplate(ctx, orgID, userID, nil, scope); err != nil {
		return err
	}
	return r.mirrorRequestedRole(ctx, orgID, userID, roleTemplateID, scope)
}

func (r *OrganizationRepository) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string, scope identitystore.OrgScope) error {
	registryRole, err := r.registryRoleTemplateID(ctx, roleTemplateName)
	if err != nil {
		return err
	}
	// UpdateMemberRoleTemplate, not UpdateMemberRole: identical scoping and
	// requireRow semantics -- it is what the name-taking one delegates to --
	// without the lookup in identity's table.
	if err := r.OrganizationRepository.UpdateMemberRoleTemplate(ctx, orgID, userID, nil, scope); err != nil {
		return err
	}
	return r.mirrorRequestedRole(ctx, orgID, userID, registryRole, scope)
}

// RemoveMember withdraws a membership. REVOCATION: the mirror goes first.
//
// A failure here returns before identity is touched, so nothing changed
// anywhere. The mirror delete also runs when the membership is already gone --
// it is a DELETE, and removing a row that is not there is the desired end state.
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string, scope identitystore.OrgScope) error {
	if err := r.mirror.ClearMember(ctx, orgID, userID); err != nil {
		return fmt.Errorf("withdraw the role in registry's own tables: %w", err)
	}
	return r.OrganizationRepository.RemoveMember(ctx, orgID, userID, scope)
}

// RemoveAllMembershipsForUser strips a user's memberships. REVOCATION, mirrored
// TWICE on purpose.
//
// The PRE-PASS clears registry's assignments across the scope the strip is about
// to apply, so a failure returns before identity is touched. It cannot know
// which rows the strip will match, so it clears the whole scope: a DELETE for a
// pair that was never a member is a no-op, and over-clearing is the safe
// direction for a revocation.
//
// The POST-PASS clears exactly what identity reports it removed. It is not
// redundant: a grant racing between the two legs would otherwise leave an
// assignment behind for a membership that no longer exists.
func (r *OrganizationRepository) RemoveAllMembershipsForUser(ctx context.Context, userID string, scope identitystore.OrgScope) (identitystore.OrgScope, error) {
	// PRE-PASS, before identity is touched, over the scope the strip is about to
	// apply. It cannot know which rows the strip will match, so it clears the
	// whole scope: a DELETE for a pair that was never a member is a no-op, and
	// over-clearing is the safe direction for a revocation.
	if err := r.mirror.ClearUserInScope(ctx, userID, scope); err != nil {
		return identitystore.OrgScope{}, fmt.Errorf("withdraw the user's roles in registry's own tables: %w", err)
	}

	removed, err := r.OrganizationRepository.RemoveAllMembershipsForUser(ctx, userID, scope)
	if err != nil {
		return removed, err
	}

	// POST-PASS over exactly what identity reports it removed. Not redundant: a
	// grant racing between the two legs would otherwise leave an assignment
	// behind for a membership that no longer exists.
	if err := r.mirror.ClearUserInScope(ctx, userID, removed); err != nil {
		return removed, fmt.Errorf("withdraw the user's roles in registry's own tables: %w", err)
	}
	return removed, nil
}

// ErrNamespaceRenameConflict reports that an organization rename would move a
// namespace that another organization owns, in either direction: renaming AWAY
// from a namespace whose content belongs to someone else, or renaming INTO a
// namespace someone else already owns. The second direction is a takeover, and
// it is the more dangerous of the two.
var ErrNamespaceRenameConflict = errors.New("namespace is owned by another organization")

// namespaceQuerier is the read surface the ownership pre-flight needs. Both
// *sql.DB and *sql.Tx satisfy it, so the SAME rule runs standalone in the
// handler (to refuse before the identity-side rename commits) and again inside
// the cascade transaction (where it can hold row locks).
type namespaceQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// resolveNamespaceOwner mirrors middleware.NamespaceAuthorizer.resolveOwnerOrg
// exactly, deliberately: a claim wins; without one, the single organization
// owning artifact rows in the namespace is authoritative; a namespace with
// neither is unowned and returns "". Two or more artifact organizations and no
// claim is ambiguous, and ambiguous ownership must never authorize a bulk move.
//
// Kept as raw SQL here rather than reusing NamespaceClaimRepository because
// those methods are bound to their own *sql.DB and cannot participate in the
// cascade's transaction.
//
// lockClaim takes FOR UPDATE on the claim row so a concurrent transfer cannot
// land between this check and the UPDATEs it authorizes. It is only applied to
// the claims read: Postgres rejects FOR UPDATE on the UNION/DISTINCT fallback.
func resolveNamespaceOwner(ctx context.Context, q namespaceQuerier, namespace string, lockClaim bool) (string, error) {
	claimQuery := `SELECT organization_id FROM namespace_claims WHERE namespace = $1`
	if lockClaim {
		claimQuery += ` FOR UPDATE`
	}
	var owner string
	switch err := q.QueryRowContext(ctx, claimQuery, namespace).Scan(&owner); {
	case err == nil:
		return owner, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("read namespace claim %q: %w", namespace, err)
	}

	rows, err := q.QueryContext(ctx, `
		SELECT DISTINCT organization_id FROM (
			SELECT organization_id FROM modules   WHERE namespace = $1 AND organization_id IS NOT NULL
			UNION
			SELECT organization_id FROM providers WHERE namespace = $1 AND organization_id IS NOT NULL
		) artifact_orgs`, namespace)
	if err != nil {
		return "", fmt.Errorf("read namespace artifact organizations %q: %w", namespace, err)
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return "", fmt.Errorf("scan namespace artifact organization %q: %w", namespace, err)
		}
		owners = append(owners, orgID)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate namespace artifact organizations %q: %w", namespace, err)
	}

	switch len(owners) {
	case 0:
		return "", nil
	case 1:
		return owners[0], nil
	default:
		// Ambiguous. Refuse rather than guess: a wrong guess here rewrites
		// another tenant's rows, which is the whole defect this check exists for.
		return "", fmt.Errorf("%w: namespace %q has artifacts owned by %d organizations and no claim",
			ErrNamespaceRenameConflict, namespace, len(owners))
	}
}

// checkRenameNamespaceConflicts proves that renaming orgID from oldName to
// newName moves only namespaces this organization owns.
//
// BOTH directions are checked, and the target side is the one the issue title
// understated. Source side: the cascade rewrites every row in the old namespace,
// so this organization must own it. Target side: the cascade rewrites those rows
// INTO the new namespace, so if another organization owns that namespace the
// rename is a cross-tenant takeover -- the renaming organization's content lands
// under a namespace someone else holds the claim to, and the protocol read path
// (which resolves by namespace alone) then serves whichever row is older.
//
// An unowned namespace on either side is fine: nothing to move, or nothing to
// collide with. This is the common case for an organization that never published.
func checkRenameNamespaceConflicts(ctx context.Context, q namespaceQuerier, orgID, oldName, newName string) error {
	for _, side := range []struct {
		namespace string
		direction string
	}{
		{oldName, "rename would move artifacts out of"},
		{newName, "rename would move artifacts into"},
	} {
		owner, err := resolveNamespaceOwner(ctx, q, side.namespace, true)
		if err != nil {
			return err
		}
		if owner != "" && owner != orgID {
			return fmt.Errorf("%w: %s namespace %q, which belongs to organization %s",
				ErrNamespaceRenameConflict, side.direction, side.namespace, owner)
		}
	}
	return nil
}

// CheckOrganizationRenameConflicts runs the namespace-ownership pre-flight
// outside a transaction so a caller can refuse a rename BEFORE any write
// happens. The cascade re-runs the same rule under row locks; this exists so the
// identity-side rename -- which commits on a different connection and cannot be
// rolled back by the cascade -- is never performed for a rename that the cascade
// will then refuse.
func CheckOrganizationRenameConflicts(ctx context.Context, db *sql.DB, orgID, oldName, newName string) error {
	return checkRenameNamespaceConflicts(ctx, db, orgID, oldName, newName)
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

	// Prove this organization owns BOTH namespaces before rewriting either.
	// Holds FOR UPDATE on the claim rows for the rest of the transaction, so a
	// concurrent transfer cannot land between the check and the UPDATEs it
	// authorizes.
	if err = checkRenameNamespaceConflicts(ctx, tx, orgID, oldName, newName); err != nil {
		return err
	}

	// Match module/provider rows by namespace alone, NOT by organization_id.
	// The organization_id predicate is deliberately ABSENT, and that is now safe
	// because checkRenameNamespaceConflicts above has PROVEN this organization
	// owns the namespace. Do not add `AND organization_id = $orgID` here.
	//
	// Why the predicate must stay absent (issue #555): rows published before
	// #778 can still carry the DEFAULT organization rather than the namespace's
	// true owner, so an organization_id predicate would match nothing whenever a
	// NON-default organization is renamed -- silently leaving that organization's
	// artifacts pinned to the old namespace while the organization row and its
	// namespace_claims move, orphaning them from the unauthenticated protocol
	// read path (which resolves modules/providers by namespace alone).
	//
	// #778 made new uploads stamp the true owning organization, which makes the
	// ORIGINAL justification for this comment stale -- but not its conclusion.
	// Legacy rows still exist, so namespace-wide matching stays. What changed is
	// that the authority to rewrite a whole namespace now comes from the proven
	// ownership check, not from an assumption that the namespace must be ours.
	// The namespace_claims row below is matched by organization_id because
	// claims -- unlike artifact rows -- always carry the true owning organization.
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

	// Re-read the target claim before committing. FOR UPDATE cannot lock a row
	// that does not exist yet, so under READ COMMITTED a concurrent first-publish
	// can claim the target namespace after the pre-flight passed. A committed
	// insert IS visible to this re-read, so it converts that race into a clean
	// refusal instead of a silent takeover.
	if owner, err := resolveNamespaceOwner(ctx, tx, newName, false); err != nil {
		return err
	} else if owner != "" && owner != orgID {
		return fmt.Errorf("%w: namespace %q was claimed by organization %s during the rename",
			ErrNamespaceRenameConflict, newName, owner)
	}

	return tx.Commit()
}

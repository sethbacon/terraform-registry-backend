// Package repositories - user_repository.go wraps the UserRepository from the
// shared identity store.
//
// It was a type ALIAS until the read cutover (sethbacon/terraform-suite-identity#206,
// phase 3b) and is a wrapper now for one reason: three of the store's user
// accessors return the user's MEMBERSHIPS, each carrying a role template and its
// scopes, and since the cutover that role has to come from registry's own tables
// like every other. An alias cannot override anything, so those three reads were
// the one authorization surface the cutover could not reach -- GET
// /api/v1/users/:id and the admin user list would have kept answering from
// `organization_members.role_template_id` while every enforcement path answered
// from registry's tables. Two answers to one question, differing only on the rows
// that are wrong.
//
// The constructor keeps its name and signature, so no call site changes.
package repositories

import (
	"context"
	"database/sql"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// UserRepository handles user database operations.
//
// It embeds the shared store's repository, so every accessor that does NOT
// return a role -- which is most of them -- is promoted unchanged. The three
// that do are overridden below, and user_role_read_class_test.go fails if the
// pinned module grows a fourth.
type UserRepository struct {
	*identitystore.UserRepository

	// roles reads registry's own authorization tables. Same connection as the
	// embedded repository, for the same reason as OrganizationRepository.roles.
	roles *MemberRoleReader
}

// NewUserRepository constructs a UserRepository over the given connection.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		UserRepository: identitystore.NewUserRepository(db),
		roles:          NewMemberRoleReader(db),
	}
}

// GetUserWithOrgRoles returns the user with their memberships, each carrying
// the role registry's own tables hold for it.
func (r *UserRepository) GetUserWithOrgRoles(ctx context.Context, userID string, scope identitystore.OrgScope) (*models.UserWithOrgRoles, error) {
	user, err := r.UserRepository.GetUserWithOrgRoles(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	if len(user.Memberships) == 0 {
		return user, nil
	}
	roles, err := r.roles.RolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	overlayMemberships(ctx, "GetUserWithOrgRoles", userID, user.Memberships, roles)
	return user, nil
}

// ListUsersWithMemberships returns a page of users with registry's own roles.
//
// Overridden even though the store implements it in terms of an unexported
// helper: Go promotes it otherwise, and the promoted version resolves roles from
// the identity tables. The overlay is applied to the RESULT rather than inside
// the helper, which is not reachable from here -- and which is the right place
// anyway, because one bulk read for the whole page preserves the 2-query shape
// the store went to trouble to get.
func (r *UserRepository) ListUsersWithMemberships(ctx context.Context, limit, offset int, scope identitystore.OrgScope) ([]*models.UserWithOrgRoles, int, error) {
	users, total, err := r.UserRepository.ListUsersWithMemberships(ctx, limit, offset, scope)
	if err != nil {
		return nil, total, err
	}
	if err := r.overlayUsers(ctx, "ListUsersWithMemberships", users); err != nil {
		return nil, total, err
	}
	return users, total, nil
}

// SearchWithMemberships returns matching users with registry's own roles.
func (r *UserRepository) SearchWithMemberships(ctx context.Context, query string, limit, offset int, scope identitystore.OrgScope) ([]*models.UserWithOrgRoles, error) {
	users, err := r.UserRepository.SearchWithMemberships(ctx, query, limit, offset, scope)
	if err != nil {
		return nil, err
	}
	if err := r.overlayUsers(ctx, "SearchWithMemberships", users); err != nil {
		return nil, err
	}
	return users, nil
}

// overlayUsers replaces the roles on a page of users with registry's, in one
// bulk read.
func (r *UserRepository) overlayUsers(ctx context.Context, accessor string, users []*models.UserWithOrgRoles) error {
	ids := make([]string, 0, len(users))
	for _, u := range users {
		if len(u.Memberships) > 0 {
			ids = append(ids, u.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	byUser, err := r.roles.RolesForUsers(ctx, ids)
	if err != nil {
		return err
	}
	for _, u := range users {
		overlayMemberships(ctx, accessor, u.ID, u.Memberships, byUser[u.ID])
	}
	return nil
}

// overlayMemberships rewrites each membership's role fields from registry's
// tables, reporting any disagreement.
//
// The slice is of VALUES, not pointers, so the loop indexes rather than ranges
// over copies -- ranging by value here would compare and overwrite a temporary
// and leave every caller reading identity's role, which is the whole defect
// this file exists to prevent and would produce no test failure anywhere.
func overlayMemberships(ctx context.Context, accessor, userID string, memberships []models.UserMembership, roles map[string]*MirroredRole) {
	for i := range memberships {
		m := &memberships[i]
		role := roles[m.OrganizationID]
		compareRole(ctx, accessor, m.OrganizationID, userID, m.RoleTemplateID, role)
		applyMirroredRole(role, &m.RoleTemplateID, &m.RoleTemplateName,
			&m.RoleTemplateDisplayName, &m.RoleTemplateScopes)
	}
}

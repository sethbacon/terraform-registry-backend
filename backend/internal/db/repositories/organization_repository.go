// organization_repository.go implements OrganizationRepository, providing database queries
// for organization CRUD, membership management, and role lookup.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// OrganizationRepository handles database operations for organizations
type OrganizationRepository struct {
	db *sql.DB
}

// NewOrganizationRepository creates a new organization repository
func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// GetDefaultOrganization retrieves the default organization for single-tenant mode
func (r *OrganizationRepository) GetDefaultOrganization(ctx context.Context) (*models.Organization, error) {
	return r.GetByName(ctx, "default")
}

// GetByName retrieves an organization by its name
func (r *OrganizationRepository) GetByName(ctx context.Context, name string) (*models.Organization, error) {
	query := `
		SELECT id, name, display_name, created_at, updated_at
		FROM organizations
		WHERE name = $1
	`

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// GetByID retrieves an organization by ID
func (r *OrganizationRepository) GetByID(ctx context.Context, id string) (*models.Organization, error) {
	query := `
		SELECT id, name, display_name, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// CreateOrganization creates a new organization
func (r *OrganizationRepository) CreateOrganization(ctx context.Context, org *models.Organization) error {
	query := `
		INSERT INTO organizations (name, display_name)
		VALUES ($1, $2)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRowContext(ctx, query, org.Name, org.DisplayName).Scan(
		&org.ID,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}

	return nil
}

// === Organization Membership Operations ===

// AddMemberWithRoleTemplate adds a user to an organization with the specified role template
func (r *OrganizationRepository) AddMemberWithRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	query := `
		INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at)
		VALUES ($1, $2, $3, NOW())
	`

	_, err := r.db.ExecContext(ctx, query, orgID, userID, roleTemplateID)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

// AddMemberWithParams adds a user to an organization with the specified role template (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) AddMemberWithParams(ctx context.Context, orgID, userID, roleTemplateName string) error {
	// Look up role template ID by name
	var roleTemplateID *string
	query := `SELECT id FROM role_templates WHERE name = $1`
	var id string
	err := r.db.QueryRowContext(ctx, query, roleTemplateName).Scan(&id)
	if err == nil {
		roleTemplateID = &id
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to look up role template: %w", err)
	}

	return r.AddMemberWithRoleTemplate(ctx, orgID, userID, roleTemplateID)
}

// RemoveMember removes a user from an organization
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string) error {
	query := `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`
	_, err := r.db.ExecContext(ctx, query, orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	return nil
}

// UpdateMemberRoleTemplate changes a user's role template in an organization
func (r *OrganizationRepository) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	query := `
		UPDATE organization_members
		SET role_template_id = $3
		WHERE organization_id = $1 AND user_id = $2
	`

	_, err := r.db.ExecContext(ctx, query, orgID, userID, roleTemplateID)
	if err != nil {
		return fmt.Errorf("failed to update member role template: %w", err)
	}

	return nil
}

// UpdateMemberRole changes a user's role template in an organization (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string) error {
	// Look up role template ID by name
	var roleTemplateID *string
	query := `SELECT id FROM role_templates WHERE name = $1`
	var id string
	err := r.db.QueryRowContext(ctx, query, roleTemplateName).Scan(&id)
	if err == nil {
		roleTemplateID = &id
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to look up role template: %w", err)
	}

	return r.UpdateMemberRoleTemplate(ctx, orgID, userID, roleTemplateID)
}

// GetMember retrieves a user's membership in an organization
func (r *OrganizationRepository) GetMember(ctx context.Context, orgID, userID string) (*models.OrganizationMember, error) {
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1 AND user_id = $2
	`

	member := &models.OrganizationMember{}
	err := r.db.QueryRowContext(ctx, query, orgID, userID).Scan(
		&member.OrganizationID,
		&member.UserID,
		&member.RoleTemplateID,
		&member.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return member, nil
}

// ListMembers retrieves all members of an organization
func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID string) ([]*models.OrganizationMember, error) {
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	members := make([]*models.OrganizationMember, 0)
	for rows.Next() {
		member := &models.OrganizationMember{}
		err := rows.Scan(
			&member.OrganizationID,
			&member.UserID,
			&member.RoleTemplateID,
			&member.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, member)
	}

	return members, rows.Err()
}

// GetUserOrganizations retrieves all organizations a user belongs to
func (r *OrganizationRepository) GetUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error) {
	query := `
		SELECT o.id, o.name, o.display_name, o.created_at, o.updated_at
		FROM organizations o
		INNER JOIN organization_members om ON o.id = om.organization_id
		WHERE om.user_id = $1
		ORDER BY o.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer rows.Close()

	organizations := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		organizations = append(organizations, org)
	}

	return organizations, rows.Err()
}

// CheckMembership checks if a user is a member of an organization and returns their role template ID
func (r *OrganizationRepository) CheckMembership(ctx context.Context, orgID, userID string) (bool, *string, error) {
	member, err := r.GetMember(ctx, orgID, userID)
	if err != nil {
		return false, nil, err
	}

	if member == nil {
		return false, nil, nil
	}

	return true, member.RoleTemplateID, nil
}

// GetMemberWithRole retrieves a user's membership in an organization with role template info
func (r *OrganizationRepository) GetMemberWithRole(ctx context.Context, orgID, userID string) (*models.OrganizationMemberWithUser, error) {
	query := `
		SELECT om.organization_id, om.user_id, om.role_template_id, om.created_at,
		       COALESCE(u.name, '') as user_name, COALESCE(u.email, '') as user_email,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes
		FROM organization_members om
		LEFT JOIN users u ON om.user_id = u.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id
		WHERE om.organization_id = $1 AND om.user_id = $2
	`

	member := &models.OrganizationMemberWithUser{}
	var scopesJSON []byte
	err := r.db.QueryRowContext(ctx, query, orgID, userID).Scan(
		&member.OrganizationID,
		&member.UserID,
		&member.RoleTemplateID,
		&member.CreatedAt,
		&member.UserName,
		&member.UserEmail,
		&member.RoleTemplateName,
		&member.RoleTemplateDisplayName,
		&scopesJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	// Parse scopes JSON
	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &member.RoleTemplateScopes); err != nil {
			return nil, fmt.Errorf("failed to parse scopes: %w", err)
		}
	}

	return member, nil
}

// Create is an alias for CreateOrganization to match admin handlers
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	return r.CreateOrganization(ctx, org)
}

// Update updates an organization
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	query := `
		UPDATE organizations
		SET display_name = $2, updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, org.ID, org.DisplayName)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	return nil
}

// Delete deletes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, orgID string) error {
	query := `DELETE FROM organizations WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	return nil
}

// List retrieves a paginated list of organizations
func (r *OrganizationRepository) List(ctx context.Context, limit, offset int) ([]*models.Organization, error) {
	query := `
		SELECT id, name, display_name, created_at, updated_at
		FROM organizations
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	orgs := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}

	return orgs, rows.Err()
}

// Count returns the total number of organizations
func (r *OrganizationRepository) Count(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM organizations`
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	return count, nil
}

// Search searches for organizations by name or display name
func (r *OrganizationRepository) Search(ctx context.Context, query string, limit, offset int) ([]*models.Organization, error) {
	searchQuery := `
		SELECT id, name, display_name, created_at, updated_at
		FROM organizations
		WHERE name ILIKE $1 OR display_name ILIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	searchPattern := "%" + query + "%"
	rows, err := r.db.QueryContext(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}
	defer rows.Close()

	orgs := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}

	return orgs, rows.Err()
}

// ListUserOrganizations is an alias for GetUserOrganizations
func (r *OrganizationRepository) ListUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error) {
	return r.GetUserOrganizations(ctx, userID)
}

// AddMember with models.OrganizationMember parameter
func (r *OrganizationRepository) AddMember(ctx context.Context, member *models.OrganizationMember) error {
	query := `
		INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.ExecContext(ctx, query,
		member.OrganizationID,
		member.UserID,
		member.RoleTemplateID,
		member.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

// UpdateMember updates a member's information
func (r *OrganizationRepository) UpdateMember(ctx context.Context, member *models.OrganizationMember) error {
	return r.UpdateMemberRoleTemplate(ctx, member.OrganizationID, member.UserID, member.RoleTemplateID)
}

// ListMembersWithUsers retrieves all members of an organization with user details and role template info
func (r *OrganizationRepository) ListMembersWithUsers(ctx context.Context, orgID string) ([]*models.OrganizationMemberWithUser, error) {
	query := `
		SELECT om.organization_id, om.user_id, om.role_template_id, om.created_at,
		       COALESCE(u.name, '') as user_name, COALESCE(u.email, '') as user_email,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes
		FROM organization_members om
		LEFT JOIN users u ON om.user_id = u.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id
		WHERE om.organization_id = $1
		ORDER BY om.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members with users: %w", err)
	}
	defer rows.Close()

	members := make([]*models.OrganizationMemberWithUser, 0)
	for rows.Next() {
		member := &models.OrganizationMemberWithUser{}
		var scopesJSON []byte
		err := rows.Scan(
			&member.OrganizationID,
			&member.UserID,
			&member.RoleTemplateID,
			&member.CreatedAt,
			&member.UserName,
			&member.UserEmail,
			&member.RoleTemplateName,
			&member.RoleTemplateDisplayName,
			&scopesJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		// Parse scopes JSON
		if len(scopesJSON) > 0 {
			if err := json.Unmarshal(scopesJSON, &member.RoleTemplateScopes); err != nil {
				return nil, fmt.Errorf("failed to parse scopes: %w", err)
			}
		}
		members = append(members, member)
	}

	return members, rows.Err()
}

// GetUserMemberships retrieves all organization memberships for a user with role template info
func (r *OrganizationRepository) GetUserMemberships(ctx context.Context, userID string) ([]*models.UserMembership, error) {
	query := `
		SELECT om.organization_id, COALESCE(o.name, '') as organization_name,
		       om.role_template_id, om.created_at,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes
		FROM organization_members om
		LEFT JOIN organizations o ON om.organization_id = o.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id
		WHERE om.user_id = $1
		ORDER BY om.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	memberships := make([]*models.UserMembership, 0)
	for rows.Next() {
		m := &models.UserMembership{}
		var scopesJSON []byte
		err := rows.Scan(
			&m.OrganizationID,
			&m.OrganizationName,
			&m.RoleTemplateID,
			&m.CreatedAt,
			&m.RoleTemplateName,
			&m.RoleTemplateDisplayName,
			&scopesJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		// Parse scopes JSON
		if len(scopesJSON) > 0 {
			if err := json.Unmarshal(scopesJSON, &m.RoleTemplateScopes); err != nil {
				return nil, fmt.Errorf("failed to parse scopes: %w", err)
			}
		}
		memberships = append(memberships, m)
	}

	return memberships, rows.Err()
}

// GetUserCombinedScopes retrieves all unique scopes for a user across all their organization memberships.
// This is used for JWT authentication where we need to know what the user can do globally.
func (r *OrganizationRepository) GetUserCombinedScopes(ctx context.Context, userID string) ([]string, error) {
	memberships, err := r.GetUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Use a map to deduplicate scopes
	scopeMap := make(map[string]bool)
	for _, m := range memberships {
		for _, scope := range m.RoleTemplateScopes {
			scopeMap[scope] = true
		}
	}

	// Convert map to slice
	scopes := make([]string, 0, len(scopeMap))
	for scope := range scopeMap {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

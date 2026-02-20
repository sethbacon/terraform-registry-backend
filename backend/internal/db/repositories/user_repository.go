// Package repositories implements the data access layer (repository pattern) for the Terraform Registry.
// Each repository type encapsulates all database queries for a domain entity.
// Handlers never issue SQL directly — all database access goes through this layer, which makes query logic testable in isolation and prevents accidental cross-domain data access.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// UserRepository handles user database operations
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// CreateUser creates a new user
func (r *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	query := `
		INSERT INTO users (id, email, name, oidc_sub, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.OIDCSub,
		user.CreatedAt,
		user.UpdatedAt,
	)

	return err
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByOIDCSub retrieves a user by OIDC subject identifier
func (r *UserRepository) GetUserByOIDCSub(ctx context.Context, oidcSub string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE oidc_sub = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, oidcSub).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUser updates a user's information
func (r *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users
		SET email = $2, name = $3, oidc_sub = $4, updated_at = $5
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.OIDCSub,
		user.UpdatedAt,
	)

	return err
}

// DeleteUser deletes a user (cascades to API keys and memberships)
func (r *UserRepository) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// ListUsers retrieves a paginated list of users
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated users
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.OIDCSub,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}

	return users, total, rows.Err()
}

// GetOrCreateUserFromOIDC gets or creates a user from OIDC authentication
func (r *UserRepository) GetOrCreateUserFromOIDC(ctx context.Context, oidcSub, email, name string) (*models.User, error) {
	// Try to find existing user by OIDC sub
	user, err := r.GetUserByOIDCSub(ctx, oidcSub)
	if err != nil {
		return nil, err
	}

	if user != nil {
		// User exists, update email and name if changed
		if user.Email != email || user.Name != name {
			user.Email = email
			user.Name = name
			err = r.UpdateUser(ctx, user)
			if err != nil {
				return nil, err
			}
		}
		return user, nil
	}

	// User doesn't exist, create new one
	newUser := &models.User{
		Email:   email,
		Name:    name,
		OIDCSub: &oidcSub,
	}

	err = r.CreateUser(ctx, newUser)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

// Create is an alias for CreateUser to match the admin handlers
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	return r.CreateUser(ctx, user)
}

// Update is an alias for UpdateUser to match the admin handlers
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	return r.UpdateUser(ctx, user)
}

// Delete is an alias for DeleteUser to match the admin handlers
func (r *UserRepository) Delete(ctx context.Context, userID string) error {
	return r.DeleteUser(ctx, userID)
}

// List retrieves a paginated list of users (simplified version)
func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.OIDCSub,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// Count returns the total number of users
func (r *UserRepository) Count(ctx context.Context) (int, error) {
	var total int
	query := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRowContext(ctx, query).Scan(&total)
	return total, err
}

// Search searches for users by email or name
func (r *UserRepository) Search(ctx context.Context, query string, limit, offset int) ([]*models.User, error) {
	searchQuery := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE email ILIKE $1 OR name ILIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	searchPattern := "%" + query + "%"
	rows, err := r.db.QueryContext(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.OIDCSub,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// GetOrCreateUserByOIDC is an alias for GetOrCreateUserFromOIDC
func (r *UserRepository) GetOrCreateUserByOIDC(ctx context.Context, oidcSub, email, name string) (*models.User, error) {
	return r.GetOrCreateUserFromOIDC(ctx, oidcSub, email, name)
}

// GetUserWithOrgRoles retrieves a user with their per-organization role template information
func (r *UserRepository) GetUserWithOrgRoles(ctx context.Context, userID string) (*models.UserWithOrgRoles, error) {
	// First get the basic user info
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	// Then get all memberships with role templates
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
		return nil, err
	}
	defer rows.Close()

	memberships := make([]models.UserMembership, 0)
	for rows.Next() {
		m := models.UserMembership{}
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
			return nil, err
		}
		// Parse scopes JSON
		if len(scopesJSON) > 0 {
			if err := json.Unmarshal(scopesJSON, &m.RoleTemplateScopes); err != nil {
				return nil, err
			}
		}
		memberships = append(memberships, m)
	}

	return &models.UserWithOrgRoles{
		User:        *user,
		Memberships: memberships,
	}, rows.Err()
}

// ListUsersWithRoles is deprecated - use ListUsers instead
// Role templates are now per-organization, not per-user
func (r *UserRepository) ListUsersWithRoles(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	return r.ListUsers(ctx, limit, offset)
}

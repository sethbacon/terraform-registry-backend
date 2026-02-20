// rbac_repository.go implements RBACRepository, providing database queries for role template
// CRUD, approval request workflows, and mirror policy management.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// RBACRepository handles database operations for RBAC features
type RBACRepository struct {
	db *sqlx.DB
}

// NewRBACRepository creates a new RBAC repository
func NewRBACRepository(db *sqlx.DB) *RBACRepository {
	return &RBACRepository{db: db}
}

// ============================================================================
// Role Templates
// ============================================================================

// ListRoleTemplates returns all role templates
func (r *RBACRepository) ListRoleTemplates(ctx context.Context) ([]*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates ORDER BY name`

	rows, err := r.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*models.RoleTemplate
	for rows.Next() {
		var t models.RoleTemplate
		var scopesJSON []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
			return nil, err
		}
		templates = append(templates, &t)
	}

	return templates, rows.Err()
}

// GetRoleTemplate retrieves a role template by ID
func (r *RBACRepository) GetRoleTemplate(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE id = $1`

	var t models.RoleTemplate
	var scopesJSON []byte
	err := r.db.QueryRowxContext(ctx, query, id).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return nil, err
	}

	return &t, nil
}

// GetRoleTemplateByName retrieves a role template by name
func (r *RBACRepository) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE name = $1`

	var t models.RoleTemplate
	var scopesJSON []byte
	err := r.db.QueryRowxContext(ctx, query, name).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return nil, err
	}

	return &t, nil
}

// CreateRoleTemplate creates a new role template
func (r *RBACRepository) CreateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return err
	}

	query := `INSERT INTO role_templates (id, name, display_name, description, scopes, is_system, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.db.ExecContext(ctx, query,
		template.ID, template.Name, template.DisplayName, template.Description, scopesJSON, template.IsSystem, template.CreatedAt, template.UpdatedAt)
	return err
}

// UpdateRoleTemplate updates an existing role template
func (r *RBACRepository) UpdateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return err
	}

	query := `UPDATE role_templates SET display_name = $2, description = $3, scopes = $4, updated_at = $5
			  WHERE id = $1 AND is_system = false`

	_, err = r.db.ExecContext(ctx, query,
		template.ID, template.DisplayName, template.Description, scopesJSON, time.Now())
	return err
}

// DeleteRoleTemplate deletes a role template (only non-system templates)
func (r *RBACRepository) DeleteRoleTemplate(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM role_templates WHERE id = $1 AND is_system = false`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// ============================================================================
// Mirror Approval Requests
// ============================================================================

// CreateApprovalRequest creates a new approval request
func (r *RBACRepository) CreateApprovalRequest(ctx context.Context, req *models.MirrorApprovalRequest) error {
	query := `INSERT INTO mirror_approval_requests
			  (id, mirror_config_id, organization_id, requested_by, provider_namespace, provider_name, reason, status, auto_approved, created_at, updated_at, expires_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.db.ExecContext(ctx, query,
		req.ID, req.MirrorConfigID, req.OrganizationID, req.RequestedBy,
		req.ProviderNamespace, req.ProviderName, req.Reason, req.Status,
		req.AutoApproved, req.CreatedAt, req.UpdatedAt, req.ExpiresAt)
	return err
}

// GetApprovalRequest retrieves an approval request by ID
func (r *RBACRepository) GetApprovalRequest(ctx context.Context, id uuid.UUID) (*models.MirrorApprovalRequest, error) {
	query := `SELECT id, mirror_config_id, organization_id, requested_by, provider_namespace, provider_name,
			  reason, status, reviewed_by, reviewed_at, review_notes, auto_approved, created_at, updated_at, expires_at
			  FROM mirror_approval_requests WHERE id = $1`

	var req models.MirrorApprovalRequest
	err := r.db.QueryRowxContext(ctx, query, id).Scan(
		&req.ID, &req.MirrorConfigID, &req.OrganizationID, &req.RequestedBy,
		&req.ProviderNamespace, &req.ProviderName, &req.Reason, &req.Status,
		&req.ReviewedBy, &req.ReviewedAt, &req.ReviewNotes, &req.AutoApproved,
		&req.CreatedAt, &req.UpdatedAt, &req.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &req, err
}

// ListApprovalRequests lists approval requests with optional filters
func (r *RBACRepository) ListApprovalRequests(ctx context.Context, orgID *uuid.UUID, status *models.ApprovalStatus) ([]*models.MirrorApprovalRequest, error) {
	query := `SELECT mar.id, mar.mirror_config_id, mar.organization_id, mar.requested_by, mar.provider_namespace, mar.provider_name,
			  mar.reason, mar.status, mar.reviewed_by, mar.reviewed_at, mar.review_notes, mar.auto_approved,
			  mar.created_at, mar.updated_at, mar.expires_at,
			  COALESCE(u1.name, '') as requested_by_name,
			  COALESCE(u2.name, '') as reviewed_by_name,
			  COALESCE(mc.name, '') as mirror_name
			  FROM mirror_approval_requests mar
			  LEFT JOIN users u1 ON mar.requested_by = u1.id
			  LEFT JOIN users u2 ON mar.reviewed_by = u2.id
			  LEFT JOIN mirror_configurations mc ON mar.mirror_config_id = mc.id
			  WHERE 1=1`

	args := []interface{}{}
	argNum := 1

	if orgID != nil {
		query += ` AND mar.organization_id = $` + string(rune('0'+argNum))
		args = append(args, *orgID)
		argNum++
	}

	if status != nil {
		query += ` AND mar.status = $` + string(rune('0'+argNum))
		args = append(args, *status)
		argNum++
	}

	query += ` ORDER BY mar.created_at DESC`

	rows, err := r.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*models.MirrorApprovalRequest
	for rows.Next() {
		var req models.MirrorApprovalRequest
		if err := rows.Scan(
			&req.ID, &req.MirrorConfigID, &req.OrganizationID, &req.RequestedBy,
			&req.ProviderNamespace, &req.ProviderName, &req.Reason, &req.Status,
			&req.ReviewedBy, &req.ReviewedAt, &req.ReviewNotes, &req.AutoApproved,
			&req.CreatedAt, &req.UpdatedAt, &req.ExpiresAt,
			&req.RequestedByName, &req.ReviewedByName, &req.MirrorName); err != nil {
			return nil, err
		}
		requests = append(requests, &req)
	}

	return requests, rows.Err()
}

// ListPendingApprovals lists all pending approval requests
func (r *RBACRepository) ListPendingApprovals(ctx context.Context, orgID *uuid.UUID) ([]*models.MirrorApprovalRequest, error) {
	status := models.ApprovalStatusPending
	return r.ListApprovalRequests(ctx, orgID, &status)
}

// UpdateApprovalStatus updates the status of an approval request
func (r *RBACRepository) UpdateApprovalStatus(ctx context.Context, id uuid.UUID, status models.ApprovalStatus, reviewedBy uuid.UUID, notes string) error {
	query := `UPDATE mirror_approval_requests
			  SET status = $2, reviewed_by = $3, reviewed_at = $4, review_notes = $5, updated_at = $6
			  WHERE id = $1`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, id, status, reviewedBy, now, notes, now)
	return err
}

// CheckApproval checks if a provider is approved for mirroring
func (r *RBACRepository) CheckApproval(ctx context.Context, mirrorConfigID uuid.UUID, namespace, provider string) (*models.MirrorApprovalRequest, error) {
	query := `SELECT id, mirror_config_id, organization_id, requested_by, provider_namespace, provider_name,
			  reason, status, reviewed_by, reviewed_at, review_notes, auto_approved, created_at, updated_at, expires_at
			  FROM mirror_approval_requests
			  WHERE mirror_config_id = $1
			    AND provider_namespace = $2
			    AND (provider_name IS NULL OR provider_name = $3)
			    AND status = 'approved'
			    AND (expires_at IS NULL OR expires_at > NOW())
			  ORDER BY provider_name DESC NULLS LAST
			  LIMIT 1`

	var req models.MirrorApprovalRequest
	err := r.db.QueryRowxContext(ctx, query, mirrorConfigID, namespace, provider).Scan(
		&req.ID, &req.MirrorConfigID, &req.OrganizationID, &req.RequestedBy,
		&req.ProviderNamespace, &req.ProviderName, &req.Reason, &req.Status,
		&req.ReviewedBy, &req.ReviewedAt, &req.ReviewNotes, &req.AutoApproved,
		&req.CreatedAt, &req.UpdatedAt, &req.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &req, err
}

// ============================================================================
// Mirror Policies
// ============================================================================

// CreateMirrorPolicy creates a new mirror policy
func (r *RBACRepository) CreateMirrorPolicy(ctx context.Context, policy *models.MirrorPolicy) error {
	query := `INSERT INTO mirror_policies
			  (id, organization_id, name, description, policy_type, upstream_registry, namespace_pattern, provider_pattern, priority, is_active, requires_approval, created_at, updated_at, created_by)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.db.ExecContext(ctx, query,
		policy.ID, policy.OrganizationID, policy.Name, policy.Description,
		policy.PolicyType, policy.UpstreamRegistry, policy.NamespacePattern, policy.ProviderPattern,
		policy.Priority, policy.IsActive, policy.RequiresApproval,
		policy.CreatedAt, policy.UpdatedAt, policy.CreatedBy)
	return err
}

// GetMirrorPolicy retrieves a mirror policy by ID
func (r *RBACRepository) GetMirrorPolicy(ctx context.Context, id uuid.UUID) (*models.MirrorPolicy, error) {
	query := `SELECT id, organization_id, name, description, policy_type, upstream_registry, namespace_pattern, provider_pattern,
			  priority, is_active, requires_approval, created_at, updated_at, created_by
			  FROM mirror_policies WHERE id = $1`

	var policy models.MirrorPolicy
	err := r.db.QueryRowxContext(ctx, query, id).Scan(
		&policy.ID, &policy.OrganizationID, &policy.Name, &policy.Description,
		&policy.PolicyType, &policy.UpstreamRegistry, &policy.NamespacePattern, &policy.ProviderPattern,
		&policy.Priority, &policy.IsActive, &policy.RequiresApproval,
		&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &policy, err
}

// ListMirrorPolicies lists all mirror policies for an organization (including global policies)
func (r *RBACRepository) ListMirrorPolicies(ctx context.Context, orgID *uuid.UUID) ([]*models.MirrorPolicy, error) {
	query := `SELECT mp.id, mp.organization_id, mp.name, mp.description, mp.policy_type,
			  mp.upstream_registry, mp.namespace_pattern, mp.provider_pattern,
			  mp.priority, mp.is_active, mp.requires_approval, mp.created_at, mp.updated_at, mp.created_by,
			  COALESCE(o.name, 'Global') as organization_name,
			  COALESCE(u.name, '') as created_by_name
			  FROM mirror_policies mp
			  LEFT JOIN organizations o ON mp.organization_id = o.id
			  LEFT JOIN users u ON mp.created_by = u.id
			  WHERE mp.organization_id IS NULL`

	if orgID != nil {
		query += ` OR mp.organization_id = $1`
	}

	query += ` ORDER BY mp.priority DESC, mp.created_at`

	var rows *sqlx.Rows
	var err error
	if orgID != nil {
		rows, err = r.db.QueryxContext(ctx, query, *orgID)
	} else {
		rows, err = r.db.QueryxContext(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*models.MirrorPolicy
	for rows.Next() {
		var policy models.MirrorPolicy
		if err := rows.Scan(
			&policy.ID, &policy.OrganizationID, &policy.Name, &policy.Description,
			&policy.PolicyType, &policy.UpstreamRegistry, &policy.NamespacePattern, &policy.ProviderPattern,
			&policy.Priority, &policy.IsActive, &policy.RequiresApproval,
			&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy,
			&policy.OrganizationName, &policy.CreatedByName); err != nil {
			return nil, err
		}
		policies = append(policies, &policy)
	}

	return policies, rows.Err()
}

// UpdateMirrorPolicy updates an existing mirror policy
func (r *RBACRepository) UpdateMirrorPolicy(ctx context.Context, policy *models.MirrorPolicy) error {
	query := `UPDATE mirror_policies
			  SET name = $2, description = $3, policy_type = $4, upstream_registry = $5,
			      namespace_pattern = $6, provider_pattern = $7, priority = $8,
			      is_active = $9, requires_approval = $10, updated_at = $11
			  WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.PolicyType,
		policy.UpstreamRegistry, policy.NamespacePattern, policy.ProviderPattern,
		policy.Priority, policy.IsActive, policy.RequiresApproval, time.Now())
	return err
}

// DeleteMirrorPolicy deletes a mirror policy
func (r *RBACRepository) DeleteMirrorPolicy(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM mirror_policies WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// EvaluatePolicies evaluates all policies for a given provider and returns the result
func (r *RBACRepository) EvaluatePolicies(ctx context.Context, orgID *uuid.UUID, registry, namespace, provider string) (*models.PolicyEvaluationResult, error) {
	policies, err := r.ListMirrorPolicies(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Default: deny if no policies match
	result := &models.PolicyEvaluationResult{
		Allowed:          false,
		RequiresApproval: false,
		Reason:           "No matching policy found",
	}

	// Evaluate policies in priority order (highest first)
	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}

		if policy.Matches(registry, namespace, provider) {
			result.MatchedPolicy = policy
			result.RequiresApproval = policy.RequiresApproval

			if policy.PolicyType == models.PolicyTypeAllow {
				result.Allowed = true
				result.Reason = "Allowed by policy: " + policy.Name
			} else {
				result.Allowed = false
				result.Reason = "Denied by policy: " + policy.Name
			}
			return result, nil
		}
	}

	return result, nil
}

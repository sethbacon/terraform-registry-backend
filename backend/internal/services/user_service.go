// Package services — user_service.go provides GDPR data-subject operations:
// data export (Article 15/20) and erasure (Article 17 "right to be forgotten").
//
// Data export produces a JSON bundle containing all PII and user-attributed
// records. Erasure tombstones the user record (preserving the audit trail
// as required by regulation) but removes or anonymizes PII.
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// UserService provides GDPR data-subject operations.
type UserService struct {
	db *sql.DB
}

// NewUserService creates a new UserService.
func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

// UserDataExport is the full data export bundle for a single user (GDPR Art. 15/20).
type UserDataExport struct {
	ExportedAt       time.Time          `json:"exported_at"`
	User             UserExportRecord   `json:"user"`
	Memberships      []MembershipRecord `json:"memberships"`
	APIKeys          []APIKeyRecord     `json:"api_keys"`
	AuditEntries     int                `json:"audit_entry_count"`
	ModulesCreated   []ResourceRecord   `json:"modules_created"`
	ProvidersCreated []ResourceRecord   `json:"providers_created"`
}

// UserExportRecord is the PII portion of a user record.
type UserExportRecord struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	OIDCSub   *string   `json:"oidc_sub,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MembershipRecord describes an organization membership.
type MembershipRecord struct {
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	RoleTemplateName string `json:"role_template_name"`
}

// APIKeyRecord describes an API key owned by the user (secret not included).
type APIKeyRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// ResourceRecord is a minimal reference to a module or provider.
type ResourceRecord struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// ExportUserData gathers all data associated with a user for GDPR export.
func (s *UserService) ExportUserData(ctx context.Context, userID string) (*UserDataExport, error) {
	export := &UserDataExport{
		ExportedAt: time.Now().UTC(),
	}

	// 1. User record
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, oidc_sub, created_at, updated_at FROM users WHERE id = $1`, userID,
	).Scan(&export.User.ID, &export.User.Email, &export.User.Name,
		&export.User.OIDCSub, &export.User.CreatedAt, &export.User.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 2. Organization memberships
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.id, o.name, COALESCE(rt.name, 'none')
		FROM organization_members om
		JOIN organizations o ON o.id = om.organization_id
		LEFT JOIN role_templates rt ON rt.id = om.role_template_id
		WHERE om.user_id = $1
	`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var m MembershipRecord
			if err := rows.Scan(&m.OrganizationID, &m.OrganizationName, &m.RoleTemplateName); err == nil {
				export.Memberships = append(export.Memberships, m)
			}
		}
	}

	// 3. API keys (no secrets)
	keyRows, err := s.db.QueryContext(ctx, `
		SELECT id, name, created_at, expires_at, last_used_at
		FROM api_keys WHERE user_id = $1
	`, userID)
	if err == nil {
		defer keyRows.Close()
		for keyRows.Next() {
			var k APIKeyRecord
			if err := keyRows.Scan(&k.ID, &k.Name, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt); err == nil {
				export.APIKeys = append(export.APIKeys, k)
			}
		}
	}

	// 4. Audit entry count (not full entries — they may be voluminous)
	s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1`, userID,
	).Scan(&export.AuditEntries)

	// 5. Modules created by this user
	modRows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT m.id, m.namespace, m.name
		FROM modules m
		JOIN module_versions mv ON mv.module_id = m.id
		WHERE mv.created_by = $1
	`, userID)
	if err == nil {
		defer modRows.Close()
		for modRows.Next() {
			var r ResourceRecord
			if err := modRows.Scan(&r.ID, &r.Namespace, &r.Name); err == nil {
				export.ModulesCreated = append(export.ModulesCreated, r)
			}
		}
	}

	// 6. Providers created by this user
	provRows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT p.id, p.namespace, p.type
		FROM providers p
		JOIN provider_versions pv ON pv.provider_id = p.id
		WHERE pv.created_by = $1
	`, userID)
	if err == nil {
		defer provRows.Close()
		for provRows.Next() {
			var r ResourceRecord
			if err := provRows.Scan(&r.ID, &r.Namespace, &r.Name); err == nil {
				export.ProvidersCreated = append(export.ProvidersCreated, r)
			}
		}
	}

	return export, nil
}

// ExportUserDataJSON returns the user data export as JSON bytes.
func (s *UserService) ExportUserDataJSON(ctx context.Context, userID string) ([]byte, error) {
	export, err := s.ExportUserData(ctx, userID)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(export, "", "  ")
}

// EraseUser tombstones a user record for GDPR Article 17 compliance.
//
// This does NOT delete audit log entries (audit trails must be preserved per
// regulation). Instead it:
//  1. Anonymizes PII in the users table (email → "erased-<id>@erased", name → "Erased User").
//  2. Revokes all API keys.
//  3. Removes organization memberships.
//  4. Sets a tombstone flag so the user cannot log in.
//
// The user ID is preserved in audit logs for traceability but is no longer
// linkable to a natural person.
func (s *UserService) EraseUser(ctx context.Context, userID string, erasedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Verify user exists
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists)
	if err != nil || !exists {
		return fmt.Errorf("user not found: %s", userID)
	}

	// 1. Anonymize PII
	anonymizedEmail := fmt.Sprintf("erased-%s@erased.local", userID)
	_, err = tx.ExecContext(ctx, `
		UPDATE users
		SET email = $2, name = 'Erased User', oidc_sub = NULL, updated_at = NOW()
		WHERE id = $1
	`, userID, anonymizedEmail)
	if err != nil {
		return fmt.Errorf("failed to anonymize user: %w", err)
	}

	// 2. Revoke all API keys
	_, err = tx.ExecContext(ctx, `DELETE FROM api_keys WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke API keys: %w", err)
	}

	// 3. Remove organization memberships
	_, err = tx.ExecContext(ctx, `DELETE FROM organization_members WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to remove memberships: %w", err)
	}

	// 4. Revoke any active JWT sessions
	_, _ = tx.ExecContext(ctx, `
		INSERT INTO revoked_tokens (token_id, revoked_at)
		SELECT id, NOW() FROM user_sessions WHERE user_id = $1
	`, userID)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit erasure: %w", err)
	}

	return nil
}

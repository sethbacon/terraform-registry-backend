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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// UserService provides GDPR data-subject operations.
type UserService struct {
	db *sql.DB
	// creds invalidates the credential families that survive an erasure. May
	// be nil, in which case the sweep is skipped.
	creds *credlifecycle.Sweeper
	// floor holds the never-zero administrator invariants across an erasure
	// (issue #766), and carrier retires the erased principal's platform_admins
	// row. May be nil, in which case both are skipped.
	floor   *adminfloor.Guard
	carrier *repositories.PlatformAdminRepository
	// outbox carries the audit intent for that retirement INTO the deleting
	// transaction. Mandatory once carrier is set: migration 000052's constraint
	// trigger refuses the commit without a matching intent, so a nil outbox
	// makes the cleanup fail rather than silently skip -- see
	// revokePlatformAdminCarrier.
	outbox *audit.Outbox
}

// NewUserService creates a new UserService.
func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

// WithCredentialSweeper wires the credential sweeper used by EraseUser.
// Returns the service for chaining.
func (s *UserService) WithCredentialSweeper(sweeper *credlifecycle.Sweeper) *UserService {
	s.creds = sweeper
	return s
}

// WithAdminFloor wires the never-zero administrator guard, the platform-admin
// carrier, and the audit outbox that carrier writes through (issue #766).
// Returns the service for chaining.
//
// One option rather than three: the floor's read of the carrier, the row the
// erasure retires, and the intent that retirement must commit with are the same
// fact seen three ways, and a deployment that wired one without the others
// would either count a grant it was about to strand or fail its commit.
func (s *UserService) WithAdminFloor(floor *adminfloor.Guard, carrier *repositories.PlatformAdminRepository, outbox *audit.Outbox) *UserService {
	s.floor = floor
	s.carrier = carrier
	s.outbox = outbox
	return s
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
	_ = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1`, userID,
	).Scan(&export.AuditEntries)

	// 5. Modules created by this user
	modRows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT m.id, m.namespace, m.name
		FROM modules m
		JOIN module_versions mv ON mv.module_id = m.id
		WHERE mv.published_by = $1
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
		WHERE pv.published_by = $1
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

// eraseTx is the erasure itself: the three statements that used to be
// EraseUser's body, unchanged, lifted into their own method so the whole
// transaction can be the write the floor protects.
func (s *UserService) eraseTx(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit erasure: %w", err)
	}
	return nil
}

// revokePlatformAdminCarrier retires an erased principal's platform_admins row
// (issue #766). Best-effort and logged; the erasure has already committed and
// answering an error would invite a retry that then reports "user not found".
//
// The last-standing predicate is nil deliberately: the floor has already
// cleared this erasure, and re-checking here would refuse to remove the very
// grant it just discounted.
//
// The AUDIT INTENT is not optional in the same way. Migration 000052's deferred
// constraint trigger refuses any commit that deletes a carrier row without a
// matching intent in the same transaction, so this cleanup carries one — with
// the action the trigger pins and metadata saying why the grant went, which is
// the difference between "an administrator was revoked" and "an administrator
// was erased" in the trail. A nil outbox therefore cannot be skipped past: the
// DELETE would abort at COMMIT anyway, and saying so here is clearer than
// letting Postgres say it.
func (s *UserService) revokePlatformAdminCarrier(ctx context.Context, userID, erasedBy string) {
	if s.carrier == nil {
		return
	}
	resourceType := repositories.AuditResourcePlatformAdmin
	target := userID
	intent := &audit.Intent{
		Action:       repositories.AuditActionPlatformAdminRevoked,
		ResourceType: &resourceType,
		ResourceID:   &target,
		Metadata: map[string]interface{}{
			"target_user_id": userID,
			"reason":         "gdpr erasure",
		},
	}
	if erasedBy != "" && erasedBy != "system" {
		actor := erasedBy
		intent.ActorUserID = &actor
	}

	_, err := s.carrier.Revoke(ctx, userID, nil, func(ctx context.Context, tx *sql.Tx) error {
		return s.outbox.Enqueue(ctx, tx, intent)
	})
	if err == nil {
		slog.Info("removed the platform-admin grant of an erased principal", "user_id", userID)
		return
	}
	if errors.Is(err, repositories.ErrNotPlatformAdmin) {
		return
	}
	slog.Error("failed to remove an erased principal's platform-admin grant; it survives and still resolves to a users row",
		"user_id", userID, "error", err)
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
// GUARD admin-floor (issue #766). The erasure is run inside the floor's lock,
// with the whole transaction as the protected write.
//
// An erasure is the most complete authority reduction the product has and the
// least obvious one: step 3 is an UNSCOPED `DELETE FROM organization_members`,
// so it strips the subject's administrative role in every organization on the
// platform at once, and step 1 NULLs oidc_sub so they can never log in again.
// Neither statement mentions a role or an administrator, which is why nothing
// noticed that erasing the deployment's only administrator was a supported
// operation.
//
// DestroysPrincipal, even though the users row survives: what the floor counts
// is an administrator who can still EXERCISE the grant, and an anonymised row
// with no oidc_sub cannot authenticate. Counting it would leave the deployment
// with an administrator nobody can log in as, which is the lockout with extra
// steps.
func (s *UserService) EraseUser(ctx context.Context, userID string, erasedBy string) error {
	if err := s.floor.Protect(ctx, adminfloor.Change{
		UserID:            userID,
		RemovesMembership: true,
		DestroysPrincipal: true,
	}, func(ctx context.Context) error { return s.eraseTx(ctx, userID) }); err != nil {
		return err
	}

	// The carrier row the erasure cannot reach: platform_admins is on the
	// registry's connection, the transaction above runs on identity's, and
	// migration 000051 declines the foreign key that would retire it. Left
	// behind it names a principal who can no longer authenticate but still
	// resolves to a users row, so — unlike a deleted user's orphan — nothing
	// downstream can tell it is inert. Best-effort, after the commit.
	s.revokePlatformAdminCarrier(ctx, userID, erasedBy)

	// 4. Revoke any active JWT sessions.
	//
	// This step used to be an in-transaction
	//
	//	INSERT INTO revoked_tokens (token_id, revoked_at)
	//	SELECT id, NOW() FROM user_sessions WHERE user_id = $1
	//
	// with its error deliberately discarded (`_, _ =`). There is no
	// user_sessions table anywhere in this repository's migrations or in the
	// shared identity schema, and the registry does not keep server-side
	// sessions at all -- a JWT is self-contained and is stopped only by a JTI
	// denylist hit or by the per-user revoke-all watermark. So the statement
	// always errored, the error was swallowed, and the erasure revoked
	// nothing: an "erased" user's outstanding sessions kept working, carrying
	// the scope union they had at login, until the token expired. It also made
	// the erasure LOOK swept to any reviewer (and to the enumeration
	// signature) because the SQL text mentions revoked_tokens.
	//
	// The real mechanism is the watermark, which lives on a different
	// connection from this transaction and so cannot be part of it. Running it
	// after the commit keeps the erasure atomic and reports the sweep result
	// separately.
	if s.creds != nil {
		// Platform-wide: an erasure that left the subject's credentials working
		// in some organization would not be an erasure. The transaction above
		// has already deleted every membership row unconditionally, so there is
		// no narrower scope this could honestly carry.
		if out := s.creds.UserDeprovisioned(ctx, userID,
			repositories.OrgScopeAllOrganizations(), "gdpr erasure"); out.Incomplete {
			slog.Error("credential sweep incomplete after GDPR erasure; the user's sessions may still be live",
				"user_id", userID, "erased_by", erasedBy)
			return fmt.Errorf("user data erased but credential revocation was incomplete for %s", userID)
		}
	}

	return nil
}

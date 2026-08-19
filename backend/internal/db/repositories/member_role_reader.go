// member_role_reader.go READS registry's own per-app authorization tables --
// `registry_role_templates` and `organization_member_roles`, migration 000055.
//
// Design: sethbacon/terraform-suite-identity#206. Phase 3a created these tables
// and dual-wrote them while every authorization decision still came from
// `organization_members.role_template_id` joined to `role_templates`. THIS FILE
// IS THE OTHER HALF: from here on, "which role does this member hold in
// registry, and what does it confer" is answered by registry's own tables.
//
// It is the mirror image of member_role_mirror.go, which exposes no reads for
// exactly the reason this type exists separately: a read method on the writer
// would have been the first step of the cutover, and the cutover had to be its
// own reviewable change. Keeping the two types apart also keeps the guard in
// member_role_read_class_test.go able to say which methods read the mirror.
//
// # What still does NOT come from here
//
// The membership FACT. `organization_members` remains the answer to "is this
// principal a member of this organization at all", and it stays there until
// phase 4. Every accessor in organization_repository.go therefore asks the
// shared identity store first -- which also supplies the user and organization
// columns the display shapes carry -- and overlays only the ROLE from here. A
// mirrored row whose membership no longer exists confers nothing, because
// nothing asks this file about a principal the store did not already return.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// roleRowScanner is the one method *sql.Row and *sql.Rows share, so the scan
// helpers below serve both the single-row and the multi-row reads.
type roleRowScanner interface {
	Scan(dest ...any) error
}

// MirroredRole is what registry's own tables say about one membership: the role
// template it holds, and what that template confers.
//
// A membership with a row but no role is represented by a non-nil MirroredRole
// whose RoleTemplateID is nil -- NOT by a nil MirroredRole. The distinction is
// the same one migration 000055 preserved in the schema: "this member holds no
// role here" and "this member has no row here" are different facts, and only
// the second one is drift.
type MirroredRole struct {
	// RoleTemplateID is the template the membership holds, or nil for none.
	RoleTemplateID *string
	// Name / DisplayName are the template's, empty when RoleTemplateID is nil.
	Name        string
	DisplayName string
	// Scopes is what the template confers. Always non-nil; empty for no role,
	// which is the fail-closed value -- an empty scope set denies everything.
	Scopes []string
}

// namePtr returns Name as the *string the shared models carry, nil when there
// is no role. The models use a pointer because the source columns are
// nullable; this keeps a role-less membership serialising as `null` exactly as
// it did when the value came from a LEFT JOIN that matched nothing.
func (r *MirroredRole) namePtr() *string {
	if r == nil || r.RoleTemplateID == nil {
		return nil
	}
	n := r.Name
	return &n
}

// displayNamePtr is namePtr for the display name.
func (r *MirroredRole) displayNamePtr() *string {
	if r == nil || r.RoleTemplateID == nil {
		return nil
	}
	d := r.DisplayName
	return &d
}

// id returns the role template id, or nil for a nil receiver.
func (r *MirroredRole) id() *string {
	if r == nil {
		return nil
	}
	return r.RoleTemplateID
}

// scopes returns the conferred scopes, or an empty set for a nil receiver.
//
// A nil receiver means "registry has no row for this membership", and the
// fail-closed reading of that is no authority at all. Returning nil scopes
// rather than erroring is safe HERE only because the callers that matter treat
// an empty scope set as a denial; the error path is in the accessors, which do
// not construct a nil MirroredRole from a failed query -- they return the
// error. See organization_repository.go.
func (r *MirroredRole) scopes() []string {
	if r == nil || r.Scopes == nil {
		return []string{}
	}
	return r.Scopes
}

// noRole is the value every accessor uses for "registry has no row here". It is
// a package-level function rather than a nil literal so the fail-closed choice
// has one name and one place to read about it.
func noRole() *MirroredRole { return nil }

// MemberRoleReader reads registry's own authorization tables.
//
// It is built on the connection the caller resolves `organization_members`
// through. In the default topology that is registry's only connection; under
// TFR_IDENTITY_SCHEMA_ENABLED it is the identity pool, whose
// `search_path=<identity>,public` resolves these two tables through the
// trailing `,public`. The one topology where that is false -- identity in a
// SEPARATE DATABASE -- is refused at boot rather than served from a table the
// connection cannot see (internal/api/router.go).
type MemberRoleReader struct {
	db *sql.DB
}

// NewMemberRoleReader builds a reader over the given connection.
func NewMemberRoleReader(db *sql.DB) *MemberRoleReader {
	return &MemberRoleReader{db: db}
}

// mirroredRoleColumns is the one projection every membership read below
// selects, so a schema change edits one literal rather than three.
//
// LEFT JOIN, and COALESCE on the template columns: a mirrored row with a NULL
// role_template_id is a legitimate "no role here", and it must come back as a
// row rather than vanish -- otherwise it is indistinguishable from "no mirrored
// row", which is the one difference the drift check exists to see.
const mirroredRoleColumns = `omr.role_template_id,
		       COALESCE(rrt.name, ''), COALESCE(rrt.display_name, ''),
		       COALESCE(rrt.scopes, '[]'::jsonb)`

// mirroredRoleFrom is the canonical FROM/JOIN chain for a membership read.
const mirroredRoleFrom = `
		FROM organization_member_roles omr
		LEFT JOIN registry_role_templates rrt ON rrt.id = omr.role_template_id`

// scanMirroredRole scans one mirroredRoleColumns row.
func scanMirroredRole(row roleRowScanner, leading ...any) (*MirroredRole, error) {
	var role MirroredRole
	var scopesJSON []byte
	dest := make([]any, 0, len(leading)+4)
	dest = append(dest, leading...)
	dest = append(dest, &role.RoleTemplateID, &role.Name, &role.DisplayName, &scopesJSON)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &role.Scopes); err != nil {
		return nil, fmt.Errorf("parse mirrored role scopes: %w", err)
	}
	if role.Scopes == nil {
		role.Scopes = []string{}
	}
	return &role, nil
}

// RoleFor returns the role registry's own tables record for one membership, or
// nil when there is no mirrored row for it.
//
// nil is NOT an error. It is the drift the divergence signal reports and the
// drift check gates on, and it fails closed at every call site: a nil role
// yields no scopes.
func (r *MemberRoleReader) RoleFor(ctx context.Context, orgID, userID string) (*MirroredRole, error) {
	role, err := scanMirroredRole(r.db.QueryRowContext(ctx,
		`SELECT `+mirroredRoleColumns+mirroredRoleFrom+`
		 WHERE omr.organization_id = $1 AND omr.user_id = $2`, orgID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return noRole(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read registry role for (%s, %s): %w", orgID, userID, err)
	}
	return role, nil
}

// RolesForUser returns every organization in which registry records a role for
// this user, keyed by organization id.
//
// One query for the whole set rather than RoleFor per membership: the
// user-axis accessors resolve a principal's authority across every
// organization they belong to and run on the login path, where an N+1 would be
// a per-organization round trip on every token mint.
func (r *MemberRoleReader) RolesForUser(ctx context.Context, userID string) (map[string]*MirroredRole, error) {
	return r.rolesKeyedBy(ctx,
		`SELECT omr.organization_id, `+mirroredRoleColumns+mirroredRoleFrom+`
		 WHERE omr.user_id = $1`, userID)
}

// RolesForOrg returns every user for whom registry records a role in this
// organization, keyed by user id.
func (r *MemberRoleReader) RolesForOrg(ctx context.Context, orgID string) (map[string]*MirroredRole, error) {
	return r.rolesKeyedBy(ctx,
		`SELECT omr.user_id, `+mirroredRoleColumns+mirroredRoleFrom+`
		 WHERE omr.organization_id = $1`, orgID)
}

// RolesForUsers is the bulk form of RolesForUser: user id -> organization id ->
// role.
//
// It exists because the shared store's user-list accessors deliberately load
// memberships for a whole page in ONE query rather than N, and an overlay that
// then issued one read per user would reintroduce exactly the N+1 they avoid --
// on the admin user list, the page with the most rows.
//
// An empty userIDs returns an empty map without a round trip: `= ANY('{}')`
// matches nothing, and asking the database to confirm that on every empty page
// is a query whose answer is already known.
func (r *MemberRoleReader) RolesForUsers(ctx context.Context, userIDs []string) (map[string]map[string]*MirroredRole, error) {
	out := map[string]map[string]*MirroredRole{}
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT omr.user_id, omr.organization_id, `+mirroredRoleColumns+mirroredRoleFrom+`
		 WHERE omr.user_id = ANY($1)`, userIDs)
	if err != nil {
		return nil, fmt.Errorf("read registry roles for %d user(s): %w", len(userIDs), err)
	}
	defer rows.Close()

	for rows.Next() {
		var userID, orgID string
		role, scanErr := scanMirroredRole(rows, &userID, &orgID)
		if scanErr != nil {
			return nil, fmt.Errorf("scan registry role: %w", scanErr)
		}
		if out[userID] == nil {
			out[userID] = map[string]*MirroredRole{}
		}
		out[userID][orgID] = role
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read registry roles for %d user(s): %w", len(userIDs), err)
	}
	return out, nil
}

// rolesKeyedBy runs a membership read whose first column is the map key.
func (r *MemberRoleReader) rolesKeyedBy(ctx context.Context, query, arg string) (map[string]*MirroredRole, error) {
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, fmt.Errorf("read registry roles: %w", err)
	}
	defer rows.Close()

	out := map[string]*MirroredRole{}
	for rows.Next() {
		var key string
		role, scanErr := scanMirroredRole(rows, &key)
		if scanErr != nil {
			return nil, fmt.Errorf("scan registry role: %w", scanErr)
		}
		out[key] = role
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read registry roles: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Role templates
// ---------------------------------------------------------------------------

// registryRoleTemplateColumns is the projection for a whole template row.
const registryRoleTemplateColumns = `id, name, display_name, description, scopes, is_system, created_at, updated_at`

// scanRegistryRoleTemplate scans one registryRoleTemplateColumns row.
func scanRegistryRoleTemplate(row roleRowScanner) (*models.RoleTemplate, error) {
	var t models.RoleTemplate
	var scopesJSON []byte
	if err := row.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description,
		&scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return nil, fmt.Errorf("parse role template scopes: %w", err)
	}
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	return &t, nil
}

// ListRoleTemplates returns registry's own role templates.
func (r *MemberRoleReader) ListRoleTemplates(ctx context.Context) ([]*models.RoleTemplate, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+registryRoleTemplateColumns+` FROM registry_role_templates ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list registry role templates: %w", err)
	}
	defer rows.Close()

	out := make([]*models.RoleTemplate, 0)
	for rows.Next() {
		t, scanErr := scanRegistryRoleTemplate(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan registry role template: %w", scanErr)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list registry role templates: %w", err)
	}
	return out, nil
}

// GetRoleTemplate returns one of registry's own role templates by id.
//
// It returns identitystore's ErrNotFound sentinel for a missing row, matching
// what the shared store's RoleTemplateRepository returned from this call
// before the cutover: the handlers map that sentinel onto 404, and answering a
// different error here would turn "no such template" into a 500.
func (r *MemberRoleReader) GetRoleTemplate(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	return r.roleTemplateWhere(ctx, `id = $1`, id, "role template")
}

// GetRoleTemplateByName returns one of registry's own role templates by name.
func (r *MemberRoleReader) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	return r.roleTemplateWhere(ctx, `name = $1`, name, "role template by name")
}

// roleTemplateWhere is the shared single-template read.
func (r *MemberRoleReader) roleTemplateWhere(ctx context.Context, predicate string, arg any, what string) (*models.RoleTemplate, error) {
	t, err := scanRegistryRoleTemplate(r.db.QueryRowContext(ctx,
		`SELECT `+registryRoleTemplateColumns+` FROM registry_role_templates WHERE `+predicate, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s not found: %w", what, identitystore.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get registry %s: %w", what, err)
	}
	return t, nil
}

// MembershipsWithTemplate returns the (user, organization) pairs that hold the
// given template in REGISTRY.
//
// This is the credential-invalidation sweep's input: when a template's scopes
// change or it is deleted, these are the principals whose JWTs and API keys
// snapshotted the old authority. It reads registry's own assignment table
// because that is now what conferred the authority being withdrawn -- sweeping
// the identity table's holders would revoke the wrong set the moment the two
// disagree, which is precisely the state the drift check exists to detect.
func (r *MemberRoleReader) MembershipsWithTemplate(ctx context.Context, roleTemplateID uuid.UUID) ([]RoleTemplateMembership, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT DISTINCT user_id, organization_id FROM organization_member_roles WHERE role_template_id = $1`,
		roleTemplateID)
	if err != nil {
		return nil, fmt.Errorf("list registry memberships holding %s: %w", roleTemplateID, err)
	}
	defer rows.Close()

	var out []RoleTemplateMembership
	for rows.Next() {
		var m RoleTemplateMembership
		if err := rows.Scan(&m.UserID, &m.OrganizationID); err != nil {
			return nil, fmt.Errorf("scan registry membership: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list registry memberships holding %s: %w", roleTemplateID, err)
	}
	return out, nil
}

package admin

import (
	"os"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestMain(m *testing.M) {
	// Set JWT secret for tests that exercise GenerateJWT (e.g., RefreshHandler success path)
	os.Setenv("TFR_JWT_SECRET", "test-admin-jwt-secret-that-is-32chars!!")
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// registry's own role tables (sethbacon/terraform-suite-identity#206, phase 3b)
// ---------------------------------------------------------------------------
//
// Why these helpers exist: the role-bearing reads on repositories'
// OrganizationRepository and UserRepository no longer answer from the identity
// tables alone. Each one still asks the shared identity store first -- that is
// what supplies the membership FACT and the user/organization columns, and it
// is the query these fixtures already seed -- and then issues ONE ADDITIONAL
// query, on the SAME connection and IMMEDIATELY AFTER, against registry's own
// `organization_member_roles` joined to `registry_role_templates`. The role and
// the scopes it returns are what the accessor reports.
//
// So every fixture that drives one of those accessors needs one of the three
// expectations below queued directly after the identity row it already seeds.
//
// A FOURTH shape exists in the production code and has no helper here: the bulk
// per-page read (MemberRoleReader.RolesForUsers, `WHERE omr.user_id = ANY($1)`)
// that UserRepository's ListUsersWithMemberships and SearchWithMemberships
// issue. Every user-list fixture in this package returns users with NO
// memberships, and the overlay skips the read entirely in that case, so nothing
// here drives it. A fixture that gives a listed user a membership will need it.
//
// The row must repeat the SAME role template id and the SAME scopes as that
// identity row, because the production code compares the two: when they differ
// it logs an ERROR and increments registry_role_read_divergence_total. A
// fixture that let them drift would still pass, while quietly exercising the
// disagreement path instead of the behaviour the test was written for.

// registryRole is one membership's row in registry's own tables.
//
// A membership that holds NO role template is `registryRole{}` (or one with a
// nil id): a row that exists and confers nothing. That is different from
// queueing no row at all, which is the missing-mirror divergence.
type registryRole struct {
	// orgID and userID identify the membership. Each read below projects only
	// the one(s) it keys its result by, so a fixture need only set the field(s)
	// that read looks at.
	orgID  string
	userID string

	// id is the role template held: a string, or nil for none. Repeat whatever
	// the identity fixture seeded into organization_members.role_template_id.
	id any

	// name, displayName and scopes are the template's. The display shapes carry
	// all three, so repeat whatever the identity fixture seeded there too;
	// scopes is a JSON array literal and defaults to the empty set.
	name        string
	displayName string
	scopes      string
}

// scopesJSON is the scopes column as the reader parses it, defaulting to the
// empty array so that the zero registryRole is the "holds no role" row rather
// than a JSON parse error.
func (r registryRole) scopesJSON() []byte {
	if r.scopes == "" {
		return []byte(`[]`)
	}
	return []byte(r.scopes)
}

// registryRoleCols are the four columns every one of these reads projects after
// its leading key column(s).
var registryRoleCols = []string{"role_template_id", "name", "display_name", "scopes"}

// expectRegistryRoleFor queues the single-membership read (MemberRoleReader
// .RoleFor), issued by GetMember, CheckMembership, GetMemberWithRole and
// GetUserScopesForOrg.
func expectRegistryRoleFor(mock sqlmock.Sqlmock, role registryRole) {
	mock.ExpectQuery(`SELECT omr\.role_template_id,`).
		WillReturnRows(sqlmock.NewRows(registryRoleCols).
			AddRow(role.id, role.name, role.displayName, role.scopesJSON()))
}

// expectRegistryRolesForOrg queues the per-organization read (RolesForOrg),
// keyed by user id, issued by ListMembers and ListMembersWithUsers. Both skip
// it entirely when the store returned no members.
func expectRegistryRolesForOrg(mock sqlmock.Sqlmock, roles ...registryRole) {
	rows := sqlmock.NewRows(append([]string{"user_id"}, registryRoleCols...))
	for _, role := range roles {
		rows.AddRow(role.userID, role.id, role.name, role.displayName, role.scopesJSON())
	}
	mock.ExpectQuery(`SELECT omr\.user_id, omr\.role_template_id`).WillReturnRows(rows)
}

// expectRegistryRolesForUser queues the per-user read (RolesForUser), keyed by
// organization id, issued by GetUserMemberships -- and so also by
// GetUserCombinedScopes, OrgScopeForUser and GetUserWithOrgRoles, which are
// built on it. All of them skip it when the store returned no memberships.
func expectRegistryRolesForUser(mock sqlmock.Sqlmock, roles ...registryRole) {
	rows := sqlmock.NewRows(append([]string{"organization_id"}, registryRoleCols...))
	for _, role := range roles {
		rows.AddRow(role.orgID, role.id, role.name, role.displayName, role.scopesJSON())
	}
	mock.ExpectQuery(`SELECT omr\.organization_id, omr\.role_template_id`).WillReturnRows(rows)
}

package admin

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #766 — the platform-wide `admin` role template is assignable as an
// organization membership role.
//
// IT IS NOT, ANY MORE, AND THAT IS WHAT THIS FILE NOW ASSERTS.
//
// PR #850 wrote the strongest property reachable at the time:
//
//	an admin-bearing role template becomes a membership role only where a
//	principal that already holds platform-admin authority put it there.
//
// It declined #766's headline recommendation — reject admin-bearing templates
// on the member API — and was right to: `organization_members.role_template_id`
// was then the ONLY carrier for scopes, so the refusal would have left a
// deployment unable to have a platform administrator at all.
//
// `platform_admins` is that carrier now (migration 000051), the management API
// grants through it (PR #862), the setup wizard bootstraps through it, and
// migration 000054 has taken `admin` off the role templates. So the property
// flips to the one the issue asked for:
//
//	an admin-bearing role template cannot become a membership role AT ALL.
//
// Two consequences visible below. The behavioural half now asserts the refusal
// for a PLATFORM ADMINISTRATOR as well as for an organization owner — the
// caller PR #850 deliberately permitted, and the only one who could ever have
// created the state it tolerated. And `bootstrapExemptions` loses its
// `ConfigureAdmin` entry, because the setup wizard writes the carrier and no
// membership at all; the list is checked in both directions, so that entry
// could not simply be left behind.

// ---------------------------------------------------------------------------
// Behavioural half: the routes #719 exempted
// ---------------------------------------------------------------------------

// newOrgScopedMemberRouter wires the two member-write routes with a principal
// that is an organization owner in org-1 and nothing more.
func newOrgScopedMemberRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newMemberRouterAs(t, "org-owner-1", []string{string(auth.ScopeOrganizationsWrite)})
}

// newPlatformAdminMemberRouter wires the same two routes with the principal PR
// #850 deliberately allowed through: a platform administrator, holding the
// wildcard the carrier now confers.
func newPlatformAdminMemberRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newMemberRouterAs(t, "platform-admin-1", []string{string(auth.ScopeAdmin)})
}

func newMemberRouterAs(t *testing.T, userID string, scopes []string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewOrganizationHandlers(&config.Config{}, db, repositories.NewNamespaceClaimRepository(db), nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("auth_method", "jwt")
		// The flat, org-less union a session JWT carries (#652).
		c.Set("scopes", scopes)
	})
	r.POST("/organizations/:id/members", h.AddMemberHandler())
	r.PUT("/organizations/:id/members/:user_id", h.UpdateMemberHandler())
	return mock, r
}

// expectRoleTemplateLookup queues the ONE read a refusal costs: the target
// template's scopes. The per-organization ceiling lookup that used to follow it
// is deliberately not queued — the refusal happens before it, and sqlmock's
// ordered mode makes an unconsumed expectation a failure, so queueing it would
// assert the opposite of the property.
func expectRoleTemplateLookup(mock sqlmock.Sqlmock, roleScopesJSON string) {
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(roleScopesJSON)))
}

// expectOrgOwnerCeilingLookups queues both reads checkRoleAssignment makes for
// a non-platform-admin caller assigning a template it does NOT refuse outright:
// the target template's scopes, then the caller's own role IN THE TARGET ORG.
func expectOrgOwnerCeilingLookups(mock sqlmock.Sqlmock, roleScopesJSON string) {
	expectRoleTemplateLookup(mock, roleScopesJSON)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).AddRow(
			"org-1", "org-owner-1", "role-owner", time.Now(),
			"Owner One", "owner@example.com", "org_owner", "Organization Owner",
			// migration 000049's org_owner scope set: everything an
			// organization needs, and no wildcard.
			[]byte(`["organizations:write","users:read","api_keys:manage","modules:read","modules:write","providers:read","providers:write","mirrors:read","mirrors:manage","scm:read","scm:manage"]`),
		))
}

const adminBearingRoleUUID = "44444444-4444-4444-4444-444444444444"

// memberWriteRoutes are the two routes #719 exempted from tenant scoping on the
// grounds that ScopeAdmin is platform-wide by intent.
var memberWriteRoutes = []struct {
	name   string
	method string
	path   string
}{
	{"add member", http.MethodPost, "/organizations/org-1/members"},
	{"update member", http.MethodPut, "/organizations/org-1/members/target-1"},
}

// TestPlatformAdminGrantClass_NobodyCanGrantAnAdminBearingTemplate is #766's
// recommendation, asserted at the routes rather than at checkRoleAssignment.
//
// BOTH principals are refused, and the platform administrator is the case that
// changed: under PR #850 that caller was allowed, because they already held the
// authority they were handing out and `organization_members` was the only place
// to put it. It is now refused everywhere, so the state PR #850 tolerated
// cannot arise at all.
//
// sqlmock is in its default ordered mode with no INSERT/UPDATE queued, so a
// regression that dropped the refusal would not merely return the wrong status,
// it would attempt an unexpected write and fail here on that too. The body is
// asserted on the exact sentence the handler returns, because a 403 from the
// per-org ceiling and a 403 from this refusal are different properties and only
// one of them holds for a platform administrator.
func TestPlatformAdminGrantClass_NobodyCanGrantAnAdminBearingTemplate(t *testing.T) {
	callers := []struct {
		name  string
		build func(*testing.T) (sqlmock.Sqlmock, *gin.Engine)
	}{
		{"organization owner", newOrgScopedMemberRouter},
		{"platform administrator", newPlatformAdminMemberRouter},
	}

	for _, caller := range callers {
		for _, rt := range memberWriteRoutes {
			t.Run(caller.name+"/"+rt.name, func(t *testing.T) {
				mock, r := caller.build(t)
				expectRoleTemplateLookup(mock, `["admin"]`)

				body := `{"user_id":"target-1","role_template_id":"` + adminBearingRoleUUID + `"}`
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, bytes.NewBufferString(body)))

				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 — an admin-bearing template must not become a "+
						"membership role for anybody (#766): body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "platform-admin role cannot be assigned") {
					t.Errorf("body = %s, want the admin-bearing refusal naming "+
						"POST /api/v1/admin/platform-admins — a 403 from the per-org ceiling is a "+
						"different property and does not hold for a platform administrator",
						w.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("unmet/unexpected expectations (no membership write, and no per-org "+
						"ceiling lookup, may be attempted): %v", err)
				}
			})
		}
	}
}

// TestPlatformAdminGrantClass_OrgScopedCallerCanStillGrantWithinItsAuthority is
// the positive control for the test above. Without it, a change that rejected
// every role assignment outright would satisfy the negative case and look like
// a fix.
//
// The role assigned here is one the org owner holds itself, so the refusal does
// not apply, the ceiling permits it, and the handler proceeds to the membership
// write. It also proves the per-org ceiling is still REACHED — the refusal was
// added ahead of it, and a refusal that swallowed every path would leave #648
// and #733 unguarded.
func TestPlatformAdminGrantClass_OrgScopedCallerCanStillGrantWithinItsAuthority(t *testing.T) {
	mock, r := newOrgScopedMemberRouter(t)
	expectOrgOwnerCeilingLookups(mock, `["modules:write"]`)
	// Organization exists, target is not yet a member, then the insert.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_config_id", "created_at", "updated_at"}).
			AddRow("org-1", "acme", "Acme", nil, nil, time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}))
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).AddRow(
			"org-1", "target-1", "role-pub", time.Now(),
			"Target One", "target@example.com", "publisher", "Publisher",
			[]byte(`["modules:write"]`),
		))

	body := `{"user_id":"target-1","role_template_id":"55555555-5555-5555-5555-555555555555"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/organizations/org-1/members", bytes.NewBufferString(body)))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 — a role within the caller's own authority must "+
			"still be assignable: body=%s", w.Code, w.Body.String())
	}
}

// TestPlatformAdminGrantClass_OrgScopedCallerStillRefusedAboveItsCeiling keeps
// the OTHER refusal honest. The admin-bearing check runs first, so a template
// that merely exceeds the caller's authority — without carrying the wildcard —
// must still be refused by the per-org ceiling (#648, #733).
func TestPlatformAdminGrantClass_OrgScopedCallerStillRefusedAboveItsCeiling(t *testing.T) {
	mock, r := newOrgScopedMemberRouter(t)
	// users:write is not in the org_owner scope set queued below.
	expectOrgOwnerCeilingLookups(mock, `["users:write"]`)

	body := `{"user_id":"target-1","role_template_id":"66666666-6666-6666-6666-666666666666"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/organizations/org-1/members", bytes.NewBufferString(body)))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from the per-org ceiling: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the per-org ceiling lookup was not made — the admin-bearing refusal is short-circuiting "+
			"paths it has no business deciding: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Structural half: every membership write in the tree, not just auth.go
// ---------------------------------------------------------------------------

// ceilingGuardNames are the accepted ways a membership write can have proven
// that the role it is about to write may be written at all. Every one of them
// now applies the SAME refusal — auth.ValidateProvisionableScopes, which denies
// `admin` to every caller — on top of whatever else it does:
//
//   - checkRoleAssignment — the human-driven guard (role_ceiling.go). Refuses
//     any admin-bearing template outright, ahead of the per-org ceiling it
//     still applies to everything else (#648, #733).
//   - guardProvisionableRole / resolveProvisionableRole — the IdP-driven guard
//     (group_mapping_guard.go), which has refused admin-bearing templates to
//     every caller since #604/#815.
var ceilingGuardNames = map[string]bool{
	"checkRoleAssignment":      true,
	"guardProvisionableRole":   true,
	"resolveProvisionableRole": true,
}

// bootstrapExemptions are membership writes that deliberately proceed with no
// caller authority to check, keyed by "<path>:<function>". Being a map rather
// than a prefix rule is the point: a new unguarded write cannot join the
// exemption by living in a plausible-looking file, someone has to name it here.
//
// Checked in BOTH directions — an entry naming a site that no longer exists
// fails the test too, so the list cannot rot into names nobody has re-examined.
//
// `internal/api/setup/handlers.go:ConfigureAdmin` USED TO BE HERE, and its
// removal is the point of PR 3 rather than an incidental tidy-up. It was the
// one write that deliberately put the platform-wide template on a membership,
// and it was unremovable while `organization_members` was the only carrier for
// the wildcard. The wizard now grants through `platform_admins` and writes no
// membership at all, so the site is gone — and the bidirectional check below is
// what forced this entry to go with it.
var bootstrapExemptions = map[string]string{
	"internal/api/admin/organizations.go:CreateOrganizationHandler": "Auto-adds the creating user as " +
		"org_owner in the organization they just created (#648). The template is a fixed literal with " +
		"no wildcard scope, not caller-supplied, so there is nothing for a ceiling to constrain.",
}

// membershipWriteSite is one call to a membership-write repository method.
type membershipWriteSite struct {
	path string // repo-relative, slash-separated
	fn   string // enclosing top-level function or method name
	pos  token.Position
}

// backendRoot walks up from the test's working directory to the directory
// holding go.mod, so the scan covers the whole module however it is invoked.
func backendRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs cwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}

// findMembershipWriteSites parses every non-test .go file under the module and
// returns each membership-write call with the function that contains it, plus
// the set of "path:fn" keys whose write is preceded by a ceiling guard.
func findMembershipWriteSites(t *testing.T, root string) (sites []membershipWriteSite, guarded map[string]bool) {
	t.Helper()
	guarded = map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// vendor/ and testdata/ are not this module's enforcement surface.
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			t.Fatalf("rel %s: %v", path, relErr)
		}
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !membershipWriteMethods[callName(call)] {
					return true
				}
				key := rel + ":" + fn.Name.Name
				sites = append(sites, membershipWriteSite{path: rel, fn: fn.Name.Name, pos: fset.Position(call.Pos())})
				// Whole-function granularity, deliberately coarser than
				// idp_membership_guard_class_test.go's path-aware walk: that
				// one has to distinguish sibling branches inside a single
				// reconciliation function, whereas these handlers guard once
				// at the top and this check only has to notice a write with no
				// guard anywhere near it. The path-aware test still runs on
				// auth.go, so nothing is weakened there.
				for _, g := range guardPositionsIn(fn.Body, call.Pos(), ceilingGuardNames) {
					if g < call.Pos() {
						guarded[key] = true
						break
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return sites, guarded
}

// TestPlatformAdminGrantClass_EveryMembershipWriteProvesItsAuthority is the
// structural half. The defect #766 describes is not a wrong branch, it is a
// missing one: a membership-write site that never asks whether its caller may
// grant the role it is writing. No behavioural test of the two handlers in
// organizations.go generalises to a third handler someone adds next year, and
// PR #815's AST guard only ever parsed auth.go, so everything outside that one
// file was structurally unchecked.
func TestPlatformAdminGrantClass_EveryMembershipWriteProvesItsAuthority(t *testing.T) {
	root := backendRoot(t)
	sites, guarded := findMembershipWriteSites(t, root)

	// An empty universe is the failure mode this check cannot otherwise see: if
	// the repository method names drift, the walk matches nothing and reports
	// green while checking nothing.
	if len(sites) == 0 {
		t.Fatal("found no membership-write calls under the module — membershipWriteMethods is " +
			"stale, so this guard is vacuous. Re-derive it from the identity store's " +
			"organization-member write methods.")
	}

	seenExemptions := map[string]bool{}
	for _, s := range sites {
		key := s.path + ":" + s.fn
		if _, exempt := bootstrapExemptions[key]; exempt {
			seenExemptions[key] = true
			continue
		}
		if guarded[key] {
			continue
		}
		t.Errorf("%s: %s writes a membership role in %s with no guard "+
			"(checkRoleAssignment / guardProvisionableRole) ahead of it. A membership write that "+
			"does not refuse an admin-bearing template can put the platform-wide `admin` scope on "+
			"an organization membership, which is the state issue #766 is about and which nothing "+
			"in the product may reach any more. Guard it, or — if it genuinely has no caller to "+
			"check and no caller-supplied template — add it to bootstrapExemptions with the reason.",
			s.pos, s.fn, s.path)
	}

	// The other direction: an exemption that no longer names a real site is a
	// standing permission nobody re-examined.
	var stale []string
	for key := range bootstrapExemptions {
		if !seenExemptions[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("bootstrapExemptions names site(s) with no membership write any more: %s. "+
			"Remove the entry — an exemption for code that no longer exists hides the day "+
			"something new moves into that function name.", strings.Join(stale, ", "))
	}

	t.Logf("checked %d membership-write call site(s) across the module", len(sites))
}

// rawMembershipWriteRe matches a hand-written statement that would create or
// re-role an organization_members row. DELETE is deliberately not matched: it
// is an authority DECREASE and the registry does perform one directly
// (internal/services/user_service.go, user deletion).
var rawMembershipWriteRe = regexp.MustCompile(`(?i)(INSERT\s+INTO\s+organization_members|UPDATE\s+organization_members\s+SET)`)

// TestPlatformAdminGrantClass_NoRawSQLMembershipWrites closes the way around
// the guard above. That test reasons about calls to the identity store's
// membership-write methods; a hand-rolled INSERT/UPDATE against
// organization_members would grant exactly the same authority and match none of
// them, so the structural check would pass while a new, entirely unguarded
// carrier for the platform-wide template existed.
//
// The registry has no such statement today — every membership role is written
// through the identity store, which is what makes the method vocabulary a
// complete universe rather than a sample. This keeps that true.
func TestPlatformAdminGrantClass_NoRawSQLMembershipWrites(t *testing.T) {
	root := backendRoot(t)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if loc := rawMembershipWriteRe.FindIndex(src); loc != nil {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, filepath.ToSlash(rel)+": "+string(src[loc[0]:loc[1]]))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s — a hand-written organization_members write bypasses the identity store's "+
			"membership methods, and therefore bypasses every ceiling check that reasons about "+
			"them (#766). Write memberships through the repository so the guard above sees them.", o)
	}
}

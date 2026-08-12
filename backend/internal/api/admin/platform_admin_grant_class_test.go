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
// It is, and it has to stay that way: `organization_members.role_template_id`
// is the ONLY carrier for scopes in this system, so it is also the only carrier
// for the platform-wide wildcard. The setup wizard bootstraps the first
// operator that way (internal/api/setup/handlers.go), and after setup closes
// the org-member API is the only route left that can mint another one.
// Rejecting admin-bearing templates there — #766's headline recommendation —
// would leave a deployment unable to have a platform administrator at all.
//
// What CAN be made enforceable is the property that the #719 tenant-scoping
// exemptions actually rest on:
//
//	an admin-bearing role template becomes a membership role only where a
//	principal that already holds platform-admin authority put it there.
//
// PR #815 enforced that on the IdP-driven writes in auth.go
// (idp_membership_guard_class_test.go). The human-driven writes in
// organizations.go are enforced by checkRoleAssignment's ceiling, which
// auth.RoleScopesPermittedBy makes fail-closed for ScopeAdmin specifically:
// a caller who does not hold `admin` can never assign a role that carries it,
// in any organization. That half had unit coverage on checkRoleAssignment
// itself but nothing tying it to the routes #719 exempted, and no structural
// guard outside auth.go — so a third membership-write handler could be added
// with no ceiling at all and every existing test would stay green.
//
// This file closes both: the behavioural half on the two exempted routes, and
// the structural half across the whole backend tree.

// ---------------------------------------------------------------------------
// Behavioural half: the routes #719 exempted
// ---------------------------------------------------------------------------

// newOrgScopedMemberRouter wires the two member-write routes with a principal
// that is an organization owner in org-1 and nothing more — deliberately NOT
// the platform administrator newOrgRouter installs, since that principal is
// allowed to assign anything and so cannot show the ceiling working.
func newOrgScopedMemberRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewOrganizationHandlers(&config.Config{}, db, repositories.NewNamespaceClaimRepository(db), nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "org-owner-1")
		c.Set("auth_method", "jwt")
		// The flat, org-less union a session JWT carries (#652). It is enough
		// to pass RequireScope(organizations:write) on these routes, which is
		// why the per-org ceiling below is the check that matters.
		c.Set("scopes", []string{string(auth.ScopeOrganizationsWrite)})
	})
	r.POST("/organizations/:id/members", h.AddMemberHandler())
	r.PUT("/organizations/:id/members/:user_id", h.UpdateMemberHandler())
	return mock, r
}

// expectOrgOwnerCeilingLookups queues the two reads checkRoleAssignment makes
// for a non-platform-admin caller: the target template's scopes, then the
// caller's own role IN THE TARGET ORG.
func expectOrgOwnerCeilingLookups(mock sqlmock.Sqlmock, roleScopesJSON string) {
	mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(roleScopesJSON)))
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

// TestPlatformAdminGrantClass_OrgScopedCallerCannotGrantAdminTemplate is the
// property #719's route exemptions depend on, asserted at the route rather than
// at checkRoleAssignment: an organization owner — the strongest per-org role
// migration 000049 defines — cannot hand out an admin-bearing template through
// either member-write route, and no membership write reaches the database.
//
// sqlmock is in its default ordered mode with no INSERT/UPDATE queued, so a
// regression that dropped the ceiling would not merely return the wrong status,
// it would attempt an unexpected write and fail here on that too.
func TestPlatformAdminGrantClass_OrgScopedCallerCannotGrantAdminTemplate(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"add member", http.MethodPost, "/organizations/org-1/members"},
		{"update member", http.MethodPut, "/organizations/org-1/members/target-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, r := newOrgScopedMemberRouter(t)
			expectOrgOwnerCeilingLookups(mock, `["admin"]`)

			body := `{"user_id":"target-1","role_template_id":"` + adminBearingRoleUUID + `"}`
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(body)))

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 — an org-scoped caller must not be able to "+
					"grant the platform-wide admin template (#766): body=%s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet/unexpected expectations (a membership write must not be attempted): %v", err)
			}
		})
	}
}

// TestPlatformAdminGrantClass_OrgScopedCallerCanStillGrantWithinItsAuthority is
// the positive control for the test above. Without it, a change that rejected
// every role assignment outright would satisfy the negative case and look like
// a fix.
//
// The role assigned here is one the org owner holds itself, so the ceiling
// permits it and the handler proceeds to the membership write.
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

// ---------------------------------------------------------------------------
// Structural half: every membership write in the tree, not just auth.go
// ---------------------------------------------------------------------------

// ceilingGuardNames are the accepted ways a membership write can have proven
// the writer's authority to grant the role it is about to write:
//
//   - checkRoleAssignment — the human-driven ceiling (role_ceiling.go). Denies
//     any admin-bearing template to a caller who does not already hold `admin`,
//     because auth.RoleScopesPermittedBy refuses ScopeAdmin outright for a
//     non-admin caller.
//   - guardProvisionableRole / resolveProvisionableRole — the IdP-driven guard
//     (group_mapping_guard.go), which refuses admin-bearing templates to every
//     caller, human or not (#604, #815).
var ceilingGuardNames = map[string]bool{
	"checkRoleAssignment":      true,
	"guardProvisionableRole":   true,
	"resolveProvisionableRole": true,
}

// bootstrapExemptions are membership writes that deliberately grant the
// platform-wide template with no caller authority to check, keyed by
// "<path>:<function>". Being a map rather than a prefix rule is the point: a
// new unguarded write cannot join the exemption by living in a plausible-looking
// file, someone has to name it here.
//
// Checked in BOTH directions — an entry naming a site that no longer exists
// fails the test too, so the list cannot rot into names nobody has re-examined.
var bootstrapExemptions = map[string]string{
	"internal/api/setup/handlers.go:ConfigureAdmin": "Setup-wizard bootstrap: creates the FIRST platform " +
		"administrator, before any principal exists whose authority could be checked. Gated on the " +
		"one-time setup token and refused once setup completes. This is the grant that makes every " +
		"later ceiling check able to succeed for somebody.",
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
		t.Errorf("%s: %s writes a membership role in %s with no ceiling guard "+
			"(checkRoleAssignment / guardProvisionableRole) ahead of it. A membership write "+
			"that does not check its caller's authority can hand out the platform-wide `admin` "+
			"template, which the org-less session scope union (#652) then carries into every "+
			"organization (#766). Guard it, or — if it genuinely has no caller to check — add "+
			"it to bootstrapExemptions with the reason.",
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

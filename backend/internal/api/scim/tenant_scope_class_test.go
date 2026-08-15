package scim

import (
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// CLASS TEST for the SCIM half of issue #719 — the DELETE axis.
//
// It lives here rather than in internal/api/admin's table because the class
// spans packages: the same defect (an organization-owned row written without
// binding the caller to its owning organization) has instances in both, and a
// table that can only see one package is a table that reports green while the
// other leaks. The two share one resolver, internal/tenantscope.
//
// This package's instance is the most destructive in the batch and needs no
// read at all: every deactivation path called RemoveAllMembershipsForUser, a
// single statement with WHERE user_id = $1 and no organization predicate
// anywhere. scim:provision is granted through membership in ONE organization,
// so a provisioner in any tenant could delete a target's membership rows in
// EVERY organization on the platform by naming their user id.
//
// There are FOUR such paths, which is the point of shaping this as a table:
// DELETE /Users/:id, PUT with active=false, PATCH replace path=active, and the
// pathless PATCH replace form. Fixing the one that gets reported leaves three.

const (
	scimOrgAlpha = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // the caller's org
	scimOrgBeta  = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb" // the victim's other org
	scimTargetID = "33333333-cccc-4ccc-8ccc-cccccccccccc"
	scimCallerID = "44444444-dddd-4ddd-8ddd-dddddddddddd"
)

var scimMembershipCols = []string{
	"organization_id", "organization_name", "role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

var scimUserCols = []string{
	"id", "email", "name", "oidc_sub", "created_at", "updated_at",
}

// scimRegistryRoleCols is the projection MemberRoleReader.RolesForUser selects
// (terraform-suite-identity#206, phase 3b).
var scimRegistryRoleCols = []string{
	"organization_id", "role_template_id", "role_template_name",
	"role_template_display_name", "role_template_scopes",
}

// expectCallerRegistryRoles primes the SECOND read every membership accessor
// now issues: the shared identity store still answers "which organizations is
// this caller a member of", and registry's own organization_member_roles
// answers "with what role, here".
//
// The rows given must carry the SAME role ids and scopes as the identity rows
// queued just before, so these fixtures keep testing the tenant predicate they
// were written for rather than accidentally testing a divergence. A mismatch is
// not silent -- the read path logs it and increments
// registry_role_read_divergence_total -- but it would change what the
// surrounding assertion means, which is worse than loud.
func expectCallerRegistryRoles(mock sqlmock.Sqlmock, orgIDs ...string) {
	rows := sqlmock.NewRows(scimRegistryRoleCols)
	for i, orgID := range orgIDs {
		rows.AddRow(orgID, fmt.Sprintf("role-%d", i+1),
			"provisioner", "Provisioner", []byte(`["scim:provision"]`))
	}
	mock.ExpectQuery(`(?s)FROM organization_member_roles omr.*WHERE omr\.user_id`).
		WithArgs(scimCallerID).
		WillReturnRows(rows)
}

// scimDeprovisionPath is one enumerated deactivation path over
// organization_members.
type scimDeprovisionPath struct {
	// symbol is the stable site identity inside this package.
	symbol string
	// route is the stable site identity at the API surface.
	route string
	// request issues the deactivation.
	request func() *http.Request
	// updatesUserRow is true for the paths that persist the user row after
	// deprovisioning (PUT and PATCH). DELETE does not, so priming the UPDATE
	// unconditionally would leave an unmet expectation on that path alone.
	updatesUserRow bool
}

func scimDeprovisionPaths() []scimDeprovisionPath {
	return []scimDeprovisionPath{
		{
			symbol: "scim.Handlers.DeleteUser",
			route:  "DELETE /scim/v2/Users/:id",
			request: func() *http.Request {
				return httptest.NewRequest("DELETE", "/scim/v2/Users/"+scimTargetID, nil)
			},
		},
		{
			symbol: "scim.Handlers.PutUser (active=false)",
			route:  "PUT /scim/v2/Users/:id",
			request: func() *http.Request {
				body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],` +
					`"userName":"victim@example.com","active":false}`
				req := httptest.NewRequest("PUT", "/scim/v2/Users/"+scimTargetID, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			updatesUserRow: true,
		},
		{
			symbol: "scim.Handlers.applyReplaceOp (path=active)",
			route:  "PATCH /scim/v2/Users/:id",
			request: func() *http.Request {
				body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
					`"Operations":[{"op":"replace","path":"active","value":false}]}`
				req := httptest.NewRequest("PATCH", "/scim/v2/Users/"+scimTargetID, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			updatesUserRow: true,
		},
		{
			symbol: "scim.Handlers.applyReplaceOp (pathless)",
			route:  "PATCH /scim/v2/Users/:id",
			request: func() *http.Request {
				body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
					`"Operations":[{"op":"replace","value":{"active":false}}]}`
				req := httptest.NewRequest("PATCH", "/scim/v2/Users/"+scimTargetID, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			updatesUserRow: true,
		},
	}
}

// scimRouter mounts the four deactivation routes behind a NON-ADMIN
// scim:provision principal whose only membership is scimOrgAlpha. Platform
// admins are deliberately exempt from this guard, so testing with one proves
// nothing.
func scimRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := NewHandlers(&config.Config{}, db)

	// Statement ORDER is not the property under test — which statements are
	// issued is. DELETE /Users/:id never reaches the user UPDATE that PUT and
	// PATCH perform, so an ordered matcher would fail for the wrong reason.
	mock.MatchExpectationsInOrder(false)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeSCIMProvision)})
		c.Set("user_id", scimCallerID)
	})
	r.PUT("/scim/v2/Users/:id", h.PutUser())
	r.PATCH("/scim/v2/Users/:id", h.PatchUser())
	r.DELETE("/scim/v2/Users/:id", h.DeleteUser())
	return r, mock
}

// boundScope matches the array argument an OrgScope binds into a statement,
// asserting which organization ids it names and which it does not.
//
// This is the assertion the class needs now that the tenant constraint is a
// PREDICATE rather than a loop. Before identity v0.25.0 the only way to check
// it was to count DELETE statements and inspect their per-row arguments; the
// removal is one statement now, so what has to be pinned is the CONTENT of the
// scope it carries.
type boundScope struct {
	want    []string
	notWant []string
}

func (b boundScope) Match(v driver.Value) bool {
	s := fmt.Sprint(v)
	for _, w := range b.want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	for _, n := range b.notWant {
		if strings.Contains(s, n) {
			return false
		}
	}
	return true
}

// TestSCIMDeprovisionClass_OnlyRemovesInScopeMemberships is the class assertion.
//
// The target belongs to BOTH organizations; the caller holds scim:provision in
// Alpha only. ONE removal is issued and it carries a tenant predicate naming
// Alpha and only Alpha, so Beta's row is unreachable by the database rather than
// by a filter this handler applies to rows it already read. A mutant that passes
// the platform-wide scope renders the predicate as the literal TRUE, binds no
// array at all, and fails the expectation below.
func TestSCIMDeprovisionClass_OnlyRemovesInScopeMemberships(t *testing.T) {
	for _, path := range scimDeprovisionPaths() {
		t.Run(path.symbol, func(t *testing.T) {
			r, mock := scimRouter(t)

			// Every path loads the target user first.
			mock.ExpectQuery("(?s)FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
					scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

			// The CALLER's memberships: scim:provision in Alpha only.
			mock.ExpectQuery("(?s)SELECT.*FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols).AddRow(
					scimOrgAlpha, "Alpha", "role-1", time.Now(),
					"provisioner", "Provisioner", []byte(`["scim:provision"]`)))
			// ...and the role each of those memberships carries IN REGISTRY,
			// which is where the scope that resolves the tenant predicate now
			// comes from (terraform-suite-identity#206, phase 3b).
			expectCallerRegistryRoles(mock, scimOrgAlpha)

			// GUARD scim-deprovision-tenant-scope. One statement, scoped to
			// Alpha, RETURNING the organizations it actually removed — the value
			// that then scopes the credential sweep.
			mock.ExpectQuery(`(?s)DELETE FROM organization_members WHERE user_id = \$1 AND organization_id = ANY\(\$2\)`).
				WithArgs(scimTargetID, boundScope{want: []string{scimOrgAlpha}, notWant: []string{scimOrgBeta}}).
				WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow(scimOrgAlpha))

			// PUT/PATCH persist the user row afterwards; DELETE does not.
			if path.updatesUserRow {
				mock.ExpectExec("(?s)UPDATE users").
					WillReturnResult(sqlmock.NewResult(0, 1))
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, path.request())

			if w.Code >= 500 {
				t.Fatalf("%s (%s): status = %d, body=%s",
					path.symbol, path.route, w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("%s (%s): the scoped membership removal was not issued as expected — "+
					"guard scim-deprovision-tenant-scope missing?: %v",
					path.symbol, path.route, err)
			}
		})
	}
}

// TestSCIMDeprovisionClass_NoScopeRemovesNothing pins the fail-closed default: a
// principal with no qualifying membership deprovisions nobody, rather than
// falling through to the unscoped sweep.
func TestSCIMDeprovisionClass_NoScopeRemovesNothing(t *testing.T) {
	for _, path := range scimDeprovisionPaths() {
		t.Run(path.symbol, func(t *testing.T) {
			r, mock := scimRouter(t)

			mock.ExpectQuery("(?s)FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
					scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))
			// Caller holds scim:provision NOWHERE, so the resolved scope
			// matches nothing and RemoveAllMembershipsForUser short-circuits
			// without a round trip. No DELETE is primed, so any removal at all
			// is an unexpected statement.
			mock.ExpectQuery("(?s)SELECT.*FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols))
			mock.ExpectExec("(?s)UPDATE users").
				WillReturnResult(sqlmock.NewResult(0, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, path.request())

			if err := mock.ExpectationsWereMet(); err != nil &&
				strings.Contains(err.Error(), "DELETE FROM organization_members") {
				t.Fatalf("%s (%s): a principal with no scim:provision anywhere still "+
					"removed memberships — guard scim-deprovision-tenant-scope missing?: %v",
					path.symbol, path.route, err)
			}
		})
	}
}

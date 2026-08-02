package scim

import (
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

// scimDeprovisionPath is one enumerated deactivation path over
// organization_members.
type scimDeprovisionPath struct {
	// symbol is the stable site identity inside this package.
	symbol string
	// route is the stable site identity at the API surface.
	route string
	// request issues the deactivation.
	request func() *http.Request
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

// TestSCIMDeprovisionClass_OnlyRemovesInScopeMemberships is the class assertion.
//
// The target belongs to BOTH organizations; the caller holds scim:provision in
// Alpha only. Exactly one DELETE — Alpha's — may be issued. sqlmock fails on any
// unexpected statement, so a sweep that also removes Beta's row (or that falls
// back to the single unscoped RemoveAllMembershipsForUser) surfaces here rather
// than passing silently.
func TestSCIMDeprovisionClass_OnlyRemovesInScopeMemberships(t *testing.T) {
	for _, path := range scimDeprovisionPaths() {
		t.Run(path.symbol, func(t *testing.T) {
			r, mock := scimRouter(t)

			// Every path loads the target user first.
			mock.ExpectQuery("(?s)FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows(scimUserCols).AddRow(
					scimTargetID, "victim@example.com", "Victim", nil, time.Now(), time.Now()))

			// The CALLER's memberships: scim:provision in Alpha only.
			mock.ExpectQuery("(?s)FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols).AddRow(
					scimOrgAlpha, "Alpha", "role-1", time.Now(),
					"provisioner", "Provisioner", []byte(`["scim:provision"]`)))

			// The TARGET's memberships: both organizations.
			mock.ExpectQuery("(?s)FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols).
					AddRow(scimOrgAlpha, "Alpha", "role-1", time.Now(),
						"viewer", "Viewer", []byte(`["modules:read"]`)).
					AddRow(scimOrgBeta, "Beta", "role-2", time.Now(),
						"viewer", "Viewer", []byte(`["modules:read"]`)))

			// EXACTLY ONE removal, for Alpha. Any second DELETE — or the
			// unscoped sweep — is an unexpected statement.
			mock.ExpectExec("(?s)DELETE FROM organization_members").
				WithArgs(scimOrgAlpha, scimTargetID).
				WillReturnResult(sqlmock.NewResult(0, 1))

			// PUT/PATCH persist the user row afterwards; DELETE does not.
			mock.ExpectExec("(?s)UPDATE users").
				WillReturnResult(sqlmock.NewResult(0, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, path.request())

			if w.Code >= 500 {
				t.Fatalf("%s (%s): status = %d, body=%s",
					path.symbol, path.route, w.Code, w.Body.String())
			}

			// The assertion that matters: Beta's membership was never touched.
			// GUARD scim-deprovision-tenant-scope.
			if err := mock.ExpectationsWereMet(); err != nil {
				if strings.Contains(err.Error(), "DELETE FROM organization_members") &&
					strings.Contains(err.Error(), scimOrgBeta) {
					t.Fatalf("%s (%s): removed a membership in an organization the "+
						"caller has no scim:provision in — guard "+
						"scim-deprovision-tenant-scope missing?: %v",
						path.symbol, path.route, err)
				}
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
			// Caller holds scim:provision NOWHERE.
			mock.ExpectQuery("(?s)FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols))
			// Target's memberships may still be read; no DELETE is primed, so
			// any removal at all is an unexpected statement.
			mock.ExpectQuery("(?s)FROM organization_members").
				WillReturnRows(sqlmock.NewRows(scimMembershipCols).
					AddRow(scimOrgBeta, "Beta", "role-2", time.Now(),
						"viewer", "Viewer", []byte(`["modules:read"]`)))
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

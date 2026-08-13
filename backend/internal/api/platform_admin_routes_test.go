package api

import (
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// Issue #766, PR 2 — the gate on /api/v1/admin/platform-admins.
//
// These routes confer and remove the highest privilege in the product, so the
// authority question is the whole point: only a principal holding `admin` may
// reach them. After PR 1 that scope means "the platform_admins carrier OR the
// role-template union", and at PR 3 it will mean the carrier alone — with no
// edit to the routes, which is why the gate is the SCOPE and not the carrier
// read directly (see the package comment in internal/api/admin/platform_admins.go).
//
// Written the same way as TestPlatformTerraformMirrorRoutes_Authority, over the
// real registerAPIV1Routes wiring rather than a hand-mounted group, so a route
// that loses its gate — or is moved to a group that does not carry one — fails
// here rather than in a test that describes routes as they were the day it was
// written.

// platformAdminTargetID is an arbitrary well-formed UUID. The gate decides
// before any row is read, so no grant needs to exist for it to be observable.
const platformAdminTargetID = "9f1d1f8e-2b7a-4c53-8f0e-6a1b2c3d4e5f"

var platformAdminRoutes = []struct {
	name   string
	method string
	path   string
}{
	{"list platform admins", http.MethodGet, "/api/v1/admin/platform-admins"},
	{"grant platform admin", http.MethodPost, "/api/v1/admin/platform-admins"},
	{"revoke platform admin", http.MethodDelete, "/api/v1/admin/platform-admins/" + platformAdminTargetID},
}

func TestPlatformAdminRoutes_RequireTheAdminScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-jwt-secret-that-is-32-chars!!")

	principals := []struct {
		name        string
		scopes      []string
		wantAllowed bool
	}{
		{
			// The seeded org_owner: every organization-level scope the product
			// grants through membership, and none of them is `admin`.
			name: "organization owner",
			scopes: []string{
				string(auth.ScopeModulesWrite), string(auth.ScopeProvidersWrite),
				string(auth.ScopeMirrorsManage), string(auth.ScopeUsersWrite),
				string(auth.ScopeAuditRead),
			},
			wantAllowed: false,
		},
		{
			name:        "reader",
			scopes:      []string{string(auth.ScopeModulesRead)},
			wantAllowed: false,
		},
		{
			name:        "platform admin",
			scopes:      []string{string(auth.ScopeAdmin)},
			wantAllowed: true,
		},
	}

	for _, p := range principals {
		for _, rt := range platformAdminRoutes {
			t.Run(p.name+"/"+rt.name, func(t *testing.T) {
				code := platformRouteCase(t, rt.method, rt.path, p.scopes)

				if code == http.StatusNotFound {
					t.Fatalf("%s %s: 404 — the route is not registered", rt.method, rt.path)
				}
				// The deps handed to platformRouteCase carry no
				// PlatformAdminHandlers, so an AUTHORIZED caller falls through
				// to a nil handler and gin.Recovery answers 500. The signal is
				// exactly "403 or not", which is the authority decision.
				gotAllowed := code != http.StatusForbidden
				if gotAllowed != p.wantAllowed {
					verb := "allowed"
					if !p.wantAllowed {
						verb = "refused"
					}
					t.Errorf("%s %s as %s: status %d, want the caller to be %s.\n"+
						"These routes grant and revoke platform-admin; a principal without the "+
						"`admin` scope must not reach them.",
						rt.method, rt.path, p.name, code, verb)
				}
			})
		}
	}
}

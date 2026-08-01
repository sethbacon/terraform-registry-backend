package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// CLASS TEST for issue #719: an organization-owned row read or written without
// verifying the caller's membership in the owning organization.
//
// This supersedes tenant_scoping_test.go as the coverage of record. That file
// is the cautionary example: it asserted the two sites the #719 fix touched
// (ListAuditLogsHandler, SCMProviderHandlers.ListProviders), passed, and the
// issue was closed — while the by-id read, the export stream, the mirror list,
// the policy read, the approval list and three create/update axes over the SAME
// resources kept leaking. A test shaped like the fix inherits the fix's blind
// spots.
//
// So this table is shaped like the CLASS instead: it is generated from the
// enumeration, one row per (resource x access axis) site, and every row is
// driven by the same two questions —
//
//	1. does a caller who is NOT a member of the owning organization get denied?
//	2. does a caller who IS a member still get through?
//
// Each row names the guard whose removal must make it fail, so a mutation gate
// can flip one guard at a time and require exactly the matching row to go red.
//
// Sites are recorded by STABLE IDENTITY (package.Symbol + METHOD /route), not
// by file/line, so the table survives refactoring.

const (
	classOrgAlpha = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // the caller's org
	classOrgBeta  = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb" // the victim's org
	classUserID   = "33333333-cccc-4ccc-8ccc-cccccccccccc"
	classResource = "44444444-dddd-4ddd-8ddd-dddddddddddd"
)

// tenantScopeSite is one enumerated instance of the class.
type tenantScopeSite struct {
	// symbol is the stable site identity inside this package.
	symbol string
	// route is the stable site identity at the API surface.
	route string
	// guard names the guard comment in the fixed code. Removing it must make
	// this row fail.
	guard string
	// mount builds a router exposing only this handler, plus the sqlmock the
	// row primes. `member` selects whether the caller belongs to classOrgBeta.
	mount func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock)
	// request issues the cross-tenant request.
	request func() *http.Request
	// wantForeignStatus is the status a NON-member must receive.
	wantForeignStatus int
	// foreignBodyMustNotContain is checked on the non-member response: the
	// victim organization's id must never appear in a 200 body either, which is
	// how the list/export axes fail (they answer 200 with filtered rows rather
	// than denying outright).
	foreignBodyMustNotContain string
}

// -----------------------------------------------------------------------
// shared mount helpers
// -----------------------------------------------------------------------

// classMembershipRows answers OrganizationRepository.GetUserMemberships. A
// non-member of classOrgBeta is still a member of classOrgAlpha: the point is
// cross-tenant denial, not "unauthenticated is denied", which would pass
// trivially.
func classMembershipRows(member bool) *sqlmock.Rows {
	rows := sqlmock.NewRows(membershipCols)
	if member {
		return rows.AddRow(classOrgBeta, "Beta", "role-1", time.Now(),
			"devops", "DevOps", []byte(`["mirrors:manage","mirrors:read","scm:manage","audit:read"]`))
	}
	return rows.AddRow(classOrgAlpha, "Alpha", "role-1", time.Now(),
		"devops", "DevOps", []byte(`["mirrors:manage","mirrors:read","scm:manage","audit:read"]`))
}

// classCaller installs a NON-admin principal. Platform admins are deliberately
// exempt from every guard in this class, so testing with one proves nothing.
func classCaller() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("scopes", []string{
			string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage),
			string(auth.ScopeAuditRead), string(auth.ScopeSCMManage),
		})
		c.Set("user_id", classUserID)
	}
}

func classSQLMock(t *testing.T) (sqlmock.Sqlmock, *sqlx.DB, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := gin.New()
	r.Use(classCaller())
	return mock, sqlx.NewDb(db, "sqlmock"), r
}

func tenantScopeSites() []tenantScopeSite {
	return []tenantScopeSite{
		{
			symbol: "admin.AuditLogHandlers.GetAuditLogHandler",
			route:  "GET /api/v1/admin/audit-logs/:id",
			guard:  "audit-byid-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM audit_logs").WillReturnRows(
					sqlmock.NewRows(auditLogGetCols).AddRow(
						classResource, classUserID, classOrgBeta, "mirror.create",
						"mirror", classResource, nil, nil, time.Now()))
				r.GET("/admin/audit-logs/:id", NewAuditLogHandlers(sqlxDB.DB).GetAuditLogHandler())
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/audit-logs/"+classResource, nil)
			},
			// Out-of-scope entries read as absent, so the route cannot be used to
			// probe for another organization's audit entries.
			wantForeignStatus:         http.StatusNotFound,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			// The headline instance of this batch: the #719 fix scoped the LIST
			// axis of this very resource and left the EXPORT axis — a different
			// symbol, in a different file, calling a different repository method
			// — reading every organization's audit trail.
			symbol: "admin.AuditLogHandlers.ExportAuditLogs",
			route:  "GET /api/v1/admin/audit-logs/export",
			guard:  "audit-export-row-filter",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM audit_logs").WillReturnRows(
					sqlmock.NewRows(auditExportCols).AddRow(
						"beta-entry", classUserID, classOrgBeta, "mirror.create",
						"mirror", classResource, nil, nil, time.Now(), nil, nil))
				r.GET("/admin/audit-logs/export", NewAuditLogHandlers(sqlxDB.DB).ExportAuditLogs("test"))
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/audit-logs/export", nil)
			},
			// A stream cannot 403 after headers are sent; it answers 200 and
			// simply must not emit the foreign tenant's entries.
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: "beta-entry",
		},
		{
			symbol: "admin.MirrorHandler.ListMirrorConfigs",
			route:  "GET /api/v1/admin/mirrors",
			guard:  "mirror-list-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM mirror_configurations").WillReturnRows(
					sqlmock.NewRows(mirrorCfgCols).AddRow(
						classResource, "beta-mirror", nil, "https://registry.terraform.io", classOrgBeta,
						nil, nil, nil, nil, true, 24, nil, nil, nil,
						time.Now(), time.Now(), nil))
				h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					repositories.NewProviderRepository(sqlxDB.DB))
				r.GET("/admin/mirrors", h.ListMirrorConfigs)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/mirrors", nil)
			},
			// A list cannot 403 — it answers 200 with only what the caller may
			// see. The assertion that matters is the absence of the foreign row.
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			symbol: "admin.MirrorHandler.CreateMirrorConfig",
			route:  "POST /api/v1/admin/mirrors",
			guard:  "mirror-create-target-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM mirror_configurations").WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)INSERT INTO mirror_configurations").WillReturnRows(
					sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
						AddRow(classResource, time.Now(), time.Now()))
				h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					repositories.NewProviderRepository(sqlxDB.DB))
				r.POST("/admin/mirrors", h.CreateMirrorConfig)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"name":"planted","upstream_registry_url":"https://registry.terraform.io",` +
					`"organization_id":"` + classOrgBeta + `"}`
				req := httptest.NewRequest("POST", "/admin/mirrors", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantForeignStatus: http.StatusForbidden,
		},
		{
			symbol: "admin.MirrorHandler.UpdateMirrorConfig",
			route:  "PUT /api/v1/admin/mirrors/:id",
			guard:  "mirror-update-reparent-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				// The row being edited belongs to the caller's OWN org, so the
				// route's per-resource guard passes. The re-parent target does
				// not. That gap is what this row pins.
				mock.ExpectQuery("(?s)FROM mirror_configurations").WillReturnRows(
					sqlmock.NewRows(mirrorCfgCols).AddRow(
						classResource, "own-mirror", nil, "https://registry.terraform.io", classOrgAlpha,
						nil, nil, nil, nil, true, 24, nil, nil, nil,
						time.Now(), time.Now(), nil))
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectExec("(?s)UPDATE mirror_configurations").WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					repositories.NewProviderRepository(sqlxDB.DB))
				r.PUT("/admin/mirrors/:id", h.UpdateMirrorConfig)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"organization_id":"` + classOrgBeta + `"}`
				req := httptest.NewRequest("PUT", "/admin/mirrors/"+classResource, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantForeignStatus: http.StatusForbidden,
		},
		{
			// The unfiltered variant of this route is NOT an instance:
			// RBACRepository.ListMirrorPolicies with a nil organization selects
			// `WHERE mp.organization_id IS NULL`, i.e. global policies only. The
			// instance is the explicit foreign organization_id, which the
			// repository happily honours because the predicate's VALUE comes
			// straight off the wire — an SQL organization filter is not a tenant
			// binding when the caller chooses what it filters to.
			symbol: "admin.RBACHandlers.ListMirrorPolicies",
			route:  "GET /api/v1/admin/policies?organization_id=<foreign>",
			guard:  "policy-list-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM mirror_policies").WillReturnRows(
					sqlmock.NewRows(mpListCols).AddRow(
						classResource, classOrgBeta, "beta-policy", nil, "allow",
						nil, nil, nil, 10, true, false, time.Now(), time.Now(), nil, "Beta", ""))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.GET("/admin/policies", h.ListMirrorPolicies)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/policies?organization_id="+classOrgBeta, nil)
			},
			wantForeignStatus:         http.StatusForbidden,
			foreignBodyMustNotContain: "beta-policy",
		},
		{
			symbol: "admin.RBACHandlers.ListApprovalRequests",
			route:  "GET /api/v1/admin/approvals",
			guard:  "approval-list-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM mirror_approval_requests").WillReturnRows(
					sqlmock.NewRows(approvalListCols).AddRow(
						classResource, classResource, classOrgBeta, nil,
						"hashicorp", nil, "", "pending",
						nil, nil, nil, false,
						time.Now(), time.Now(), nil, "", "", ""))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.GET("/admin/approvals", h.ListApprovalRequests)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/approvals", nil)
			},
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			symbol: "admin.SCMProviderHandlers.CreateProvider",
			route:  "POST /api/v1/scm-providers",
			guard:  "scm-create-target-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				mock.ExpectQuery("(?s)FROM scm_providers").WillReturnRows(sqlmock.NewRows(scmProvCols))
				mock.ExpectExec("(?s)INSERT INTO scm_providers").WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewSCMProviderHandlers(&config.Config{},
					repositories.NewSCMRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					testTokenCipher(t))
				r.POST("/scm-providers", h.CreateProvider)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"name":"planted","provider_type":"github","client_id":"id",` +
					`"client_secret":"secret","organization_id":"` + classOrgBeta + `"}`
				req := httptest.NewRequest("POST", "/scm-providers", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantForeignStatus: http.StatusForbidden,
		},
	}
}

// TestTenantScopeClass_ForeignOrgDenied is the class assertion: for EVERY
// enumerated site, a caller who is a member of some other organization must not
// reach classOrgBeta's row.
func TestTenantScopeClass_ForeignOrgDenied(t *testing.T) {
	for _, site := range tenantScopeSites() {
		t.Run(site.symbol, func(t *testing.T) {
			r, _ := site.mount(t, false)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, site.request())

			if w.Code != site.wantForeignStatus {
				t.Errorf("%s (%s): status = %d, want %d — guard %q missing?\nbody: %s",
					site.symbol, site.route, w.Code, site.wantForeignStatus, site.guard, w.Body.String())
			}
			if site.foreignBodyMustNotContain != "" &&
				strings.Contains(w.Body.String(), site.foreignBodyMustNotContain) {
				t.Errorf("%s (%s): response leaked organization %s across the tenant "+
					"boundary — guard %q missing?\nbody: %s",
					site.symbol, site.route, site.foreignBodyMustNotContain, site.guard, w.Body.String())
			}
		})
	}
}

// TestTenantScopeClass_OwnOrgAllowed is the other half: the guards must not
// break legitimate same-organization access. Without this the class could be
// "fixed" by denying everyone.
func TestTenantScopeClass_OwnOrgAllowed(t *testing.T) {
	for _, site := range tenantScopeSites() {
		t.Run(site.symbol, func(t *testing.T) {
			r, _ := site.mount(t, true)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, site.request())

			if w.Code == http.StatusForbidden || w.Code == http.StatusNotFound {
				t.Errorf("%s (%s): status = %d for a MEMBER of the owning organization; "+
					"guard %q is over-broad\nbody: %s",
					site.symbol, site.route, w.Code, site.guard, w.Body.String())
			}
		})
	}
}

// TestTenantScopeClass_NoMembershipsSeesNothing pins the fail-closed default at
// the handler layer, mirroring AuditScope's zero value in the shared module: a
// principal with no memberships must not fall through to an unfiltered result.
func TestTenantScopeClass_NoMembershipsSeesNothing(t *testing.T) {
	cases := []struct {
		name  string
		scope TenantScope
		orgID string
		want  bool
	}{
		{"zero value denies a real org", TenantScope{}, classOrgBeta, false},
		{"zero value denies unowned rows", TenantScope{}, "", false},
		{"member permits own org", TenantScope{OrgIDs: []string{classOrgAlpha}}, classOrgAlpha, true},
		{"member denies foreign org", TenantScope{OrgIDs: []string{classOrgAlpha}}, classOrgBeta, false},
		{"member denies unowned rows", TenantScope{OrgIDs: []string{classOrgAlpha}}, "", false},
		{"platform admin permits any org", TenantScope{PlatformAdmin: true}, classOrgBeta, true},
		{"platform admin permits unowned rows", TenantScope{PlatformAdmin: true}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.Permits(tc.orgID); got != tc.want {
				t.Errorf("Permits(%q) = %v, want %v", tc.orgID, got, tc.want)
			}
		})
	}
}

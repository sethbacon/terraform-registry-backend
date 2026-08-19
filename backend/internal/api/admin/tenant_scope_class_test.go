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
	"github.com/terraform-registry/terraform-registry/internal/db/models"
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
	// principal overrides the default non-admin JWT caller. Rows that exercise
	// a different PRINCIPAL KIND — an organization-bound API key, say — set
	// this; everything else leaves it nil.
	principal func(member bool) gin.HandlerFunc
	// request issues the cross-tenant request.
	request func() *http.Request
	// wantForeignStatus is the status a NON-member must receive.
	wantForeignStatus int
	// ownOrgBodyMustContain is checked on the MEMBER response. Denial alone is
	// only half a guard: a resolver that returns the empty scope for a principal
	// it does not understand denies everything, passes every foreign-org
	// assertion, and is still broken. This is the half that catches that — it is
	// how the API-key row pins the "silent empty list on its OWN organization"
	// direction of the defect.
	ownOrgBodyMustContain string
	// ownOrgExempt, when non-empty, records WHY this row is excluded from the
	// own-organization half of the class assertion — the case where the correct
	// answer is "denied to every non-admin, member or not". Stating the reason
	// on the row keeps the exemption reviewable instead of silent.
	ownOrgExempt string
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
const classRoleScopes = `["mirrors:manage","mirrors:read","scm:manage","audit:read","organizations:read"]`

func classMembershipRows(member bool) *sqlmock.Rows {
	rows := sqlmock.NewRows(membershipCols)
	if member {
		return rows.AddRow(classOrgBeta, "Beta", "role-1", time.Now(),
			"devops", "DevOps", []byte(classRoleScopes))
	}
	return rows.AddRow(classOrgAlpha, "Alpha", "role-1", time.Now(),
		"devops", "DevOps", []byte(classRoleScopes))
}

// classCaller installs a NON-admin principal. Platform admins are deliberately
// exempt from every guard in this class, so testing with one proves nothing.
func classCaller() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("scopes", []string{
			string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage),
			string(auth.ScopeAuditRead), string(auth.ScopeSCMManage),
			string(auth.ScopeOrganizationsRead),
		})
		c.Set("user_id", classUserID)
	}
}

func classSQLMock(t *testing.T) (sqlmock.Sqlmock, *sqlx.DB, *gin.Engine) {
	t.Helper()
	return classSQLMockAs(t, classCaller())
}

// classSQLMockAs is classSQLMock with an explicit principal, for the rows that
// exercise a principal kind other than the default non-admin JWT caller.
func classSQLMockAs(t *testing.T, principal gin.HandlerFunc) (sqlmock.Sqlmock, *sqlx.DB, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := gin.New()
	r.Use(principal)
	return mock, sqlx.NewDb(db, "sqlmock"), r
}

// classAPIKeyCaller installs a USERLESS organization-bound API key — the shape a
// CI service credential actually has (api_keys.user_id IS NULL). It has no
// memberships to look up, so before GUARD tenant-scope-api-key-principal it
// resolved to the empty scope and was served silent empty lists and 403s on its
// OWN organization, while the /:id routes of the same families accepted it.
func classAPIKeyCaller(orgID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("scopes", []string{
			string(auth.ScopeMirrorsRead), string(auth.ScopeMirrorsManage),
			string(auth.ScopeAuditRead), string(auth.ScopeSCMManage),
			string(auth.ScopeOrganizationsRead),
		})
		c.Set("api_key", &models.APIKey{OrganizationID: orgID})
	}
}

// classMembershipRowsWithScopes is classMembershipRows with the role template's
// scopes chosen per case, for the row that pins GUARD
// tenant-scope-role-template: bare membership is not authority.
func classMembershipRowsWithScopes(orgID string, scopes string) *sqlmock.Rows {
	return sqlmock.NewRows(membershipCols).AddRow(
		orgID, "Org", "role-1", time.Now(), "custom", "Custom", []byte(scopes))
}

// expectClassRegistryRoles queues the read of registry's own role tables that
// now follows every classMembershipRows lookup, answering with the SAME role and
// the SAME scopes so each site's resolved tenant scope is unchanged.
func expectClassRegistryRoles(mock sqlmock.Sqlmock, member bool) {
	orgID := classOrgAlpha
	if member {
		orgID = classOrgBeta
	}
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgID, id: "role-1", name: "devops", displayName: "DevOps", scopes: classRoleScopes,
	})
}

// expectClassRegistryRolesWithScopes is the same for classMembershipRowsWithScopes.
func expectClassRegistryRolesWithScopes(mock sqlmock.Sqlmock, orgID, scopes string) {
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgID, id: "role-1", name: "custom", displayName: "Custom", scopes: scopes,
	})
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
				expectClassRegistryRoles(mock, member)
				// The tenant constraint is a QUERY PREDICATE, so the expectation
				// requires it in the statement: strip the guard and the emitted
				// SQL no longer matches, the read errors, and this row goes red.
				// A scoped database simply does not return the foreign row, so
				// the non-member case answers zero rows rather than relying on
				// the handler to discard what it was handed.
				q := mock.ExpectQuery(`(?s)FROM audit_logs.*organization_id = ANY`)
				if member {
					q.WillReturnRows(sqlmock.NewRows(auditLogGetCols).AddRow(
						classResource, classUserID, classOrgBeta, "mirror.create",
						"mirror", classResource, nil, nil, time.Now(), nil))
				} else {
					q.WillReturnRows(sqlmock.NewRows(auditLogGetCols))
				}
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
			guard:  "audit-export-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				// As with the by-id axis: the predicate is in the statement, so
				// the stream never receives the foreign tenant's rows. The
				// earlier revision of this batch filtered them out in Go after
				// reading them, which produced the same bytes on the wire and
				// left the leak in place.
				q := mock.ExpectQuery(`(?s)FROM audit_logs.*organization_id = ANY`)
				if member {
					q.WillReturnRows(sqlmock.NewRows(auditExportCols).AddRow(
						"beta-entry", classUserID, classOrgBeta, "mirror.create",
						"mirror", classResource, nil, nil, time.Now(), nil, nil, nil))
				} else {
					q.WillReturnRows(sqlmock.NewRows(auditExportCols))
				}
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
				expectClassRegistryRoles(mock, member)
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
				expectClassRegistryRoles(mock, member)
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
				expectClassRegistryRoles(mock, member)
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
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery("(?s)FROM mirror_policies").WillReturnRows(
					sqlmock.NewRows(mpListCols).AddRow(
						classResource, classOrgBeta, "beta-policy", nil, "allow",
						nil, nil, nil, 10, true, false, time.Now(), time.Now(), nil, "Beta", ""))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil, nil).
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
			// The contract this batch had to PICK. An earlier revision let the
			// list axis return NULL-organization ("global") policies to
			// non-admins while the /:id axis it added in the same diff refused
			// them — two axes of one resource disagreeing about who owns a row,
			// which is #719 itself. Both axes now use tenantscope.Scope.Permits,
			// and it denies unowned rows to everyone but a platform admin.
			symbol: "admin.RBACHandlers.ListMirrorPolicies (unowned rows)",
			route:  "GET /api/v1/admin/policies",
			guard:  "policy-list-unowned-rows",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery("(?s)FROM mirror_policies").WillReturnRows(
					sqlmock.NewRows(mpListCols).AddRow(
						classResource, nil, "global-policy", nil, "deny",
						nil, nil, nil, 10, true, false, time.Now(), time.Now(), nil, "", ""))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil, nil).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.GET("/admin/policies", h.ListMirrorPolicies)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/policies", nil)
			},
			// A list answers 200; the assertion is the absence of the unowned row.
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: "global-policy",
			// Both cases are non-admin, so the unowned row is invisible in both.
			// OwnOrgAllowed only requires a non-403/404, which 200 satisfies.
		},
		{
			symbol: "admin.RBACHandlers.ListApprovalRequests",
			route:  "GET /api/v1/admin/approvals",
			guard:  "approval-list-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery("(?s)FROM mirror_approval_requests").WillReturnRows(
					sqlmock.NewRows(approvalListCols).AddRow(
						classResource, classResource, classOrgBeta, nil,
						"hashicorp", nil, "", "pending",
						nil, nil, nil, false,
						time.Now(), time.Now(), nil, "", "", ""))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil, nil).
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
			// The case the previous revision's table did NOT exercise: the
			// organization_id field is OMITTED rather than set to a foreign
			// UUID. The guard only ran when the field was supplied, so the whole
			// check was bypassable by deleting one key from the body — the
			// handler fell through to GetDefaultOrganization and planted the row
			// there with no membership check at all. A non-member of the default
			// organization wrote into it by saying nothing.
			symbol: "admin.MirrorHandler.CreateMirrorConfig (organization_id OMITTED)",
			route:  "POST /api/v1/admin/mirrors",
			guard:  "tenant-scope-target-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM mirror_configurations").WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectExec("(?s)INSERT INTO mirror_configurations").
					WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					repositories.NewProviderRepository(sqlxDB.DB))
				r.POST("/admin/mirrors", h.CreateMirrorConfig)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"name":"planted","upstream_registry_url":"https://registry.terraform.io"}`
				req := httptest.NewRequest("POST", "/admin/mirrors", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			// The row lands in the caller's OWN single in-scope organization, or
			// nowhere. The non-member here is a member of classOrgAlpha, so the
			// create succeeds — into Alpha, never into the default organization
			// on the strength of an omitted field. What must not happen is a
			// write attributed to an organization the caller has no scope in;
			// classOrgBeta must not appear in the response.
			wantForeignStatus:         http.StatusCreated,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			// The EMPTY-STRING spelling of the re-parent attack. `""` used to
			// null organization_id unconditionally, and jobs/mirror_sync.go
			// resolves a NULL organization back to the DEFAULT organization when
			// it materialises providers — so this re-parented the row into the
			// default org without ever naming it, walking straight past the
			// foreign-UUID guard beside it.
			symbol: "admin.MirrorHandler.UpdateMirrorConfig (organization_id EMPTY STRING)",
			route:  "PUT /api/v1/admin/mirrors/:id",
			guard:  "mirror-update-unparent-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM mirror_configurations").WillReturnRows(
					sqlmock.NewRows(mirrorCfgCols).AddRow(
						classResource, "own-mirror", nil, "https://registry.terraform.io", classOrgAlpha,
						nil, nil, nil, nil, true, 24, nil, nil, nil,
						time.Now(), time.Now(), nil))
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectExec("(?s)UPDATE mirror_configurations").WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewMirrorHandler(repositories.NewMirrorRepository(sqlxDB),
					repositories.NewOrganizationRepository(sqlxDB.DB),
					repositories.NewProviderRepository(sqlxDB.DB))
				r.PUT("/admin/mirrors/:id", h.UpdateMirrorConfig)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"organization_id":""}`
				req := httptest.NewRequest("PUT", "/admin/mirrors/"+classResource, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			// Un-owning a row is a platform-operator action; a non-admin is
			// refused in BOTH the member and non-member cases, so this row is
			// exempt from the own-org-allowed half (see classOwnOrgExempt).
			wantForeignStatus: http.StatusForbidden,
			ownOrgExempt: "un-owning a mirror configuration is a platform-operator " +
				"action: NULL organization_id resolves back to the DEFAULT " +
				"organization at sync time, so no non-admin may set it, member or not",
		},
		{
			// PRINCIPAL KIND, not membership. The resolver never read
			// c.Get("api_key"), so a userless organization service key — the
			// normal shape for CI automation, api_keys.user_id IS NULL — had no
			// memberships to look up and resolved to the empty scope: silent
			// empty lists and 403s on its OWN organization, while the /:id
			// routes of the same families accepted it via authorizeOrgAccess.
			// Broken in both directions, and invisible to a table that only ever
			// tested JWT callers.
			symbol: "admin.MirrorHandler.ListMirrorConfigs (API-key principal)",
			route:  "GET /api/v1/admin/mirrors",
			guard:  "tenant-scope-api-key-principal",
			principal: func(member bool) gin.HandlerFunc {
				if member {
					return classAPIKeyCaller(classOrgBeta)
				}
				return classAPIKeyCaller(classOrgAlpha)
			},
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				key := classAPIKeyCaller(classOrgAlpha)
				if member {
					key = classAPIKeyCaller(classOrgBeta)
				}
				mock, sqlxDB, r := classSQLMockAs(t, key)
				// No membership query is primed: an org-bound key must not need
				// one. If the resolver falls back to the user branch the
				// unexpected statement fails the row.
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
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
			// The other direction, and the one a denial-only table misses: a key
			// bound to Beta MUST see Beta's row. Before the guard it saw an empty
			// list on its own organization, which looks identical to correct
			// tenant isolation from the foreign-org side.
			ownOrgBodyMustContain: "beta-mirror",
		},
		{
			// AUTHORITY, not membership. The resolver ignored
			// RoleTemplateScopes even though GetUserMemberships returns them, so
			// the list/create axes authorized on BARE MEMBERSHIP while the /:id
			// axes of the same families require the scope in the target
			// organization. Here the caller IS a member of classOrgBeta and
			// still must be denied, because their role template does not grant
			// mirrors:read there.
			symbol: "admin.MirrorHandler.ListMirrorConfigs (member without the scope)",
			route:  "GET /api/v1/admin/mirrors",
			guard:  "tenant-scope-role-template",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				scopes := `["modules:read"]` // a real membership, wrong authority
				if member {
					scopes = `["mirrors:read"]`
				}
				mock.ExpectQuery("(?s)FROM organization_members").
					WillReturnRows(classMembershipRowsWithScopes(classOrgBeta, scopes))
				expectClassRegistryRolesWithScopes(mock, classOrgBeta, scopes)
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
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			// Unguarded create-axis sibling of the policy routes this batch
			// guarded: organization_id came off the body and a mirror_policies
			// row was written under it with no membership check. A mirror policy
			// is an allow/deny rule over what a tenant may mirror, so planting
			// one in another organization changes what that organization is
			// permitted to pull.
			symbol: "admin.RBACHandlers.CreateMirrorPolicy",
			route:  "POST /api/v1/admin/policies",
			guard:  "policy-create-target-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectExec("(?s)INSERT INTO mirror_policies").
					WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil, nil).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.POST("/admin/policies", h.CreateMirrorPolicy)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"name":"planted","policy_type":"allow","organization_id":"` + classOrgBeta + `"}`
				req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantForeignStatus: http.StatusForbidden,
		},
		{
			// Unguarded create-axis sibling of the approval routes this batch
			// guarded, and the subtlest one: it names no organization at all, it
			// names a MIRROR CONFIG. The row's organization was taken from the
			// REQUESTER's ambient context, so an approval filed against another
			// organization's configuration was stamped as the requester's — and
			// then read as theirs to every downstream per-org guard, including
			// POST /approvals/:id/token, whose minted token is redeemable
			// without authentication.
			symbol: "admin.RBACHandlers.CreateApprovalRequest",
			route:  "POST /api/v1/admin/approvals",
			guard:  "approval-create-config-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				// The configuration being approved against belongs to Beta.
				mock.ExpectQuery("(?s)FROM mirror_configurations.*WHERE id").WillReturnRows(
					sqlmock.NewRows(mirrorCfgCols).AddRow(
						classResource, "beta-mirror", nil, "https://registry.terraform.io", classOrgBeta,
						nil, nil, nil, nil, true, 24, nil, nil, nil,
						time.Now(), time.Now(), nil))
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectExec("(?s)INSERT INTO mirror_approval_requests").
					WillReturnResult(sqlmock.NewResult(1, 1))
				h := NewRBACHandlers(repositories.NewRBACRepository(sqlxDB), nil, nil).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB)).
					WithMirrorRepo(repositories.NewMirrorRepository(sqlxDB))
				r.POST("/admin/approvals", h.CreateApprovalRequest)
				return r, mock
			},
			request: func() *http.Request {
				body := `{"mirror_config_id":"` + classResource + `","provider_namespace":"hashicorp"}`
				req := httptest.NewRequest("POST", "/admin/approvals", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantForeignStatus: http.StatusForbidden,
		},
		{
			// Missed by the previous revision's route enumeration entirely: the
			// handler built its filter straight from query parameters with no
			// organization predicate anywhere.
			symbol: "admin.VersionApprovalHandler.List",
			route:  "GET /api/v1/admin/version-approvals",
			guard:  "version-approval-tenant-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				// The predicate must be in the statement. Strip the guard and
				// the emitted SQL stops matching, so the row goes red.
				mock.ExpectQuery(`(?s)SELECT COUNT.*organization_id = ANY`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
				mock.ExpectQuery(`(?s)SELECT \* FROM.*organization_id = ANY`).
					WillReturnRows(sqlmock.NewRows(vaCols))
				h := NewVersionApprovalHandler(repositories.NewVersionApprovalRepository(sqlxDB)).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.GET("/admin/version-approvals", h.List)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/version-approvals", nil)
			},
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			symbol: "admin.VersionApprovalHandler.Events",
			route:  "GET /api/v1/admin/version-approvals/:id/events",
			guard:  "version-approval-events-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery(`(?s)SELECT va\.organization_id FROM`).
					WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow(classOrgBeta))
				mock.ExpectQuery("(?s)FROM version_approval_events").WillReturnRows(
					sqlmock.NewRows([]string{
						"id", "mirrored_provider_version_id", "terraform_version_id",
						"scanner_binary_version_id", "action", "performed_by",
						"performed_by_name", "notes", "auto_approve_rule", "created_at",
					}).AddRow(classResource, classResource, nil, nil, "approved",
						nil, "beta-reviewer", nil, nil, time.Now()))
				h := NewVersionApprovalHandler(repositories.NewVersionApprovalRepository(sqlxDB)).
					WithOrgRepo(repositories.NewOrganizationRepository(sqlxDB.DB))
				r.GET("/admin/version-approvals/:id/events", h.Events)
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/version-approvals/"+classResource+"/events", nil)
			},
			wantForeignStatus:         http.StatusNotFound,
			foreignBodyMustNotContain: "beta-reviewer",
		},
		{
			// namespace_claims is org-owned and NOT NULL (migration 000045), so
			// it is squarely inside this class's own definition — and it had no
			// predicate. The response is a map of which organization owns which
			// module/provider namespace across the whole estate.
			symbol: "admin.OrganizationHandlers.ListNamespaceClaimsHandler",
			route:  "GET /api/v1/admin/namespaces",
			guard:  "namespace-claim-list-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery("(?s)FROM namespace_claims").WillReturnRows(
					sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}).
						AddRow("beta-ns", classOrgBeta, nil, time.Now()))
				mock.ExpectQuery("(?s)FROM organizations WHERE id").WillReturnRows(
					sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
						AddRow(classOrgBeta, "beta", "Beta", nil, nil, time.Now(), time.Now()))
				h := NewOrganizationHandlers(&config.Config{}, sqlxDB.DB,
					repositories.NewNamespaceClaimRepository(sqlxDB.DB), nil)
				r.GET("/admin/namespaces", h.ListNamespaceClaimsHandler())
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/namespaces", nil)
			},
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: "beta-ns",
		},
		{
			symbol: "admin.OrganizationHandlers.GetNamespaceOwnershipHandler",
			route:  "GET /api/v1/admin/namespaces/:namespace",
			guard:  "namespace-ownership-byid-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				mock.ExpectQuery("(?s)FROM namespace_claims").WillReturnRows(
					sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}).
						AddRow("beta-ns", classOrgBeta, nil, time.Now()))
				mock.ExpectQuery("(?s)FROM organizations WHERE id").WillReturnRows(
					sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
						AddRow(classOrgBeta, "beta", "Beta", nil, nil, time.Now(), time.Now()))
				h := NewOrganizationHandlers(&config.Config{}, sqlxDB.DB,
					repositories.NewNamespaceClaimRepository(sqlxDB.DB), nil)
				r.GET("/admin/namespaces/:namespace", h.GetNamespaceOwnershipHandler())
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/admin/namespaces/beta-ns", nil)
			},
			wantForeignStatus:         http.StatusNotFound,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			// This batch's OWN sibling-asymmetry test, failing: every
			// /organizations/:id route carries RequireOrgScopeForPathOrg
			// (GHSA-hc25-j576-cqm2) while the list beside them returned every
			// organization on the platform, handing out the exact ids those
			// guarded routes are keyed on.
			symbol: "admin.OrganizationHandlers.ListOrganizationsHandler",
			route:  "GET /api/v1/organizations",
			guard:  "organization-list-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				// The tenant constraint is a QUERY PREDICATE since identity
				// v0.25.0, on BOTH statements this handler issues: the page and
				// its total. Previously the handler fetched each in-scope id one
				// at a time and paginated in memory — a second implementation of
				// the same scope that ordered and counted differently from the
				// platform-admin branch beside it. Strip the predicate from
				// either statement and the emitted SQL no longer matches these
				// expectations, so this row goes red.
				orgID, name, display := classOrgAlpha, "alpha", "Alpha"
				if member {
					orgID, name, display = classOrgBeta, "beta", "Beta"
				}
				mock.ExpectQuery(`(?s)FROM organizations WHERE 1=1 AND id = ANY`).WillReturnRows(
					sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
						AddRow(orgID, name, display, nil, nil, time.Now(), time.Now()))
				mock.ExpectQuery(`(?s)SELECT COUNT\(\*\) FROM organizations WHERE 1=1 AND id = ANY`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				h := NewOrganizationHandlers(&config.Config{}, sqlxDB.DB,
					repositories.NewNamespaceClaimRepository(sqlxDB.DB), nil)
				r.GET("/organizations", h.ListOrganizationsHandler())
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/organizations", nil)
			},
			wantForeignStatus:         http.StatusOK,
			foreignBodyMustNotContain: classOrgBeta,
		},
		{
			// Search is strictly worse than the list: it turns the census into a
			// lookup, so a caller who knows a target organization's name
			// confirms it exists and recovers its id without enumerating.
			symbol: "admin.OrganizationHandlers.SearchOrganizationsHandler",
			route:  "GET /api/v1/organizations/search",
			guard:  "organization-search-scope",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
				name, display := "alpha", "Alpha"
				orgID := classOrgAlpha
				if member {
					name, display, orgID = "beta", "Beta", classOrgBeta
				}
				// The scope is its own conjunct AFTER the parenthesised
				// name/display_name alternation, so no search term can OR its way
				// outside the tenancy. The in-memory matcher that used to enforce
				// that by hand is gone; this expectation is what keeps the SQL
				// honest in its place.
				mock.ExpectQuery(`(?s)FROM organizations WHERE \(name ILIKE .* OR display_name ILIKE .*\) AND id = ANY`).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
							AddRow(orgID, name, display, nil, nil, time.Now(), time.Now()))
				h := NewOrganizationHandlers(&config.Config{}, sqlxDB.DB,
					repositories.NewNamespaceClaimRepository(sqlxDB.DB), nil)
				r.GET("/organizations/search", h.SearchOrganizationsHandler())
				return r, mock
			},
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/organizations/search?q=beta", nil)
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
				expectClassRegistryRoles(mock, member)
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
		{
			// The omitted-field sibling of scm-create-target-org, and the same
			// bypass as the mirror create axis: uuid.Nil fell through to
			// GetDefaultOrganization with no membership check, so a non-member
			// installed an SCM provider — with credentials they control — in the
			// default organization by leaving the field out.
			symbol: "admin.SCMProviderHandlers.CreateProvider (organization_id OMITTED)",
			route:  "POST /api/v1/scm-providers",
			guard:  "tenant-scope-target-org",
			mount: func(t *testing.T, member bool) (*gin.Engine, sqlmock.Sqlmock) {
				mock, sqlxDB, r := classSQLMock(t)
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(classMembershipRows(member))
				expectClassRegistryRoles(mock, member)
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
				body := `{"name":"planted","provider_type":"github","client_id":"id","client_secret":"secret"}`
				req := httptest.NewRequest("POST", "/scm-providers", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			// As with the mirror create axis: the row lands in the caller's own
			// single in-scope organization, never in the default organization on
			// the strength of an omitted field.
			wantForeignStatus:         http.StatusCreated,
			foreignBodyMustNotContain: classOrgBeta,
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
			if site.ownOrgExempt != "" {
				t.Skipf("exempt from the own-organization half: %s", site.ownOrgExempt)
			}
			r, _ := site.mount(t, true)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, site.request())

			if w.Code == http.StatusForbidden || w.Code == http.StatusNotFound {
				t.Errorf("%s (%s): status = %d for a MEMBER of the owning organization; "+
					"guard %q is over-broad\nbody: %s",
					site.symbol, site.route, w.Code, site.guard, w.Body.String())
			}
			if site.ownOrgBodyMustContain != "" &&
				!strings.Contains(w.Body.String(), site.ownOrgBodyMustContain) {
				t.Errorf("%s (%s): a MEMBER of the owning organization did not receive "+
					"%s — guard %q resolves this principal to an empty scope, which "+
					"denies everything and therefore passes the foreign-org half for "+
					"the wrong reason\nbody: %s",
					site.symbol, site.route, site.ownOrgBodyMustContain, site.guard,
					w.Body.String())
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

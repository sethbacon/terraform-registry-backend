package admin

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Cross-organization authorization gaps found while mapping #652.
//
// All three routes below were gated ONLY by the flat, org-less scope union in
// the session JWT. That union is the documented, deliberate design — it is safe
// precisely because "per-org membership is re-checked server-side on every
// org-scoped route", which is the claim written at internal/auth/jwt.go and
// repeated at every mint site. These three routes did not re-check, so on them
// the claim was false and a scope held in ANY organization read data from
// EVERY organization.
//
// The severity comes from which templates grant the scopes: mirrors:read is on
// the seeded `viewer` template — the lowest-privilege role in the product — and
// scanning:read is on `devops` and `auditor`.

// --- POST /admin/policies/evaluate -----------------------------------------
//
// Its sibling GET /:id in the same route block carries
// RequireOrgScopeForResource. This route took organization_id off the query
// string and evaluated against it with no caller check of any kind.

func newPolicyEvaluateRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewRBACHandlers(repositories.NewRBACRepository(sqlx.NewDb(db, "sqlmock")), nil, nil).
		WithOrgRepo(repositories.NewOrganizationRepository(db))

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeMirrorsRead)})
		c.Set("user_id", scopeUserID)
	})
	r.POST("/evaluate", h.EvaluatePolicy)
	return mock, r
}

const evaluateBody = `{"registry":"registry.terraform.io","namespace":"hashicorp","provider":"aws"}`

func TestEvaluatePolicy_ForeignOrg_Denied(t *testing.T) {
	mock, r := newPolicyEvaluateRouter(t)

	// Member of alpha only. Asking about beta must not reach the policy query.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "rt-viewer", time.Now(), "viewer", "Viewer",
			[]byte(`["mirrors:read"]`),
		))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgAlpha, id: "rt-viewer", name: "viewer", displayName: "Viewer", scopes: `["mirrors:read"]`,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/evaluate?organization_id="+orgBeta, strings.NewReader(evaluateBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// Assert the SPECIFIC denial status. `!= 200` would also be satisfied by a
	// 500 from a broken mock, which is how this very test first passed while
	// the handler was erroring out before it ever reached the guard.
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for a caller with no membership in beta, got %d: %s", w.Code, w.Body.String())
	}
	// The decisive assertion: no policy query was issued at all. A handler that
	// queried and then filtered would still have read the row.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet/extra expectations — the policy query must never run: %v", err)
	}
}

// Positive control. Without this, a handler that denied EVERYTHING would pass
// the test above.
func TestEvaluatePolicy_OwnOrg_Allowed(t *testing.T) {
	mock, r := newPolicyEvaluateRouter(t)

	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "rt-viewer", time.Now(), "viewer", "Viewer",
			[]byte(`["mirrors:read"]`),
		))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgAlpha, id: "rt-viewer", name: "viewer", displayName: "Viewer", scopes: `["mirrors:read"]`,
	})
	mock.ExpectQuery("(?s)FROM mirror_policies").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "organization_id", "name", "description", "policy_type",
			"registry_pattern", "namespace_pattern", "provider_pattern",
			"action", "priority", "requires_approval", "created_at", "updated_at",
			"organization_name",
		}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/evaluate?organization_id="+orgAlpha, strings.NewReader(evaluateBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("member of alpha was denied its own organization: %d %s", w.Code, w.Body.String())
	}
}

// Omitting organization_id stays open to everyone: ListMirrorPolicies then
// matches only `organization_id IS NULL`, the global policies, which no tenant
// owns. Pinned so the fix cannot drift into requiring a parameter the route
// never required.
func TestEvaluatePolicy_NoOrgParam_NeedsNoMembership(t *testing.T) {
	mock, r := newPolicyEvaluateRouter(t)

	mock.ExpectQuery("(?s)FROM mirror_policies").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "organization_id", "name", "description", "policy_type",
			"registry_pattern", "namespace_pattern", "provider_pattern",
			"action", "priority", "requires_approval", "created_at", "updated_at",
			"organization_name",
		}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/evaluate", strings.NewReader(evaluateBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("global-only evaluation was refused: %d %s", w.Code, w.Body.String())
	}
}

// --- GET /admin/scanning/stats ---------------------------------------------
//
// Three queries, none of which carried an organization predicate. Two did not
// even join to a table that has the column.

func TestScanningStats_NonAdmin_EveryQueryCarriesTheTenantPredicate(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "rt-devops", time.Now(), "devops", "DevOps",
			[]byte(`["scanning:read"]`),
		))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgAlpha, id: "rt-devops", name: "devops", displayName: "DevOps", scopes: `["scanning:read"]`,
	})

	// Each of the three queries must join through to modules AND constrain
	// m.organization_id. `= ANY` is what OrgScope.SQL emits for a bounded set;
	// asserting on it means a fix that dropped the predicate (emitting bare
	// TRUE) fails here.
	tenantPredicate := "(?s)JOIN modules m .*m.organization_id = ANY"
	mock.ExpectQuery(tenantPredicate).
		WillReturnRows(sqlmock.NewRows([]string{"total", "pending", "scanning", "clean", "findings", "error_count"}).
			AddRow(0, 0, 0, 0, 0, 0))
	mock.ExpectQuery(tenantPredicate).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(tenantPredicate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "version", "name", "namespace", "system", "scanner", "status",
			"critical_count", "high_count", "medium_count", "low_count",
			"scanned_at", "created_at",
		}))

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeScanningRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/stats", GetScanningStatsHandler(sqlx.NewDb(db, "sqlmock"), repositories.NewOrganizationRepository(db)))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a scanning-stats query ran without the tenant predicate: %v", err)
	}
}

// --- GET /modules/:ns/:name/:system/versions/:v/scan ------------------------
//
// Resolved the DEFAULT organization regardless of caller, so scanning:read held
// anywhere read the default org's findings.

func TestModuleScanByVersion_CallerOutsideDefaultOrg_NotFound(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Caller belongs to alpha; the default organization is beta.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "rt-devops", time.Now(), "devops", "DevOps",
			[]byte(`["scanning:read"]`),
		))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgAlpha, id: "rt-devops", name: "devops", displayName: "DevOps", scopes: `["scanning:read"]`,
	})
	mock.ExpectQuery("(?s)FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}).
			AddRow(orgBeta, "default", "Beta", nil, nil, time.Now(), time.Now()))

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeScanningRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/modules/:namespace/:name/:system/versions/:version/scan", GetModuleScanHandler(db))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/modules/hashicorp/vpc/aws/versions/1.0.0/scan", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a caller outside the default org, got %d: %s", w.Code, w.Body.String())
	}
	// 404 must come from the guard, not from a module lookup that ran anyway.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the module lookup must never run for an out-of-scope caller: %v", err)
	}
}

// Guard the guard: if the harness stopped reaching these handlers the tests
// above would pass vacuously. Each asserts a real database conversation, so a
// silent no-op is caught by ExpectationsWereMet — except the compile-time shape
// of the handlers themselves, pinned here.
var (
	_                                                                      = GetModuleScanHandler
	_ func(*sqlx.DB, *repositories.OrganizationRepository) gin.HandlerFunc = GetScanningStatsHandler
	_ *sql.DB
)

// --- GET /admin/stats/dashboard --------------------------------------------
//
// Issue #566. Found by orgscope_route_class_test.go, which enumerates the real
// route table: this route is the one authenticated route in the whole table
// that carries NO RequireScope at all, so every principal reaches it — and two
// of its queries read mirror_configurations, which carries organization_id.
// The recent-sync list emitted `c.name`, another tenant's chosen name for its
// upstream mirror, to anybody with a session.

// dashboardRouter mounts GET /stats/dashboard with a principal holding
// mirrors:read and a single membership in alpha.
func dashboardRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewStatsHandler(sqlx.NewDb(db, "sqlmock")).
		WithOrgRepo(repositories.NewOrganizationRepository(db))

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeMirrorsRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/stats/dashboard", h.GetDashboardStats)
	return mock, r
}

// TestDashboardStats_MirrorQueriesCarryTheTenantPredicate pins the fix at the
// SQL level. `= ANY` is what OrgScope.SQL emits for a bounded organization set;
// the unscoped handler emitted neither that nor any organization_id reference,
// so the two expectations below would not match and ExpectationsWereMet fails.
// The assertion is on ExpectationsWereMet, not on a swallowed query error:
// both statements are best-effort (`_ =`) in the handler, so a bare `err != nil`
// could never see them at all.
func TestDashboardStats_MirrorQueriesCarryTheTenantPredicate(t *testing.T) {
	mock, r := dashboardRouter(t)

	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "rt-viewer", time.Now(), "viewer", "Viewer",
			[]byte(`["mirrors:read"]`),
		))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgAlpha, id: "rt-viewer", name: "viewer", displayName: "Viewer", scopes: `["mirrors:read"]`,
	})

	opts := defaultStatsOpts()
	opts.mirrorHealthQuery = "(?s)FROM mirror_configurations.*organization_id = ANY"
	opts.recentSyncQuery = "(?s)JOIN mirror_configurations c .*c.organization_id = ANY"
	opts.recentSyncs = []RecentSyncEntry{{
		MirrorName: "alpha-upstream", MirrorType: "provider", Status: "success",
		StartedAt: time.Now(), VersionsSynced: 1, TriggeredBy: "scheduler",
	}}
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/stats/dashboard", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a mirror_configurations query ran without the tenant predicate: %v", err)
	}
}

// TestDashboardStats_NoMemberships_SelectsNothing is the deny direction. A
// principal with no qualifying membership resolves to the empty scope, which
// OrgScope.SQL renders as the constant FALSE — not an absent predicate, and not
// TRUE. Asserted on the emitted SQL, because an empty result set is also what a
// correctly-scoped query returns for an empty database: only the predicate
// distinguishes "you may see nothing" from "there is nothing".
func TestDashboardStats_NoMemberships_SelectsNothing(t *testing.T) {
	mock, r := dashboardRouter(t)

	// No membership rows: the caller holds mirrors:read in no organization.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols))

	opts := defaultStatsOpts()
	opts.provMirrorTotal, opts.provMirrorHealthy, opts.provMirrorFailed = 0, 0, 0
	opts.mirrorHealthQuery = "(?s)FROM mirror_configurations\\s+WHERE enabled = true AND FALSE"
	opts.recentSyncQuery = "(?s)JOIN mirror_configurations c .*WHERE FALSE"
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/stats/dashboard", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the empty scope did not render as FALSE: %v", err)
	}

	var body struct {
		ProviderMirrors ProviderMirrorStats `json:"provider_mirrors"`
		RecentSyncs     []RecentSyncEntry   `json:"recent_syncs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ProviderMirrors.Total != 0 {
		t.Errorf("provider_mirrors.total = %d, want 0", body.ProviderMirrors.Total)
	}
	if len(body.RecentSyncs) != 0 {
		t.Errorf("recent_syncs = %v, want none", body.RecentSyncs)
	}
}

// TestDashboardStats_PlatformAdmin_SeesEveryTenant is the positive control.
// Without it, a "fix" that hard-coded FALSE would satisfy both tests above and
// look correct. A platform admin resolves to OrgScopeAllOrganizations, which
// renders as TRUE and binds no arguments — and reaches no membership query at
// all, which is why none is queued here.
func TestDashboardStats_PlatformAdmin_SeesEveryTenant(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	h := NewStatsHandler(sqlx.NewDb(db, "sqlmock")).
		WithOrgRepo(repositories.NewOrganizationRepository(db))
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/stats/dashboard", h.GetDashboardStats)

	opts := defaultStatsOpts()
	opts.mirrorHealthQuery = "(?s)FROM mirror_configurations\\s+WHERE enabled = true AND TRUE"
	opts.recentSyncQuery = "(?s)JOIN mirror_configurations c .*WHERE TRUE"
	opts.recentSyncs = []RecentSyncEntry{{
		MirrorName: "beta-upstream", MirrorType: "provider", Status: "success",
		StartedAt: time.Now(), VersionsSynced: 3, TriggeredBy: "scheduler",
	}}
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/stats/dashboard", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the platform-admin scope did not render as TRUE: %v", err)
	}
	if !strings.Contains(w.Body.String(), "beta-upstream") {
		t.Errorf("platform admin lost the cross-tenant view: %s", w.Body.String())
	}
}

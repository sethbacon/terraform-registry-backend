package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #783 — the by-id axis of the #718/#719 tenant-scoping class.
//
// GET /api/v1/admin/scanning/scans/:id was gated on RequireScope(scanning:read)
// and nothing else, and fetched purely by primary key. scanning:read is granted
// by the seeded devops and auditor role templates through membership in a
// SINGLE organization, so any such holder could read another tenant's
// vulnerability findings by naming a scan id — no platform authority required.
//
// module_version_scans carries no organization_id of its own; it is
// organization-owned transitively through module_versions -> modules. Nothing
// about the row says whose it is, which is exactly why fetching it by primary
// key looked harmless.
//
// These tests assert the SCOPED form of the query specifically. sqlmock matches
// query text and arguments; it does not evaluate predicates. An expectation that
// merely said "FROM module_version_scans" would be satisfied by the unscoped
// query too, and would pass with the guard reverted.

const (
	scanOrgAlpha = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	scanID       = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
)

// scopedScanRouter wires the handler behind a non-admin scanning:read principal
// holding that scope in one organization only.
func scopedScanRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeScanningRead)})
		c.Set("user_id", "scoped-user")
	})
	r.GET("/admin/scanning/scans/:id", GetScanByIDHandler(db, repositories.NewOrganizationRepository(db)))
	return mock, r
}

// membershipRowsForScanScope is the GetUserMemberships shape tenantscope.Resolve
// reads to build the caller's scope.
func membershipRowsForScanScope(orgID string, scopes string) *sqlmock.Rows {
	return sqlmock.NewRows(membershipCols).
		AddRow(orgID, "org-alpha", "role-1", time.Now(), "devops", "DevOps", []byte(scopes))
}

// expectScanScopeRegistryRole queues the read of registry's own role tables that
// now follows the membership lookup above, repeating the same role and the same
// scopes so the caller's resolved scope is unchanged.
func expectScanScopeRegistryRole(mock sqlmock.Sqlmock, orgID, scopes string) {
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgID, id: "role-1", name: "devops", displayName: "DevOps", scopes: scopes,
	})
}

func TestGetScanByID_ScopedCallerGetsTheScopedQuery(t *testing.T) {
	mock, r := scopedScanRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRowsForScanScope(scanOrgAlpha, `["scanning:read"]`))
	expectScanScopeRegistryRole(mock, scanOrgAlpha, `["scanning:read"]`)
	// The scoped form joins through module_versions -> modules and binds
	// m.organization_id. A platform-wide scope emits the literal TRUE and would
	// not match this expectation, which is what makes the test meaningful.
	mock.ExpectQuery("(?s)JOIN modules.*m.organization_id").
		WillReturnRows(sampleScanResultRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/scanning/scans/"+scanID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestGetScanByID_OutOfScopeIs404NotForbidden(t *testing.T) {
	mock, r := scopedScanRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRowsForScanScope(scanOrgAlpha, `["scanning:read"]`))
	expectScanScopeRegistryRole(mock, scanOrgAlpha, `["scanning:read"]`)
	// A scan owned by another organization matches no row under this scope.
	mock.ExpectQuery("(?s)JOIN modules.*m.organization_id").
		WillReturnRows(sqlmock.NewRows(scanAdminCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/scanning/scans/"+scanID, nil))

	// 404 rather than 403 on purpose: the response body is another tenant's
	// vulnerability findings, so confirming the id exists is itself part of the
	// disclosure. Out of scope must be indistinguishable from never issued.
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an out-of-scope scan; body: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "" {
		for _, leak := range []string{"critical", "raw_results", "module_version_id"} {
			if containsFold(body, leak) {
				t.Errorf("404 body leaked %q: %s", leak, body)
			}
		}
	}
}

func TestGetScanByID_MembershipWithoutScanningReadReachesNothing(t *testing.T) {
	mock, r := scopedScanRouter(t)
	// A member of alpha, but the role template there does not grant
	// scanning:read. Membership is not authority (#719).
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRowsForScanScope(scanOrgAlpha, `["modules:read"]`))
	expectScanScopeRegistryRole(mock, scanOrgAlpha, `["modules:read"]`)
	// The empty scope emits the literal FALSE rather than binding a column, so
	// the predicate is unsatisfiable before the database considers a single row.
	// Matching on FALSE here is the assertion: if this ever became a bound
	// organization list, the caller would be reaching rows again.
	mock.ExpectQuery("(?s)WHERE s.id = .*AND FALSE").
		WillReturnRows(sqlmock.NewRows(scanAdminCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/scanning/scans/"+scanID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if lower(haystack[i+j]) != lower(needle[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

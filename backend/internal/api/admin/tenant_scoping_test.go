package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Tenant-scoping tests for the two list endpoints that a per-resource guard
// cannot protect (issue #719). Both were previously authorized only by the
// flat, org-less scope union in the session JWT (#652), so a caller holding
// scm:read or audit:read via membership in ONE organization could read across
// every organization.

const (
	scopeUserID = "user-scoped"
	orgAlpha    = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	orgBeta     = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

// Column shape of identity models.UserMembership, which GetUserMemberships
// returns — deliberately different from GetMemberWithRole's row shape.
// GetUserMemberships' row shape. Note the column ORDER differs from the field
// order of identity models.UserMembership: created_at is scanned at index 3,
// before the role-template columns. Verified against the real repository call.
var membershipCols = []string{
	"organization_id", "organization_name", "role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func newNonAdminSCMRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewSCMProviderHandlers(
		&config.Config{},
		repositories.NewSCMRepository(sqlx.NewDb(db, "sqlmock")),
		repositories.NewOrganizationRepository(db),
		testTokenCipher(t),
	)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeSCMRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/scm-providers", h.ListProviders)
	return mock, r
}

func TestSCMList_NonAdmin_ForeignOrgFilter_Denied(t *testing.T) {
	mock, r := newNonAdminSCMRouter(t)
	// Not a member of the requested organization (GetUserMemberships shape).
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers?organization_id="+orgBeta, nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (not a member of the requested org): body=%s", w.Code, w.Body.String())
	}
}

func TestSCMList_NonAdmin_OwnOrgFilter_Allowed(t *testing.T) {
	mock, r := newNonAdminSCMRouter(t)
	// GetUserMemberships shape, not GetMemberWithRole: the explicit-org branch
	// now resolves through the SHARED tenant-scope resolver, the same one the
	// unfiltered branch uses, instead of this file's own callerIsMemberOf
	// (which checked bare membership and ignored role-template scopes).
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "role-viewer", time.Now(),
			"viewer", "Viewer", []byte(`["scm:read"]`),
		))
	mock.ExpectQuery("(?s)FROM scm_providers").WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers?organization_id="+orgAlpha, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (member of the requested org): body=%s", w.Code, w.Body.String())
	}
}

func TestSCMList_NonAdmin_Unfiltered_ScopedToOwnOrgs(t *testing.T) {
	mock, r := newNonAdminSCMRouter(t)
	// With no organization_id the caller must get their OWN orgs' providers,
	// not the whole estate: one membership lookup, then one per-org list.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "role-viewer", time.Now(), "viewer", "Viewer", []byte(`["scm:read"]`),
		))
	mock.ExpectQuery("(?s)FROM scm_providers WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(scmProvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scm-providers", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	// The per-org query having been consumed is the assertion that matters: a
	// regression to the old behaviour would issue the unfiltered list instead.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected a per-organization provider query, got: %v", err)
	}
}

func newNonAdminAuditRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewAuditLogHandlers(db)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAuditRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/audit-logs", h.ListAuditLogsHandler())
	return mock, r
}

func TestListAuditLogs_NonAdmin_NoMemberships_ReturnsEmpty(t *testing.T) {
	mock, r := newNonAdminAuditRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	// Must fail closed: no audit rows queried at all, rather than an unfiltered
	// query returning every organization's trail.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected queries beyond the membership lookup: %v", err)
	}
}

func TestListAuditLogs_NonAdmin_ForeignOrgFilter_Denied(t *testing.T) {
	mock, r := newNonAdminAuditRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			orgAlpha, "Alpha", "role-auditor", time.Now(), "auditor", "Auditor", []byte(`["audit:read"]`),
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs?organization_id="+orgBeta, nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (audit trail of an organization the caller does not belong to)", w.Code)
	}
}

// TestListAuditLogs_NonAdmin_MultiOrg_ScopesToAllOwnOrgs replaces the former
// TestListAuditLogs_NonAdmin_MultiOrg_RequiresExplicitOrg.
//
// That test asserted a 400: the consumer-side workaround for a shared
// AuditFilters that could only carry ONE organization, so a multi-org auditor
// had to name one rather than silently receive a partial or unscoped result.
// The shared module now takes an AuditScope carrying the whole allowlist, so
// the workaround is gone and the caller is scoped to every organization they
// hold audit:read in — one statement, one predicate, no 400.
//
// The property that matters is unchanged and is what this asserts: the
// statement carries the tenant predicate. Remove it and the query no longer
// matches the expectation, so this row goes red.
func TestListAuditLogs_NonAdmin_MultiOrg_ScopesToAllOwnOrgs(t *testing.T) {
	mock, r := newNonAdminAuditRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).
			AddRow(orgAlpha, "Alpha", "r1", time.Now(), "auditor", "Auditor", []byte(`["audit:read"]`)).
			AddRow(orgBeta, "Beta", "r2", time.Now(), "auditor", "Auditor", []byte(`["audit:read"]`)))
	mock.ExpectQuery(`SELECT COUNT.*FROM audit_logs.*organization_id = ANY`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT al\.id.*FROM audit_logs.*organization_id = ANY`).
		WillReturnRows(sqlmock.NewRows(auditLogListCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("audit list did not carry the organization predicate for a "+
			"multi-org caller — guard audit-list-tenant-scope missing?: %v", err)
	}
}
